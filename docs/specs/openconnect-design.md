# OpenConnect 出站设计

状态：设计草案，尚未实现或完成协议互通验证。

日期：2026-09-09

## 1. 设计决策

为 meow-rs 增加 `type: openconnect` 出站，首个支持的协议为
`protocol: anyconnect`。采用独立协议客户端、基于 smoltcp 的用户态出站
TCP/IP 栈和 `OpenConnectAdapter` 三层结构，保持现有 `ProxyAdapter` 接口。

优先打通 Cookie 认证 → CSTP/TLS → 用户态栈 → SOCKS5 curl 的纵向链路。
DTLS 使用现成库，优先通过 Rust `openssl` bindings 验证 AnyConnect 兼容性，
不自行实现密码算法或 DTLS 握手协议。纯 Rust 的 `webrtc-dtls` 是备选方案，
尚未确认其原版能满足注入会话恢复和旧 Cisco DTLS 的要求。

OpenSSL 是 DTLS 的首选验证后端，不代表已经证明全部目标网关可用。
先完成独立握手实验，再固定依赖版本、FFI 范围和发布构建方式。
CSTP/TLS 阶段沿用现有 TLS 基础设施；若后续 PSK 模式需要 TLS exporter，
必须从实际控制连接导出密钥，不能创建另一条 TLS 连接代替。

首期不支持 F5、GlobalProtect 等其他 VPN 协议，不承诺完整复制 OpenConnect
命令行客户端的认证能力，也不安装系统 VPN 路由或修改系统 DNS。

## 2. 当前实现与参考依据

以下是设计时读取的本地工作树；提交号用于定位参考基线，不保证工作树没有额外改动。

| 项目 | 参考基线 | 用途 |
| --- | --- | --- |
| mihomo | `260cce1faacd14f1e1123a01748dbf9d088d26e4` | OpenConnect 配置、共享会话、DNS、重连与网络参数更新 |
| clash-rs | `2f13a21f8044ed2242343ceaeabe33f760009d09` | WireGuard 出站的 smoltcp 桥接与主动建连 |

本地参考文件：

- `/Users/deepdream/Developer/github/Demogorgon314/mihomo/adapter/outbound/openconnect.go`
- `/Users/deepdream/Developer/github/Demogorgon314/mihomo/adapter/outbound/openconnect_session.go`
- `/Users/deepdream/Developer/github/Demogorgon314/mihomo/transport/openconnect/`
- `/Users/deepdream/Developer/github/Demogorgon314/clash-rs/clash-lib/src/proxy/wg/`

该 mihomo 工作树通过 `go.mod` 的 replace 使用
`Demogorgon314/sing-openconnect` 和 `Demogorgon314/dtls/v3`，后者替代 Pion DTLS。
其测试包含注入会话恢复；不能把参考实现的能力视为原版 DTLS 库的默认能力。
当前 clash-rs 工作树未搜到 OpenConnect 实现，参考对象是 WireGuard 的 IP 包桥接。

meow-rs 的现有边界：

- [ProxyAdapter](../../crates/meow-common/src/adapter.rs) 提供 TCP/UDP 拨号接口。
- [连接类型](../../crates/meow-common/src/conn.rs) 要求 TCP 满足
  `AsyncRead + AsyncWrite + Unpin + Send + Sync`，UDP 使用独立的数据报接口。
- [代理解析器](../../crates/meow-config/src/proxy_parser.rs) 负责出站构造与 feature 错误。
- [现有 lwIP 栈](../../crates/meow-lwip/rust/stack.rs) 用于入站，提供 TCP accept，
  没有现成的主动 TCP connect API；PCB/netif 为进程全局状态，只允许一个活动栈。
  因此不能直接为多个 VPN 节点各创建一份，也不能与 TUN 入站并行复用为独立 VPN 栈。

参考仓库根许可证分别为 GPL-3.0（mihomo）和 Apache-2.0（clash-rs）。
实现以协议资料和行为验证为依据；如复用代码或引入依赖，需要按具体文件的
许可证保留声明并核实分发要求，不能直接把参考实现改写后标为 MIT。

## 3. 数据路径与模块边界

```text
HTTP / SOCKS / TUN 入站
          │
     Tunnel 规则选路
          │
   OpenConnectAdapter
          │ TCP stream / UDP socket
     meow-netstack
          │ 原始 IPv4 / IPv6 包
    meow-openconnect
          │ CSTP/TLS 或 DTLS
       VPN 网关
```

每个节点共享一个 VPN 会话，每个会话拥有独立用户态栈。业务连接拥有各自的
TCP/UDP socket，不为每次 `dial_tcp()` 重新登录 VPN。TUN 入站继续使用现有栈。

建议新增：

| 模块 | 职责 |
| --- | --- |
| `crates/meow-openconnect/` | 认证、HTTPS CONNECT、CSTP framing、网络参数、心跳、重连、后续 DTLS |
| `crates/meow-netstack/` | smoltcp 主动 TCP/UDP socket、IP 包输入输出、定时轮询、端口与缓冲管理 |
| `crates/meow-proxy/src/openconnect_adapter.rs` | 出站接口、共享初始化、目标解析、会话与栈的生命周期 |

协议客户端只暴露 IP 包收发、就绪状态、网络配置事件和关闭能力，不依赖规则引擎。
用户态栈只处理 socket 与 IP 包转换，不了解 Cookie、CSTP 或 DTLS。
先实现这一条消费路径需要的接口，避免预建通用 VPN 插件框架。

`meow-netstack` 采用单任务拥有 smoltcp 状态的方式，外部通过有界队列与命令交互。
包装出的连接必须满足现有连接 trait，正确处理唤醒、背压、半关闭、取消、
端口耗尽与定时器。通过地址和路由配置把目标流量发给 VPN 包通道。

## 4. 会话、重连与网络配置

会话状态至少区分未启动、连接中、就绪、重试等待、失败与关闭。

- 并发首次拨号只启动一次认证和隧道建立；所有等待者共享结果。
- 拨号超时或单个等待者取消不应取消其他使用者依赖的会话。
- 认证拒绝、无效配置和证书错误不进行无限自动重试；临时网络错误使用有上限的退避。
- 初期 CSTP 断开即结束当前代次，旧 socket 明确失败；恢复后新拨号使用新代次。
  不承诺保留已有 TCP 会话。
- 每一代网络配置、栈和包队列绑定 generation ID。旧任务与排队包不得进入新栈。
- 地址变化需要重建栈并使旧连接失败；MTU/DNS 变化按其影响更新，无法安全原地更新时重建。
- 仅 TLS/DTLS 数据通道切换且网络配置不变时，目标是保留栈与 socket；需要专项测试证明。
- 对发送结果不确定的数据包不跨通道盲目重发，避免重复业务 UDP。
- adapter、活动连接和后台任务的所有权需明确。后台任务不能通过强引用环永久保活自己；
  热重载淘汰旧 adapter 后，待其使用者释放应能取消任务、关闭 socket 并回收所有队列。

网络配置包含 VPN 分配地址、有效 MTU、DNS 和后续 split-DNS 信息。
对无效地址、异常 MTU、非法或截断的帧返回明确错误；按协商 MTU 限制数据包。
IPv6 启用时校验其 MTU 要求。压缩首期关闭，未实现的压缩算法不得静默接受。

## 5. DNS 与路由语义

VPN 网关的引导解析走可用的外层解析路径，不能依赖尚未建立的 VPN。
目标主机名解析与网关解析分离。

首期使用现有目标解析路径，明确不承诺企业内部域名可用；验收使用 IP 或公网目标。
后续增加 `remote-dns-resolve`：优先使用显式 DNS 配置，否则使用网关下发 DNS，
查询通过同一 VPN 用户态栈发送，并支持 DNS 所需的 TCP 回退。
显式开启远端解析但没有可用 DNS 时返回错误，不悄悄泄漏到本地解析器。

实现前应核对 Tunnel 对 hostname/destination IP 的保留与提前解析行为，确保远端解析
使用原始域名且不会再次进入同一条代理规则形成循环。split-DNS 是后续增量能力。
网关下发路由不会写入操作系统；meow 规则决定哪些业务流量选择此出站。

首期不支持 `dialer-proxy` 或 `connect_over()` 链式传输，配置时明确拒绝前者，
后者沿用 trait 的不支持错误。现有 TCP dialer 不能直接代表 DTLS 所需的 UDP 拨号能力。

## 6. DTLS 后端和验证门槛

业务 UDP 可以封装为 IP 包经 CSTP/TLS 传输，因此 `support_udp()` 不依赖 DTLS。
DTLS 改善承载方式，但不是第一版 TCP/UDP 连通的前提。

| 候选 | 已知能力 | 仍需验证 |
| --- | --- | --- |
| Rust `openssl` bindings | DTLS method、SSL session 导入和恢复接口 | 会话参数构造/注入、具体密码套件、旧 Cisco 模式、异步 UDP 驱动 |
| `webrtc-dtls` | 可独立使用的 Rust DTLS 实现 | 目标 PSK 协商、外部会话注入、旧版兼容性及是否需要 fork |

AnyConnect 需要分别验证以下路径：

1. 现代 PSK 协商：遵循协议取得密钥与 identity，并匹配网关密码套件。
2. 注入会话恢复：通过 HTTPS 协商 master secret、session ID 和 cipher，
   构造供 DTLS 恢复的会话；普通的已完成握手会话缓存不等同于这一能力。
3. 旧 Cisco DTLS：单独评估历史协议与密码套件；默认不启用旧密码算法。

OpenSSL 适配需要处理数据报边界、非阻塞读写、握手重传定时器、MTU 和关闭。
不能把面向 TCP 的异步 TLS stream wrapper 直接视作可用的 DTLS UDP 驱动。
若高级 bindings 缺少参数设置能力，只在小范围封装必要的 FFI，并验证所有权与错误路径。

独立实验必须至少证明：目标握手模式成功、错误密钥失败、握手丢包能重传、
UDP 不通能按策略退出、双向应用数据能交换。记录 OpenSSL/绑定库版本与网关模式。
未完成验证前不固定“兼容所有 AnyConnect 网关”的承诺。

最终 `dtls-mode` 语义：

- `off`：只用 CSTP/TLS。
- `auto`：尝试 DTLS，不可用时回退 TLS；仍保留控制通道。
- `require`：DTLS 不可用时报告失败，不假装已经满足要求。

DTLS 开发完成前仅接受 `off`；完成后默认目标为 `auto`。
控制 TLS 连接和会话心跳必须按协议维护，不能因 DTLS 就绪就关闭控制连接。

## 7. 配置与 Cargo 接入

以下是拟议配置，不是当前可运行示例。占位 Cookie 需要替换，meow 不因此新增环境变量插值语义。

```yaml
proxies:
  - name: corp-vpn
    type: openconnect
    protocol: anyconnect
    server: vpn.example.com
    port: 443
    cookie: "REPLACE_WITH_SESSION_COOKIE"
    server-name: vpn.example.com
    ipv6-disabled: true
    dtls-mode: off

rules:
  - MATCH,corp-vpn
```

第一阶段支持 `name`、`server`、`port`、`protocol`、`cookie`、`server-name`、
CA 配置、握手超时、MTU、IPv6 禁用选项及 `dtls-mode: off`。
字段优先沿用参考 mihomo 命名；实现时明确 server 接受的主机名/URL 格式、
路径与 port 冲突规则、CA 是路径还是内容，避免模糊解析。
Cookie 禁止 CR/LF/NUL，默认验证证书及主机名，日志和 Debug 输出不得暴露 Cookie 或密钥。

后续增加用户名密码、authgroup、VPN DNS、DTLS 参数；MFA、客户端证书、
浏览器认证与设备检查按真实需求分别设计。对于未实现的协议或功能选项明确报错。

新增 `AdapterType::OpenConnect`，在 `meow-proxy` 注册模块，
在 `meow-config/src/proxy_parser.rs` 增加解析和 feature 禁用错误。
`openconnect` feature 由 app → config → proxy → 协议客户端/用户态栈传递。
OpenSSL 依赖进一步由 `openconnect-dtls` 控制，并让其隐含 `openconnect`；
默认构建不引入 OpenSSL。验证系统库或 vendored 构建在项目目标平台上的可发布性。
依赖版本需满足 workspace MSRV，不在设计阶段猜测固定版本。

## 8. 实施顺序与验收

| 阶段 | 交付内容 | 完成条件 |
| --- | --- | --- |
| 0：技术验证 | smoltcp 主动连接实验；OpenSSL DTLS 独立握手实验 | 原始 IP 通道上的 TCP/UDP 通；明确可支持的 DTLS 模式与缺失 API |
| 1：最小闭环 | Cookie、CSTP/TLS、IPv4、TCP/UDP、共享初始化、关闭和基础错误处理 | 配置解析 → meow 入站 → VPN 网关 → 目标服务全路径通过 |
| 2：会话完善 | 用户名密码/authgroup、VPN DNS、重连、配置代次与 IPv6 | 并发初始化、旧代次隔离、重建和资源释放验证通过 |
| 3：DTLS | OpenSSL 后端、off/auto/require、回退与切换 | 支持矩阵中的网关互通；丢包、UDP 阻断和切换测试通过 |

TLS 闭环无需等待旧 Cisco 兼容性问题解决。握手实验不可用时记录具体原因，
再决定补 FFI、采用 fork 或收窄首发兼容范围。

## 9. 测试与完成标准

自动化测试以本地模拟网关和 IP 层 TCP/UDP 测试端点为主，不需要真实节点秘密。

- CSTP：拆包/粘包、头部与长度边界、截断帧、控制消息、认证与证书失败。
- 用户态栈：主动 TCP/UDP、半关闭、背压、大于 MTU 的输入、端口回收、取消和资源释放。
- 会话：并发首拨只建立一次、等待者取消隔离、退避、断线后旧 socket 失败、旧代次包丢弃。
- DNS：内部域名经 VPN 解析、DNS TCP 回退、缺少 DNS 不泄漏回退、引导解析无循环。
- 多节点：两个 VPN 栈隔离运行，并与现有 TUN 入站同时工作。
- DTLS：各握手模式、密钥错误、重传、UDP 黑洞、auto 回退、require 失败、切换无盲目重发。

并发测试使用可控事件和虚拟时间；对真实网络定时行为采用有界超时。
模拟网关不能替代真实互通：增加独立的本地 ocserv 集成测试，并维护具体的协议模式矩阵。

实现代码后运行格式检查、相关 crate 测试、workspace 所需单元测试与 clippy，
检查默认构建、仅 openconnect、openconnect-dtls 的 feature 组合，并构建 release。
外部服务/Docker 测试按环境显式执行，记录未运行项目，不能据此宣称全部兼容。

真实节点测试遵循根 [AGENTS.md](../../AGENTS.md) 的 opt-in 流程，绝不放入 CI。
使用 `/tmp` 单节点配置和 `MATCH,<name>`，分别测试默认 HTTPS 与 HTTP/1.1，
要求 gstatic smoke 返回 204；另测受控 UDP 端点，并记录实际 TLS/DTLS 通道。
Cookie、密码、PSK、私有节点和抓包中的秘密不得提交。

## 10. 协议与库资料

- [OpenConnect 技术说明](https://www.infradead.org/openconnect/technical.html)
- [OpenConnect 协议草案：PSK 与旧式 DTLS 恢复](https://github.com/openconnect/protocol/blob/master/draft-openconnect.xml)
- [OpenConnect DTLS 实现：历史握手说明](https://gitlab.com/openconnect/openconnect/-/blob/master/dtls.c)
- [OpenSSL Rust DTLS method](https://docs.rs/openssl/latest/openssl/ssl/struct.SslMethod.html)
- [OpenSSL Rust session](https://docs.rs/openssl/latest/openssl/ssl/struct.SslSession.html)
- [OpenSSL Rust set_session](https://docs.rs/openssl/latest/openssl/ssl/struct.Ssl.html#method.set_session)
- [webrtc-dtls](https://docs.rs/webrtc-dtls)
- [smoltcp TCP socket](https://docs.rs/smoltcp/latest/smoltcp/socket/tcp/struct.Socket.html)

在线库文档的 latest 会变化，实施阶段应根据验证结果固定版本并复核 API。
