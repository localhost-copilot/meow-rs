# OpenConnect / AnyConnect 出站

meow-rs 可使用 Cookie 或用户名密码建立 AnyConnect CSTP/TLS 隧道，并将规则选中的
IPv4/IPv6 TCP/UDP 流量送入 VPN。支持 authgroup、VPN DNS 和有界重连。
多个连接共享同一节点的会话，不创建系统 VPN 接口，
不修改系统路由或 DNS。

目前是显式启用的 `openconnect` Cargo feature，不包含在默认 `full` 或 `minimal` 中。
CSTP 沿用 meow 的 BoringSSL TLS 层。可选 OpenSSL DTLS 后端已通过真实 ocserv
互通、UDP 阻断与恢复测试；构建和运行条件见下文。

同配置 mihomo 对比和原始数据见 [iperf3 与回显性能报告](benchmarks/openconnect-iperf3-2026-09-09.md)。
当前 DTLS 会话使用 64 KiB 共享 TCP 发送预算来限制突发，每流上限 32 KiB、下限一个 MTU；
这能减少网关 UDP 接收缓冲溢出，但可能限制高带宽、高延迟链路的吞吐。
`auto` 在同一会话内回退 TLS 时保留该预算。当前本地基准不代表 WAN 性能已经对齐。

## 构建与配置

```bash
cargo build --release -p meow-app --features openconnect
```

将以下配置保存在 `/tmp/meow-openconnect.yml`，替换服务器和 Cookie。
Cookie 可以是原始值，也可以带 `webvpn=` 前缀；不是环境变量插值表达式。
私有节点、Cookie 和 CA 私钥不要提交到仓库。

```yaml
mixed-port: 18080
mode: rule
ipv6: false
allow-lan: false

dns:
  enable: true
  nameserver:
    - 1.1.1.1

proxies:
  - name: corp-vpn
    type: openconnect
    protocol: anyconnect
    server: vpn.example.com
    port: 443
    server-name: vpn.example.com
    cookie: "REPLACE_WITH_SESSION_COOKIE"
    # 自签或私有 CA 时指定 PEM 证书文件；建议绝对路径。
    # ca: /absolute/path/to/vpn-ca.pem
    mtu: 1400
    handshake-timeout: 15
    ipv6-disabled: true
    udp: true
    dtls-mode: off
    compression: off

rules:
  - MATCH,corp-vpn
```

使用用户名密码时，删除 `cookie`，改为以下字段。两种认证方式不能同时配置。

```yaml
    username: "REPLACE_WITH_USERNAME"
    password: "REPLACE_WITH_PASSWORD"
    authgroup: "Engineering" # 可省略；按网关的组名称或 option value 选择
```

用户名密码认证使用 AnyConnect XML 表单，支持分步用户名/密码、组选择和隐藏字段，
在同一条验证过证书的 TLS 连接上取得 Cookie 并建立 CSTP。最多处理 6 次响应，
不自动重复提交密码；HTTP 重定向、HTML 登录、额外密码/MFA 挑战和设备检查明确报错。

需要 IPv6 和内部域名时，在节点中启用以下选项，并按需要设置全局 `ipv6: true`：

```yaml
    ipv6-disabled: false
    remote-dns-resolve: true
    # 显式 DNS 优先于网关下发 DNS；不配置时使用网关下发的服务器。
    # dns: [192.0.2.53, "[2001:db8::53]:53"]
```

DNS 服务器仅接受 IP 或带端口的 IP，不接受需要引导解析的主机名。
查询通过当前 VPN 栈发送，支持 A/AAAA 和 UDP 截断后的 TCP 回退。
没有可用 VPN DNS、查询失败或 NXDOMAIN 时返回错误，不回退本地 DNS。
每代会话最多缓存 256 个名称，TTL 不超过服务器值或 300 秒，重连后清空。
目标的原始域名优先于提前解析的 IP；UDP 的 DNS 答案绑定提供该答案的出站，
避免后续规则重匹配或代理组切换把该地址送往其他出站。
规则本身若需要 IP 匹配，仍可能触发本地解析；内部域名宜使用靠前的域名规则。
VPN 网关自身的引导解析始终沿用外层解析路径。

`server` 是裸主机名或 IP，端口单独配置；不接受含协议、路径或用户信息的 URL。
CSTP 路径固定为 `/CSCOSSLC/tunnel`。`server-name` 默认使用 `server`，正常验证
证书链和主机名；`ca` 文件中的证书加入默认根证书集合。相对 CA 路径按进程工作目录解析。

```bash
./target/release/meow -f /tmp/meow-openconnect.yml -t
./target/release/meow -f /tmp/meow-openconnect.yml
curl -fsS --max-time 30 --proxy socks5h://127.0.0.1:18080 \
  https://www.gstatic.com/generate_204 -o /tmp/meow-openconnect.out \
  -w 'http_code=%{http_code} http_version=%{http_version}\n'
```

真实节点 smoke 应按根 [AGENTS.md](../AGENTS.md) 再做 HTTP/1.1 对照，必须手动 opt-in，
不能放入 CI。本文命令是使用说明，不代表已经执行真实节点验证。

## DTLS

```bash
cargo build --release -p meow-app --features openconnect-dtls
```

此 feature 隐含 `openconnect`，不加入默认构建。运行时需要 OpenSSL 3 的共享库：
macOS 使用 Homebrew OpenSSL 3，glibc Linux 使用系统 `libssl.so.3`。
为避免与 BoringSSL 的同名 C 符号混用，后端通过独立库句柄解析 OpenSSL API；
glibc 使用 deep binding。macOS ARM64 与 Debian glibc Linux 已通过真实互通验证；
最低 Rust 版本为 1.91，用户态 TCP 栈使用 smoltcp 0.14 的 CUBIC。
Linux 验证使用 Rust 1.91 及 OpenSSL 3.0.20。
musl、Windows、BSD 不在本阶段已验证支持范围。

| `dtls-mode` | 行为 |
| --- | --- |
| `off` | 不协商 DTLS，所有 IP 包走 CSTP/TLS |
| `auto` | 尝试 DTLS，失败后使用 CSTP；有效 DTLS 参数仍在时，每 30 秒重试 |
| `require` | 建立 DTLS 后才发布会话；DTLS 故障使当前 socket 失败，不能回退 TLS 数据通道 |

启用 `openconnect-dtls` 的 Unix 构建默认 `auto`，仅启用 `openconnect` 时默认 `off`，
并拒绝 `auto` / `require`。初次 DTLS 握手最多 5 秒，整个初始化仍受
`handshake-timeout` 限制。TLS 控制连接在 DTLS 活动期间继续处理心跳。
同一控制代次固定使用两条通道都能接受的 MTU；切换不重建用户态栈。
发送结果不确定的数据报不会跨通道重发。达到网关 DTLS rekey 时间时建立新的
控制代次，现有 socket 会失败；当前不支持原地 rekey。

已验证：真实 ocserv 1.3.0 / GnuTLS 3.8.9 的现代 PSK，包含 VPN DNS、IPv4/IPv6
TCP/UDP；参考网关的 App-ID PSK 与 ChaCha20-Poly1305 注入恢复。
独立 OpenSSL 服务端的首包丢失重传和双向数据报，以及 UDP 黑洞截止测试通过。
`auto` 已验证 UDP 阻断后原 TCP/UDP socket 继续通过 TLS 工作，解除阻断后重新
进入 DTLS；`require` 已验证原 socket 失败，不向 TLS 重放不确定是否送达的数据报。
参考网关的错误 PSK／恢复密钥拒绝测试通过。旧 Cisco DTLS 未列入支持范围。

真实 ocserv 的吞吐、延迟、服务器计数和 mihomo 同配置对比见
[性能报告](benchmarks/openconnect-iperf3-2026-09-09.md)。基准是显式运行的 ignored
测试，不访问外部 VPN，也不在 CI 中运行真实节点测试。

```bash
docker build -t meow-openconnect-ocserv:test tests/openconnect
cargo test --locked -p meow-app --no-default-features \
  --features openconnect-dtls,listener-mixed --test openconnect_e2e \
  independent_ocserv_dtls -- --ignored --nocapture
```

完整 ocserv 故障测试使用筛选器 `independent_ocserv`；Linux 客户端验证：

```bash
docker build -f tests/openconnect/Dockerfile.client -t meow-openconnect-client:test .
bash tests/openconnect/test_linux.sh
```

## 当前契约与限制

- 配置校验不联网。首次业务拨号共享一次初始化；取消一个等待者不会取消其他等待者。
- adapter 被替换或释放后，已有连接继续持有会话；最后一个使用者释放时关闭 CSTP 和栈任务。
- 建连时的认证拒绝、证书错误和无效协议/配置立即失败；临时连接错误、超时及断线触发后台重连。
  连续失败或存活不足 30 秒的会话最多尝试 5 次，退避依次为 1、2、4、8 秒。
  稳定运行 30 秒后重新计算失败次数；达到上限后需重新加载节点。
- 每次重连创建独立代次的地址、MTU、DNS、栈及包队列，旧 TCP/UDP socket 明确失败。
  不恢复已有 TCP，不把发送结果不确定的 UDP 包重新发送到新代次。
- MFA、浏览器认证和客户端证书尚未支持。
- 业务 UDP 不依赖 DTLS，也可作为 IP 包经 CSTP/TLS 传输。
- IPv4 默认启用，IPv6 通过 `ipv6-disabled: false` 请求；可接受纯 IPv6 或双栈分配。
  MTU 配置范围 576–1500，IPv6 至少为 1280，最终使用配置值与网关值中的较小值。
  UDP 载荷不得超过有效 MTU 减 28（IPv4）或 48（IPv6）字节，不做出站 IP 分片。
- 每次认证及 CSTP 握手超时为 1–300 秒，默认 15 秒；外层拨号可以提前超时，
  不取消其他使用者共享的初始化。TCP 目标建连由栈的 30 秒期限及外层拨号期限共同约束。
- UDP 发送成功表示进入有界队列；接收队列满时丢包，不阻塞同隧道中的 TCP。
- 未开启 `remote-dns-resolve` 时目标域名沿用现有解析路径。
  split-DNS、压缩和 `dialer-proxy` 尚未实现，相关配置明确拒绝。
- 每个节点的栈最多同时保留 1024 个 socket；缓冲和包队列有界。

## 验证范围

[CSTP 测试](../crates/meow-openconnect/tests/cstp.rs) 覆盖拆包、粘包、并发收发控制帧、
异常长度、认证拒绝和心跳超时。
[栈测试](../crates/meow-netstack/tests/sockets.rs) 覆盖 256 KiB TCP 回显、半关闭、UDP、
取消、RST、目标拒绝和隧道故障唤醒。
[端到端测试](../crates/meow-app/tests/openconnect_e2e.rs) 使用独立本地 TLS 网关和 IP 层
TCP/UDP 服务，验证 YAML → Mixed/SOCKS5 → CSTP → 服务，以及实际 meow 子进程启动。
网关与目标均为本地测试 fixture；不依赖真实节点或用户秘密。

阶段 2 增加 XML 认证、IPv6 入站、VPN DNS/组路由、DNS TCP 回退、重连换址与缓存隔离、
等待者取消、初始化中关闭、旧 socket 失败和 5 次重试上限测试。

```bash
cargo test -p meow-netstack -p meow-openconnect
cargo test -p meow-config --features openconnect --test openconnect_config
cargo test -p meow-app --no-default-features \
  --features openconnect,listener-mixed --test openconnect_e2e
```

后续设计见 [OpenConnect 出站设计](specs/openconnect-design.md)。

### 独立 ocserv 互通

本地 Docker 测试提供独立 ocserv、DNS 与 TCP/UDP 回显服务，使用临时自签证书和公开的
测试凭据；仅修改容器内网络。测试需要 Docker 的 `NET_ADMIN` 和 `/dev/net/tun`，
结束后自动删除容器和临时证书。默认忽略该测试，不在常规 CI 中运行。

```bash
docker build -t meow-openconnect-ocserv:test tests/openconnect
cargo test -p meow-app --no-default-features \
  --features openconnect,listener-mixed --test openconnect_e2e \
  independent_ocserv -- --ignored --nocapture
```

2026-09-09 已在 macOS arm64 的 Docker 环境通过 ocserv 1.3.0 / GnuTLS 3.8.9：
用户名密码、authgroup、VPN DNS、IPv4/IPv6 TCP 和 UDP。
该测试发现并验证了一个 CSTP 兼容性修复：帧头与负载必须合并为一次 TLS 写入，
避免 ocserv 把单独的帧头记录判为不完整数据。普通字节流模拟网关无法发现这个问题。
这是本地服务互通验证，尚未测试用户真实节点、Cisco ASA 或 DTLS。

### 阶段 2 验证记录（2026-09-09，macOS arm64）

| 要求 | 已通过的验证 |
| --- | --- |
| 用户名密码 / authgroup | XML 分步表单、组名转换、隐藏字段/opaque、拒绝重复密码；ocserv 实际认证 |
| VPN DNS | 内部域名、A/AAAA、显式 DNS 优先、缺失 DNS 不回退、UDP 截断后 TCP 回退、代理组选择与 IP 规则变化时固定出站 |
| IPv6 | 纯 IPv6 / 双栈用户态 TCP/UDP、MTU 边界；SOCKS5 IPv6 入站；ocserv IPv6 互通 |
| 并发初始化 | 8 个拨号共享一次认证和会话；取消等待者不取消其他使用者 |
| 重连和代次隔离 | 后台重连、重新认证、更新地址/MTU/DNS、清空缓存、旧 socket 读写失败、新代次 IP 包使用新地址 |
| 释放及错误上限 | 初始化中释放 adapter、活动连接保留会话、最后使用者释放关闭通道、5 次有界退避和共享终态错误 |

workspace 单元测试、meow 二进制单元测试及 OpenConnect 专项测试合计 **1333 通过、5 忽略**。
其中 1 个忽略项为独立 ocserv 测试，已用上面的 `--ignored` 命令单独执行通过；
禁用 OpenConnect feature 的配置提示测试也单独通过。

`cargo fmt --all --check`、默认 / 无默认 feature / 全 feature 的严格 Clippy、
`RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` 及带 OpenConnect 的 release 构建通过。
release 验证使用 `CARGO_PROFILE_RELEASE_STRIP=none` 绕过本机 LLVM strip 动态库问题；
链接器另有 macOS 段对齐警告，构建成功，未修改发布 profile。
未测试用户真实节点或 Cisco ASA，DTLS 属于下一阶段。

### 阶段 1 验证记录（2026-09-09，macOS arm64）

- workspace 单元测试及 meow 二进制单元测试：1306 通过，4 忽略。
- CSTP、用户态栈、配置和本地端到端专项测试：13 通过；禁用 feature 的配置提示测试另有 1 项通过。
- `cargo fmt --all --check`、默认 / 无默认 feature / 全 feature 的严格 Clippy，以及
  `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` 通过。
- 带 `openconnect` 的 release 构建通过。本机 LLVM strip 工具链存在动态库问题，验证时使用
  `CARGO_PROFILE_RELEASE_STRIP=none`；未更改项目发布 profile。
- 额外尝试无默认 feature 的配置单元测试时，两个已有 provider 测试因依赖未启用的
  Shadowsocks 节点而失败；同一批测试在正常 workspace feature 组合中通过。
  OpenConnect 专项测试通过，不将该无默认 feature 单元测试组合记录为全绿。
- 未执行真实节点、ocserv 或 Docker 互通测试；DTLS 不属于本阶段实现范围。
