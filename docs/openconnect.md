# OpenConnect / AnyConnect 出站（阶段 1）

meow-rs 可使用现有 Cookie 建立 AnyConnect CSTP/TLS 隧道，并将规则选中的
IPv4 TCP/UDP 流量送入 VPN。多个连接共享同一节点的会话，不创建系统 VPN 接口，
不修改系统路由或 DNS。

目前是显式启用的 `openconnect` Cargo feature，不包含在默认 `full` 或 `minimal` 中。
本阶段沿用 meow 的 BoringSSL TLS 层，不引入阶段 0 实验使用的 OpenSSL DTLS 后端。

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

## 当前契约与限制

- 配置校验不联网。首次业务拨号共享一次初始化；取消一个等待者不会取消其他等待者。
- adapter 被替换或释放后，已有连接继续持有会话；最后一个使用者释放时关闭 CSTP 和栈任务。
- 认证失败、握手超时和已经断开的会话返回错误，不自动重复登录。恢复时需重新加载节点。
- Cookie 认证以外的用户名密码、MFA、浏览器认证和客户端证书尚未支持。
- `dtls-mode` 仅接受 `off`；业务 UDP 仍可作为 IP 包经 TLS 传输。
- 目标仅支持 IPv4；MTU 配置范围 576–1500，最终使用配置值与网关值中的较小值。
  UDP 载荷不得超过有效 MTU 减 28 字节，不做出站 IPv4 分片。
- 握手超时为 1–300 秒，默认 15 秒；TCP 目标建连由栈的 30 秒期限及外层拨号期限共同约束。
- UDP 发送成功表示进入有界队列；接收队列满时丢包，不阻塞同隧道中的 TCP。
- 目标域名沿用现有解析路径；VPN 下发 DNS、split-DNS、IPv6、压缩、自动重连和 `dialer-proxy`
  尚未实现。相关配置明确拒绝，不静默降级。内部域名需现有解析器可解析，或先使用目标 IPv4。
- 每个节点的栈最多同时保留 1024 个 socket；缓冲和包队列有界。

## 验证范围

[CSTP 测试](../crates/meow-openconnect/tests/cstp.rs) 覆盖拆包、粘包、并发收发控制帧、
异常长度、认证拒绝和心跳超时。
[栈测试](../crates/meow-netstack/tests/sockets.rs) 覆盖 256 KiB TCP 回显、半关闭、UDP、
取消、RST、目标拒绝和隧道故障唤醒。
[端到端测试](../crates/meow-app/tests/openconnect_e2e.rs) 使用独立本地 TLS 网关和 IP 层
TCP/UDP 服务，验证 YAML → Mixed/SOCKS5 → CSTP → 服务，以及实际 meow 子进程启动。
网关与目标均为本地测试 fixture；不依赖真实节点或用户秘密。

```bash
cargo test -p meow-netstack -p meow-openconnect
cargo test -p meow-config --features openconnect --test openconnect_config
cargo test -p meow-app --no-default-features \
  --features openconnect,listener-mixed --test openconnect_e2e
```

后续设计见 [OpenConnect 出站设计](specs/openconnect-design.md)。

### 本地验证记录（2026-09-09，macOS arm64）

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
