# AnyConnect 配置对齐

范围：对齐本地 `Demogorgon314/mihomo` 的 `OpenConnectOption`，提交
`260cce1faacd14f1e1123a01748dbf9d088d26e4`，以及它引用的
`sing-openconnect a503d88051b3`。按用户确认，本次只实现 AnyConnect，F5 后续处理。
这份说明描述当前源码；此前 v0.22.0 的性能、OpenWrt 和物理路由器记录属于历史版本。

## 字段与行为

| 字段 | 行为 / 默认值 |
| --- | --- |
| `name`, `type`, `protocol` | `type: openconnect`；protocol 为空或 `anyconnect`，其他值明确报错 |
| `server`, `port` | 裸主机名或 IP；端口省略或 0 使用 443 |
| `cookie`, `username`, `password`, `authgroup` | Cookie 优先；支持分步凭据、组 value/显示名选择；允许证书认证配合空密码 |
| `reported-os` | linux/linux-64/win/mac-intel/android/apple-ios，默认取运行平台 |
| `user-agent`, `version`, `local-hostname` | 同时进入认证/CSTP；默认 OpenConnect Agent、v9.21、系统主机名 |
| `mobile.platform-version`, `mobile.device-type`, `mobile.device-unique-id` | 三项必须齐全；进入 XML device-id 和 AnyConnect Identifier 请求头 |
| `form-entries[].form-id`, `submission-key`, `name`, `value`, `promote` | submission-key 优先，否则匹配 auth id/name；后配置覆盖前配置；select 在 input 前编号。promote 需要交互回调，CLI 明确报错 |
| `ca` | 内联 PEM；额外兼容文件路径。与指纹/跳过验证互斥 |
| `cert`, `key`, `key-password` | 客户端证书、证书链和加密 PEM 私钥，校验证书与私钥匹配 |
| `mca-certificate`, `mca-key`, `mca-key-password` | MCA 用户证书链以 PKCS#7 提交；对原始认证响应做 RSA/ECDSA 签名，优先 SHA512/384/256 |
| `cert-expire-warning` | 客户端证书临近到期警告，默认 60 天，0 关闭 |
| `server-name` | TLS SNI / 名称校验，省略或空值使用 server |
| `peer-fingerprint`, `peer-fingerprints` | 任一指纹匹配即接受；裸 SHA1 为证书 DER，sha1:/sha256: 为 SPKI 十六进制，pin-sha256: 为 SPKI Base64；支持最短 4 字符前缀 |
| `system-trust-disabled`, `skip-cert-verify` | 分别关闭系统/内置根或证书验证；默认 false |
| `http-keepalive-disabled` | Connection: close，并在下一认证/CSTP 请求前重新建立 TLS |
| `xml-post-disabled` | 初始 GET，旧式 auth XML 表单使用 application/x-www-form-urlencoded 提交 |
| `external-auth-disabled` | 关闭浏览器认证能力声明并拒绝相应挑战；默认 false |
| `password-authentication-disabled` | 拒绝密码表单，允许 Cookie、TLS 客户端证书或 MCA 完成认证 |
| `pfs`, `allow-insecure-crypto` | 控制 TLS 密码套件和最低 TLS 版本；默认 false |
| `token-mode`, `token-secret` | totp/rsa/oidc；HOTP 在 YAML 中与 mihomo 一样拒绝，见下文 |
| `token-pin`, `token-password`, `token-device-id` | RSA PIN、CTF 解密密码和绑定设备 ID；不调用外部 stoken 程序 |
| `token-counter` | HOTP 的初始计数值；YAML 无法提供持久化更新回调，因此不能启用 HOTP |
| `handshake-timeout` | 秒；0/省略不设置总握手期限，仍受重连窗口和 DTLS 单次 5 秒期限约束 |
| `mtu`, `base-mtu` | 0 自动；显式 576–65535，IPv6 MTU 至少 1280；base-mtu 优先 TCP PMTU，其次 MSS−13，失败用 1406 |
| `ipv6-disabled` | 默认 false，请求 IPv4 和 IPv6；true 仅 IPv4 |
| `compression` | 默认 stateless，LZ4/LZS；all 另允许 CSTP DEFLATE；off 关闭 |
| `queue-length` | 默认 32，0 使用默认，最大 4096；上下行 IP 队列有界 |
| `dpd-interval` | 秒；0 使用网关值，正值至少 2 秒；作用于 CSTP 和 DTLS |
| `reconnect-timeout` | 秒；0/省略使用 300；250 ms 起始退避，最大 30 秒，截止后共享终态错误 |
| `remote-dns-resolve`, `dns` | 使用 VPN 内 DNS；显式 IP 优先于网关 DNS，无可用答案不回退本地；额外允许 IP:port |
| `dtls-mode` | off/auto/require，支持 DTLS 的构建默认 auto |
| `dtls-key-exchange` | auto 提供 PSK 和恢复；resumption 仅提供 AES-GCM 注入恢复 |
| `legacy-dtls` | 默认 true；提供 CBC 和 Cisco DTLS 0.9；false 不提供旧套件 |
| `dtls-local-port` | 本地 UDP 端口，默认 0，由系统选择 |
| `dialer-proxy` | 控制 TCP 与 DTLS UDP 都通过前置代理；中继随代次取消，不绕过前置代理直发 |
| `interface-name`, `routing-mark` | Linux/OpenWrt 使用 SO_BINDTODEVICE / SO_MARK；macOS/iOS 使用接口索引绑定；mark 在非 Linux 平台无效 |
| `ip-version` | dual/ipv4/ipv6/ipv4-prefer/ipv6-prefer，约束外层网关解析和目标解析 |
| `tfo`, `mptcp` | 直连使用 tokio-tfo 和 Linux MPTCP；内核不支持 MPTCP 时退回 TCP |
| `udp` | meow 扩展，默认 true；业务 UDP 也可以经 CSTP 发送 |

`AuthProvider`、`TokenCounterUpdate`、`DialerForAPI` 等是 mihomo 的程序接口，不是 YAML 字段。
浏览器 SSO、任意 HTML 登录、HTTP 重定向、设备检查脚本和需要人工输入的动态表单不在
当前 CLI 认证能力内。遇到这些挑战明确失败，不能把“接受配置字段”理解为支持所有网关流程。

HOTP 每次生成后必须可靠保存下一计数值；参考实现也要求持久化回调，不能只读 YAML 的
`token-counter` 后重复使用。TOTP 支持 Base32、otpauth URI、SHA1/SHA256/SHA512、6/8 位；
RSA 支持 CTF 1/2/3/4 和手机 URI，不读取 stoken rcfile 或 SDTID 文件。
OIDC 只在当前服务器发出 Bearer challenge 后发送 token-secret。

Windows 的 CSTP 构建继续可用；本次接口绑定实现针对 Linux/OpenWrt、macOS/iOS，
Windows 显式 interface-name 仍报不支持。DTLS 的已验证平台仍以 OpenConnect 主文档为准。
通过代理链时，外层接口/TFO/MPTCP 由前置代理的拨号配置决定。

## 验证

- YAML → HTTP 前置代理 → TLS/CSTP → TCP 回显；UDP 中继双向包与取消/初始化失败释放。
- mTLS 使用独立 rustls 服务端，覆盖加密客户端密钥；CA/指纹/错误指纹覆盖实际握手。
- 身份字段实际出现在 XML/CSTP 请求中；表单覆盖、旧式提交与关闭重连、TOTP、OIDC、MCA 挑战有测试。
- RSA 测试使用 stoken 0.93 随机生成的公开测试种子；普通、密码/设备保护、手机 URI、CTF 3 的验证码与独立程序一致。
- 真实 ocserv：off/require × stateless/all，IPv4/IPv6、DNS、TCP/UDP 和重复大负载；强制 AES-GCM resumption。
- 独立 OpenSSL 3：AES-GCM、ECDHE-RSA-GCM、CBC 注入恢复；独立 GnuTLS：Cisco DTLS 0.9 AES128 与 DHE-AES256 双向记录；现代与旧模式均拒绝错误恢复密钥。

本次检查：macOS ARM64 的全量库测试 1311 通过、4 忽略；OpenConnect 应用端到端
16 通过、6 个外部测试默认忽略，ocserv 压缩/恢复互通已单独执行。Rust 1.91 的
Linux ARM64 musl 构建中，协议、独立 DTLS 对端和应用端到端合计 41 通过、6 忽略。
ARM64 musl release 构建通过，ELF 无解释器和动态库依赖；验证未在物理 OpenWrt 路由器重跑。
格式检查、严格 Clippy，以及仅 CSTP、不启用 DTLS 的构建也通过。

```bash
cargo test -p meow-openconnect --features dtls
cargo test -p meow-proxy --lib openconnect_adapter
cargo test -p meow-config --test openconnect_config
cargo test -p meow-app --test openconnect_e2e
docker build -t meow-openconnect-ocserv:test tests/openconnect
cargo test -p meow-app --test openconnect_e2e \
  independent_ocserv_compression_resumption_and_legacy_dtls -- --ignored --nocapture

# 编译两个独立测试对端；macOS 按 Homebrew prefix 设置 -I/-L。
cc tests/openconnect/dtls_resumption_server.c -lssl -lcrypto -o /tmp/meow-dtls-resumption-server
cc tests/openconnect/dtls_legacy_server.c -lgnutls -o /tmp/meow-dtls-legacy-server
DTLS_RESUMPTION_SERVER=/tmp/meow-dtls-resumption-server \
DTLS_LEGACY_SERVER=/tmp/meow-dtls-legacy-server \
cargo test -p meow-openconnect --features dtls \
  independent_resumption_cbc_and_legacy_records -- --ignored --nocapture
```

上述对端仅使用合成凭据和本机/容器端口，不接触现有路由器上的 mihomo/OpenClash 服务。
本次字段对齐没有重新进行峰值吞吐对比；历史 iperf 结果不能直接当作新增压缩/代理链路径的性能数据。
