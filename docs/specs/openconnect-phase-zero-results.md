# OpenConnect 阶段 0：技术验证结果

日期：2026-09-09。范围：用户态出站栈与 DTLS 后端可行性，不代表 OpenConnect 出站已实现。

## 结论

采用 **smoltcp 0.12 + OpenSSL DTLS 后端** 可以继续阶段 1。
原始 IPv4 通道上的主动 TCP/UDP 已通过实验；OpenSSL 的 DTLS 1.2 PSK 和注入会话恢复
均完成了本地及跨实现的数据交换。DTLS 不需要自行实现加密或重传算法。

首批可实施的 DTLS 模式为现代 PSK 和 DTLS 1.2 注入恢复。
**旧 Cisco DTLS 不列入已验证支持范围**：已能发出旧版 ClientHello，但当前参考网关
在 HelloVerify 后拒绝 OpenSSL 的握手消息序号，尚未完成数据交换。
这是已定位的互通门槛，不能据此断言真实 Cisco 网关不支持 OpenSSL。

## 可复现实验与环境

- [实验包及命令](../../experiments/openconnect/README.md)：独立 nested workspace，`publish = false`。
- [原始 IP 实验](../../experiments/openconnect/tests/raw_ip.rs)。
- [DTLS 实验](../../experiments/openconnect/tests/dtls.rs)。
- [参考网关驱动](../../experiments/openconnect/reference-gateway/main.go)：运行时依赖外部 mihomo 工作树。

执行环境为 macOS ARM64、Rust 1.98.0、Go 1.26.6、OpenSSL 3.6.3。
固定 Rust 依赖：`smoltcp 0.12.0`、`openssl 0.10.81`、`openssl-sys 0.9.117`，
传递依赖由实验包自己的 Cargo.lock 固定。三者声明的 MSRV 均为 Rust 1.80；
实际 Rust 1.89 构建尚未执行。选择 0.12 是因为本地参考的 smoltcp 0.13.1 要求 Rust 1.91。

mihomo 参考提交为 `260cce1faacd14f1e1123a01748dbf9d088d26e4`，其 DTLS replace 为
`github.com/Demogorgon314/dtls/v3 v3.1.6-0.20260813024800-71e5e4d15116`。
构建辅助程序时读取其 replace 指令，不修改参考仓库，也不将参考实现复制进产品。

## 实验矩阵

| 实验 | 观察结果 | 能证明的范围 |
| --- | --- | --- |
| smoltcp 主动 TCP | 16,384 字节完整回显；MTU 1280；故意丢失 SYN 后重传；客户端 FIN 后仍收到回显 | 两个独立栈经原始 IPv4 包通道主动建连、分段和半关闭可行 |
| smoltcp UDP | 1 / 1200 / 17 字节数据报逐个回显，源地址和端口匹配 | UDP 数据报边界和端点语义可行 |
| OpenSSL ↔ OpenSSL PSK | DTLSv1.2、PSK-AES128-GCM-SHA256、双向应用数据 | 标准 DTLS 1.2 PSK 后端可用 |
| OpenSSL ↔ OpenSSL 注入恢复 | AES128-GCM-SHA256；两端 `session_reused = true`，没有先做正常握手 | 可从外部 master secret、session ID、cipher 构造可恢复会话 |
| 两种现代模式丢首个 ClientHello | 重发 ClientHello 后成功交换应用数据 | 真实 OpenSSL 握手重传有效 |
| 错误 PSK / master secret | 在 1.5 秒预算内握手不成立 | 无效密钥不产生成功会话；DTLS 可能静默丢弃而非立即告警 |
| UDP 黑洞 | 首次发送及重传均被丢弃，1.5 秒后返回 deadline | 外层可按结果选择 TLS 回退；尚未实现生产 auto/require 状态机 |
| OpenSSL ↔ mihomo fixture PSK | 验证控制 TLS 证书，从该连接导出 PSK，DTLSv1.2 下 DATA 双向往返 | `EXPORTER-openconnect-psk` 与 Pion 后端互通 |
| OpenSSL ↔ mihomo fixture 注入恢复 | PSK-CHACHA20-POLY1305；`session_reused = true`；DATA 双向往返 | 与该 fixture 的 OC2 注入恢复模式互通，无正常 PSK 握手替代 |
| 旧 Cisco ↔ mihomo fixture | 首次 ClientHello seq=0；HelloVerify 后 seq=1 被拒绝，5 秒截止 | 旧版本选择和初始报文有效；完整握手和 DATA 未证明 |

现代 DTLS 数据实验均使用不同长度的多次数据报往返，避免仅把“握手成功”当作可用证据。
原始 IP 与 DTLS 是两个独立实验，尚未串成完整代理链路。参考 peer 只回显 DATA 的载荷，
不证明真实 VPN 服务器、IP 路由、企业认证或真实网络下的吞吐。

## Rust 绑定缺失 API 与适配结论

| 能力 | 当前可用入口 | 实验采用的补充 |
| --- | --- | --- |
| PSK 回调、cipher、DTLS 1.2 版本、MTU | `openssl` 高层 API | 无需补密码算法 |
| 控制 TLS exporter | `SslRef::export_keying_material` | 对实际控制连接调用；跨实现已验证 |
| 提交恢复会话、查询是否恢复 | `set_session` / `session_reused` | 高层 API 已有；必须检查恢复结果 |
| 新建并填充外部会话 | 固定版本的高层 API 与 openssl-sys 未提供所需 setter 组合 | 公开 C API 的小范围 extern 声明，RAII 管理 `SSL_SESSION` |
| 会话版本、cipher、master key、ID、ID context、时间与有效期 | `SSL_SESSION_new`、`SSL_SESSION_set_protocol_version`、`SSL_SESSION_set_cipher`、`SSL_SESSION_set1_master_key`、`SSL_SESSION_set1_id`、`SSL_SESSION_set1_id_context`、`SSL_SESSION_set_time`、`SSL_SESSION_set_timeout` | 输入通过复制 setter 写入，未访问私有结构、未手写 DER |
| 按协议 cipher ID 查找 cipher | `SSL_CIPHER_find` | 补公开 C API 声明 |
| DTLS 超时处理 | `DTLSv1_handle_timeout` 是 C 宏 | 经 `openssl_sys::SSL_ctrl` 调用；生产应结合 deadline/readiness 调度 |
| 外部会话的 EMS 策略 | 高层 `SslOptions` 缺少对应常量 | 经公开 `SSL_CTX_set_options` 禁用 EMS，仅限注入会话上下文 |
| `DTLS1_BAD_VER` | `SslVersion` 没有该值或 raw 构造函数 | 经版本设置的 `SSL_CTX_ctrl` 宏入口传入 `0x0100` |
| 旧模式 Encrypt-then-MAC 选项 | 高层常量缺失 | 公开 options 位；只在旧模式实验关闭 |

另一个实际发现：OpenSSL 即使做 PSK cipher 的会话恢复，也会在没有 PSK callback 时
将该 cipher 过滤掉，报 `no ciphers available`。实验注册一个始终拒绝正常握手的
callback 使 cipher 可被选择，然后通过 `session_reused` 确认只走恢复路径。
生产实现必须保留“不可退化为未授权的新握手”的约束。

握手重传既可能由显式 `handle_timeout` 处理，也可能在下一次 `do_handshake` 内处理；
测试观察实际 ClientHello 重发，不能仅按宏返回值计数判断是否重传。

现有 `SslStream` 自定义 BIO 可以驱动此次 datagram-preserving wrapper，但未覆盖完整
datagram BIO 控制语义。生产还需完成 Tokio readiness、重传 deadline、MTU/截断处理、
并发所有权和取消。实验中的轮询与短 sleep 不作为生产实现直接移植。

## 旧 Cisco 失败边界

参考工作树的 `internal/testutil/openconnect/anyconnect_legacy_dtls.go` 中，
`handleLegacyDTLSDatagram` 要求 ClientHello 的 message sequence 恒为 0。
OpenSSL 首次发送 0，在收到 HelloVerify 后发送 1；网关记录
`unexpected fake legacy DTLS handshake message` 并拒绝后续报文。

实验保留独立 ignored 诊断测试 `reference_cisco_legacy`，按 README 显式运行会失败。
没有修改参考网关或把失败改成“通过”；现代成功测试分别执行。
后续要用支持 OpenSSL 该握手序列的独立服务器（例如适当配置的 ocserv），
或先校验并修正 fixture 的消息序号约束，再验证 Finished、重放保护与双向数据。
即使修复首个差异，也不能预先假设后续握手必然通过。

## 阶段 1 的输入与后续边界

本次检查结果：

- `cargo test --locked --manifest-path experiments/openconnect/Cargo.toml`：8 项通过，
  3 项需要外部 fixture 的测试默认 ignored。
- 显式执行 `reference_psk_uses_control_tls_exporter` 和 `reference_injected_dtls12`：2 项通过。
- 显式执行 `reference_cisco_legacy`：失败，原因与报文序号记录见上文；未计入通过项。
- `cargo clippy --locked --manifest-path experiments/openconnect/Cargo.toml --all-targets -- -D warnings`：通过。
- `cargo fmt --manifest-path experiments/openconnect/Cargo.toml -- --check`、辅助脚本语法及文档相对链接检查：通过。
- release 测试构建成功；本机 `rust-objcopy` 因缺少 `libLLVM.dylib` 出现 strip 警告。
  随后以 `CARGO_PROFILE_RELEASE_STRIP=none cargo test --locked --release --manifest-path experiments/openconnect/Cargo.toml`
  完成无该警告的优化构建与 8 项测试。未修改工具链或产品构建配置。

没有运行产品 workspace 全套测试：此次 Rust 改动全部位于独立实验 workspace，
根 Cargo.toml、Cargo.lock 及产品源码未变更。

可以开始 Cookie + CSTP/TLS + smoltcp 的纵向闭环，并以已验证的现代模式规划 DTLS 后端。
本阶段不新增 `AdapterType`、用户配置或 Cargo 产品 feature，不改变现有 meow 行为。

以下仍属于后续阶段：真实网关互通、完整认证、CSTP framing、IPv6、DNS、热重载与会话代次、
TLS/DTLS 切换、生产 Tokio 驱动、完整背压/关闭测试及跨平台打包。
未执行真实节点 smoke、ocserv 集成和产品新增 feature 构建，因为这些实现尚不存在。
阶段 0 的完成表示实验与后端选择有证据，不表示完整 OpenConnect 支持已经完成。
