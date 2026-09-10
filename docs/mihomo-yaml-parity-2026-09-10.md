# 私有 YAML 与 mihomo 行为对齐验证

验证对象：用户提供的私有 YAML。
配置包含 7 个静态节点、1 个代理提供器的 2 个节点、43 个分组、97 个规则提供器和
126 条规则。原文件未修改，节点凭据、订阅地址、服务器地址和展开后的配置均未提交。

参考 mihomo 提交：`260cce1faacd14f1e1123a01748dbf9d088d26e4`。
本轮范围是该配置使用的功能和 AnyConnect；F5 不在本轮范围内。

## 实现

修复从 `092659d` 后逐项提交，运行时代码截至 `336804e`，共 28 个提交
（包括 `f0eaadc` 的测试模块位置调整）。

| 范围 | 已落实的行为 |
| --- | --- |
| AnyConnect | IPv4-only 会话丢弃未协商的入站 IPv6 包，保持 CSTP/DTLS 会话存活。 |
| TLS | BoringSSL 异步 BIO flush 正确保留 WouldBlock 重试状态。 |
| AnyTLS | UDP 首包可以先于 ACK 发送，兼容迟到或缺失的 SYNACK；传递 fingerprint 和 ALPN。 |
| VLESS | 默认使用 XUDP，保留 Reality/Vision 的流处理。 |
| DNS | 加密服务器的 `#分组` 路由、实时分组引用、`respect-rules`、原生 UDP 及截断后的 TCP 重试。 |
| DNS 配置 | ARC 缓存、独立 IPv6 开关、专用直连服务器及 follow-policy；代理服务器解析也使用选定的缓存算法。 |
| 嗅探 | HTTP/TLS 的端口及目的地址策略、DNS mapping 门控，以及 QUIC Initial 解密和 SNI 选路。 |
| 分组与持久化 | `empty-fallback` 随提供器刷新生效；选择及 fake-IP 存储开关生效。 |
| 全局设置 | `allow-lan` 默认绑定、`unified-delay`、`tcp-concurrent`、进程查找模式及默认 IPv6 行为。 |
| 健康检查 | 未指定 `expected-status` 时接受完成的 HTTP 响应，避免把 DNS 测速地址的非 2xx 响应误判为节点失效。显式状态范围仍生效；分组测速保留成功成员；定时及手动测速使用实时 provider 节点，支持同名替换。 |
| GeoData | 顶层模式、loader、URL 和更新配置；GeoIP DAT、反向 CIDR、完整/按需 GeoSite 加载，以及规则和 DNS 分类热刷新。启动只下载实际引用的数据库。 |

QUIC 验证包含 RFC 9001/9369 报文、分片、重传、乱序、畸形报文和真实 SOCKS5
套接字选路测试。它只解析 Initial 中的 ClientHello，不解密应用流量。协议边界见
[嗅探说明](specs/sniffer.md)。

## 配置与真实节点

原文件通过 release 版 `-t` 检查。运行测试使用隔离副本，只调整监听端口、回环绑定
和测试控制器。节点、规则、DNS、GeoData 及提供器配置保持原内容。

| 检查 | mihomo / macOS | meow / macOS release | meow / ARM64 路由器 |
| --- | ---: | ---: | ---: |
| HTTPS 成功 | 8/9 | 8/9 | 8/9 |
| 强制 HTTP/1.1 成功 / 配置节点 | 8/9 | 8/9 | 8/9 |
| SOCKS5 UDP DNS 成功 | 7/8 | 7/8 | 7/8 |
| 本地 DNS 查询成功 | 3/3 | 3/3 | 3/3 |
| 原始规则模式访问 | HTTP 204 | HTTP 204 | HTTP 204 |
| 分组（含 GLOBAL） | 44 | 44 | 44 |
| 规则 / 规则提供器 | 126 / 97 | 126 / 97 | 126 / 97 |
| DNS 分组测速成功成员 | 8 | 8 | 8 |

一个 Shadowsocks 节点明确关闭 UDP，因此 UDP 分母是 8。未通过 HTTPS 的节点
未继续执行 HTTP/1.1 比较。DNS 查询覆盖 fake-IP
合成、fake-IP 排除后的加密 DNS，以及 GeoSite 中国域名策略。节点检测分别选择每个
节点，避免成功请求实际经由其他节点。所有 97 个规则提供器均非空。

较早的一轮完整检查中，三种被测运行方式均达到 HTTPS 9/9、HTTP/1.1 9/9、
UDP 8/8。最终复测时，配置中的一个 SOCKS5 节点发生请求失败：
meow/macOS、meow/ARM64、mihomo 均不能经它完成 HTTPS 或 UDP DNS；
再次单独测试 mihomo 仍失败。其 TCP 监听端口可连接，但直接使用 curl 连接该
SOCKS5 服务也失败（退出码 97，约 5 秒）。因此当前不能声称所有远端节点均可用。
本轮没有修改该 SOCKS5 服务或配置中的节点信息。

DNS 分组测速的 8 个成功成员在两个内核中一致，包括 provider 的两个节点。
失效成员不再导致整个测速接口返回 504，也不会掩盖其他节点的结果。

ARM64 版本使用 Rust 1.91.1、默认完整 features 和 musl 构建；ELF 检查确认没有
动态解释器或运行时共享库依赖。物理设备为 QWRT 25.12.2、ipq95xx、aarch64。
两条 AnyConnect 连接在该设备上均实际建立 `PSK-AES256-GCM-SHA384` DTLS 会话。

路由器测试仅使用私有 `/tmp` 目录、回环监听、`nice 19`、CPU 2 和一个 Tokio worker。
测试前后现有 Clash PID/启动时间、配置文件哈希、策略路由、路由表、Clash TCP
监听及去除计数器/时间戳后的 iptables 规则均一致。临时进程和目录已清理，未安装软件包。

## 自动化检查

- `cargo test --lib`：15 个套件，1341 通过、0 失败、4 个按设计忽略。
- `cargo clippy --all-targets -- -D warnings`：通过。
- 全部 API 集成测试：84 通过；GeoData 下载集成测试：6 通过、1 个网络测试按设计忽略。
- macOS 默认完整功能 release 构建、ARM64 musl 默认完整功能构建：通过。
- 针对各修复运行了配置、协议和传输集成测试；对应实现提交与测试可在提交记录中审阅。

最终完整功能二进制：macOS 为 `target/release/meow`，ARM64 musl 为
`target/openwrt-aarch64/meow`（本地构建产物，不入库）。SHA-256：

```text
macOS  fdaf6930267702f9ec7799b8a1f1037dc9bef12e97e3877de9ad781f25ae8382
ARM64  c25f43fac9190e79e83088f6ce97b0a295cc04897099ce5255042f835dffd29b
```

## 性能与剩余边界

[完整性能复测](benchmarks/mihomo-yaml-parity-2026-09-10.md)：TLS 的四项 iperf 测试
快 6.4%–29.4%；DTLS 单流/四流上传慢 1.5%/10.3%，下载快 24.3%/21.3%。
**DTLS 四流双向 TCP 回显仍慢 33.5%，全面性能对齐尚未完成。**
两包批处理实验没有解决该差距，已撤回；没有用单向 iperf 的优势覆盖回显问题。

这些结果证明上述配置与场景的兼容情况，并不保证远端节点长期可用，也不把 UDP DNS
测试等同于所有 UDP 应用、WAN 丢包环境或任意并发负载的验证。
