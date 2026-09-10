# OpenConnect DTLS：ARM64 物理路由器验证

日期：2026-09-09（America/Los_Angeles；设备时间为 2026-09-10）。
实现提交：`8160585`。本次在用户授权的物理路由器上通过 SSH 测试，未安装软件包，
未停止、重启或修改现有 OpenClash/mihomo 服务。

## 环境和隔离

- QWRT 25.12.2，R26.8.8 / QSDK 12.5，Linux 5.4.213。
- `ipq95xx/generic`，`aarch64_cortex-a53`，4 个在线 CPU。
- 使用此前通过 musl/QEMU 验证的静态 ARM64 二进制，features 为
  `minimal,openconnect-dtls`；SHA-256：
  `3971615b61005501525fd7a284819fea5b85eee5a0488a571639b5d909e84793`。
- 二进制、测试 CA、配置和探针只放在私有 `/tmp` 目录，Mixed 仅监听
  `127.0.0.1:18080`，关闭 DNS 与 TUN，无控制器监听。
- 临时进程采用 `nice 19`、CPU 2 亲和性、一个 Tokio worker；启动时 RSS
  约 7.3–9.8 MiB，仅为启动快照，并非内存峰值。
- 真实 ocserv 网关运行在测试电脑的 Docker 中，使用自签测试 CA 和 fixture 账号。
  UDP 丢包由电脑上的转发器注入，没有操作路由器防火墙。
- 完整路径：路由器上的 SOCKS5 探针/curl → meow 入站 → `MATCH,vpn` →
  OpenConnect → ocserv → VPN 内 HTTP、TCP/UDP 回显服务。

## 结果

| 项目 | 结果 |
| --- | --- |
| `off`、`require`、`auto` 配置与启动 | 均通过 |
| 三种模式的 VPN DNS、IPv4/IPv6 HTTP | 均返回 `ocserv-http` |
| 三种模式的 IPv4/IPv6 TCP 和 UDP | 20、1200、37 字节载荷逐字节回显均通过 |
| 真实 DTLS 协商 | 客户端记录 `PSK-AES256-GCM-SHA384`，occtl 独立确认 AES-256-GCM |
| `require` 下 UDP 黑洞 | 原 IPv4、IPv6 TCP 连接关闭，通过；此项未单独检查 UDP 关闭通知 |
| `auto` 下 UDP 黑洞 | 回退 CSTP，同一组 TCP4/TCP6/UDP4/UDP6 socket 均继续回显 |
| `auto` 恢复 UDP | 回退约 30 秒后恢复 DTLS；仍用同一组 socket 回显成功 |
| 三种模式各 1 MiB 的限速 TCP 回显 | 均逐字节校验通过 |

限速传输每次发送 8192 字节，收齐回显后等待 8 ms，共 128 次。
最终一轮 `off` / `require` / `auto` 分别耗时 3.443 / 2.930 / 3.208 秒。
每方向应用有效载荷的平均速率上限为 8.192 Mbit/s，实际还受往返延迟和调度影响。
这用于验证持续数据传输，不能作为峰值吞吐或与 mihomo 性能持平的证据。
为遵守不影响已有服务的要求，本次没有安装 iperf 或执行满载压测。

## 现有服务及清理

测试前后核对通过：Clash PID 与 `/proc` 启动时间不变；现有 Clash 配置、
network/firewall/dhcp 配置的 SHA-256 不变；策略路由、全部路由和 Clash TCP
监听列表不变；控制器仍返回预期的未认证 HTTP 401，代理仍返回 HTTP 407。
这些检查证明进程未重启且上述状态保持一致；未读取生产代理凭据，未验证其认证后的业务请求。

原始 `iptables-save` 哈希不同；该输出含生成时间和链计数器，初始记录仅保存哈希，
因此不能据此证明完整防火墙规则文本前后相同。测试没有执行防火墙写操作，
结束时也未发现测试端口对应的规则。

临时 meow 和探针均已退出，测试端口关闭，路由器私有临时目录已删除。
电脑侧的 UDP 转发器和 ocserv 容器也已停止。未安装 ipk，未修改服务启停配置。

此前的构建、自动化测试及 QEMU 安装验证见
[OpenWrt ARM64 验证](openconnect-openwrt-validation.md)。
