# OpenConnect：真实 ocserv 上与 mihomo 的同配置性能对比

本文保留 Rust 1.89 / smoltcp 0.12 的历史结果。升级后的 iperf3 和双向回显对照见
[Rust 1.91 性能报告](openconnect-iperf3-2026-09-09.md)。

日期：2026-09-09。meow 为 `96b914a` 加随本文提交的发送预算、数据缓冲复用和
release 优化；mihomo 为用户指定 checkout 的 `260cce1faacd14f1e1123a01748dbf9d088d26e4`。

本轮本地测试中，meow 的 TLS 吞吐高于 mihomo，DTLS 短流和 UDP 表现接近或更好。
每流 64 MiB 的持续 DTLS 测试中，单流和四流中位数分别落后 **7.5% 和 9.0%**。
因此尚不能宣称性能完全一致，也不能将短流的优势外推到持续传输或 WAN。

## 环境与公平性

- 客户端：macOS ARM64 / Apple M4，Rust 1.98.0、Go 1.26.6；meow 保持 Rust 1.89 MSRV。
- Docker 29.4.0，Linux VM 10 CPU、约 11.7 GiB 内存；真实 ocserv 1.3.0 / GnuTLS 3.8.9，
  由仓库 `tests/openconnect/Dockerfile` 构建，Python 回显服务位于 VPN 内。
- 两边均启动完整内核进程，经同一 SOCKS5 客户端 → Mixed 入站 → `MATCH,vpn` →
  OpenConnect → ocserv → 回显服务。mihomo 使用 `with_gvisor`，meow 使用 smoltcp 0.12。
- 两边均限制为 4 个运行时 worker，使用用户名密码、同一合成账号和信任 CA、VPN DNS、
  IPv6 开启、压缩关闭、MTU 请求 1400，分别测试 `dtls-mode: off` 与 `require`。
  mihomo 的 `ca` 接收 PEM 文本，meow 接收文件路径；驱动仅转换这一表示差异。
- 每次使用新容器与新会话。服务器 benchmark 配置关闭 `cisco-client-compat`，固定
  AES-128-GCM；独立查询 `occtl` 并断言实际 TLS 1.3 / AES-128-GCM、
  DTLS 1.2 / PSK / AES-128-GCM，以及有效 MTU：`off` 1372、`require` 1334。
  meow 的 CSTP 使用 BoringSSL，DTLS 动态加载 OpenSSL 3.6.3。
- 性能路径直连 Docker 映射端口，不经过故障注入转发器。采样期间没有并行构建或其他测试。

## 采样方式

每种内核、每流大小各运行 3 轮，每轮每个指标采样 3 次，即表中每项 **9 个样本**。
第 1、3 轮顺序为 meow → mihomo，第 2 轮为 mihomo → meow。没有丢弃慢样本。
吞吐表为中位数，括号为最小值–最大值。

会话先用 128 B TCP 回显预热。TCP 测试 1 流和 4 流，每流分别发送 8 MiB、64 MiB，
包含新 SOCKS 流建连时间，完整校验所有回显内容和半关闭。四流结果为合计吞吐。
MiB/s 只计算有效回显载荷一次，不将发送和接收相加。

UDP 每个样本发送 8,192 个 1,200 B 数据报，窗口 16，检查内容、序号和重复。
延迟每个样本逐次回显 300 个 128 B 载荷；表中 p50/p95/p99 分别取 9 个样本
对应分位数的中位数，并非合并所有请求后的分位数。

## TCP 吞吐，MiB/s

| 每流载荷 | 模式 | 并发 | meow，中位数（范围） | mihomo，中位数（范围） |
| --- | --- | ---: | ---: | ---: |
| 8 MiB | TLS | 1 | 53.716（45.881–60.283） | 48.693（13.621–54.571） |
| 8 MiB | TLS | 4 | 67.852（66.887–70.078） | 35.310（30.654–79.535） |
| 8 MiB | DTLS | 1 | 52.376（49.136–57.892） | 52.581（14.021–65.149） |
| 8 MiB | DTLS | 4 | 54.733（53.386–55.927） | 18.045（6.738–68.270） |
| 64 MiB | TLS | 1 | 65.576（57.337–72.567） | 53.531（42.730–84.339） |
| 64 MiB | TLS | 4 | 74.239（72.855–75.032） | 68.212（65.385–76.540） |
| 64 MiB | DTLS | 1 | 60.377（55.455–62.216） | 65.267（60.484–67.424） |
| 64 MiB | DTLS | 4 | 54.979（54.459–55.970） | 60.425（51.726–69.912） |

短流 mihomo 的波动很大。持续传输的结果更接近，但 meow 的 DTLS 中位数仍较低。
这些是描述统计，未进行显著性检验，不能将重叠的样本范围解释为严格等效。

## UDP 与延迟

下表取 64 MiB TCP 所在轮次的 UDP 与延迟测量；8 MiB 轮次的全部记录同样归档。

| 指标 | meow TLS | mihomo TLS | meow DTLS | mihomo DTLS |
| --- | ---: | ---: | ---: | ---: |
| UDP MiB/s 中位数 | 46.776 | 40.247 | 47.938 | 40.000 |
| UDP MiB/s 范围 | 44.828–51.025 | 38.449–42.526 | 47.088–49.072 | 36.455–40.712 |
| TCP RTT p50/p95/p99，ms | .124/.137/.145 | .120/.138/.152 | .114/.136/.145 | .113/.131/.168 |
| UDP RTT p50/p95/p99，ms | .144/.158/.169 | .154/.172/.216 | .140/.154/.165 | .145/.162/.213 |
| 批量 UDP 接收/发送 | 73728/73728 | 73728/73728 | 73728/73728 | 73728/73728 |

12 次完整 benchmark 全部通过。所有 TCP 内容校验通过；两组载荷大小、两种模式、
两个内核的批量 UDP 合计 589,824 个数据报全部收到，无重复。

计时外读取服务器 `/proc/net/snmp`：meow 所有轮次的 `RcvbufErrors` 增量为 0；
mihomo 的 DTLS 在 8 MiB 三轮为 466/481/283，64 MiB 三轮为 542/547/359。
这些是整个测量期间的外层 UDP 计数，包含承载 TCP 的 DTLS 包，不能当作应用 UDP 丢包率。
接收缓冲溢出与慢样本同时存在，支持继续检查突发与 TCP 丢包恢复，但不足以单独解释全部差距。

## 保留的优化与剩余工作

1. 对 smoltcp、meow-netstack、meow-openconnect 使用 release `opt-level=3`；
   其他 crate 保留原有体积优化策略，降低校验和及逐包处理开销。
2. DTLS 会话共享 32 KiB TCP 发送预算，同时检查总量和每流份额。新流必须等待旧流
   持有的额度释放，避免新流加入时突发超额；每流最低一个 MTU，socket 缓冲仍为 32 KiB。
   该预算是软上限，更多流时可随最低份额增长，`auto` 回退 TLS 后保持同一预算。
3. 复用 DTLS 发送缓冲，接收包直接移交用户态栈，减少逐包分配和复制。

发送预算改善本地突发丢包，但不等同于完整 TCP 拥塞控制。固定窗口可能限制高带宽延迟积
链路，本轮没有 WAN 延迟/丢包性能、更多并发或正式 CPU/RSS 对比，不能宣称普遍对齐。

后续候选是 smoltcp 0.14 的 TCP 拥塞控制、快速重传与校验和改进；该版本要求 Rust 1.91，
高于项目当前 1.89，尚未变更依赖或最低工具链版本，需确定兼容性取舍后再实测。
这些上游改进不保证自动消除差距。见 [smoltcp 官方变更记录](https://raw.githubusercontent.com/smoltcp-rs/smoltcp/main/CHANGELOG.md)。

## 正确性与平台验证

- 当前代码组合测试：1,339 通过、0 失败、11 忽略；忽略项按环境要求独立执行。
- 真实 ocserv 的 TLS、DTLS 双栈/VPN DNS，以及 `auto` UDP 阻断、原 socket TLS 回退、
  DTLS 恢复，`require` 阻断时原 socket 失败，共 4 项通过。
- 独立参考网关验证 App-ID PSK、注入恢复及错误密钥拒绝；OpenSSL 后端验证握手首包丢失、
  黑洞截止和双向数据报。新增栈测试覆盖并发丢包恢复、总发送额度、半关闭和释放。
- Debian glibc / Rust 1.89 / OpenSSL 3.0.20 容器增量构建、测试及真实 Linux 客户端
  VPN DNS、IPv4/IPv6 SOCKS HTTP 验证通过。
- 默认与 DTLS feature 的 workspace Clippy、Rustdoc 警告检查通过。

## 复现

```bash
docker build -t meow-openconnect-ocserv:test tests/openconnect
cargo build --locked --release -p meow-app --no-default-features \
  --features openconnect-dtls,listener-mixed
# 在指定 mihomo checkout 内运行：
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-openconnect-benchmark .
# 回到 meow-rs；分别令 TCP_MIB=8、64，每组重复三轮并交替内核顺序：
MEOW_BENCH_TCP_MIB=64 MEOW_BENCH_PROXY_KIND=meow \
  MEOW_BENCH_PROXY_BINARY="$PWD/target/release/meow" \
  cargo test --locked --release -p meow-app --no-default-features \
  --features openconnect-dtls,listener-mixed --test openconnect_e2e \
  benchmark_real_ocserv -- --ignored --nocapture
MEOW_BENCH_TCP_MIB=64 MEOW_BENCH_PROXY_KIND=mihomo \
  MEOW_BENCH_PROXY_BINARY=/tmp/mihomo-openconnect-benchmark \
  cargo test --locked --release -p meow-app --no-default-features \
  --features openconnect-dtls,listener-mixed --test openconnect_e2e \
  benchmark_real_ocserv -- --ignored --nocapture
```

本机 LLVM strip 缺少动态库，构建额外设置 `CARGO_PROFILE_RELEASE_STRIP=none`。
实测先构建后直接运行 release 测试程序，避免测量时编译。
必须设置 `MEOW_BENCH_PROXY_BINARY` 才是完整独立进程对比；省略时运行嵌入式 meow 测试路径。
驱动自动设置 worker、证书、配置及服务器参数，拒绝 debug benchmark；退出时清理测试容器。

[测试驱动](../../crates/meow-app/tests/support/openconnect_benchmark.rs) ·
[原始记录](openconnect-dtls-2026-09-09.txt)

原始记录以 `BENCH_RUN,kernel,每流MiB,外层轮次` 分组；其余字段：
`BENCH_TCP,mode,并发数,内层样本,MiB,毫秒,MiB/s`；
`BENCH_UDP,mode,窗口,内层样本,发送数,接收数,毫秒,MiB/s`；
`BENCH_LATENCY,mode,项目,内层样本,p50毫秒,p95毫秒,p99毫秒`；
`BENCH_NEGOTIATED,mode,字段,值`；`BENCH_SERVER_UDP,mode,时点,内核计数`；
`BENCH_TRANSPORT,mode,路径,server-dtls-session=布尔值`。
