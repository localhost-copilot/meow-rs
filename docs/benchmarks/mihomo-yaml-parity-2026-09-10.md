# YAML 兼容修复后的 OpenConnect 性能复测

运行时代码为 `336804e`，使用默认完整功能的 release 二进制。
TLS 的四项 iperf3 测试均快于本轮 mihomo；DTLS 上传慢 1.5% / 10.3%，
下载快 24.3% / 21.3%。**DTLS 四流双向 TCP 回显仍慢 33.5%，未达到全面性能对齐。**
该差距与[前一轮回显基准](openconnect-iperf3-2026-09-09.md)的已知问题一致。

[采样记录](mihomo-yaml-parity-2026-09-10.txt)包含全部 `BENCH_*` 行、iperf JSON、
会话协商、容器网络计数和测试退出结果。仅将 iperf JSON 中的本机主机名匿名化，
测量字段未改动；末尾保留了未采用的两包批处理实验。

## iperf3

每项三次，表中为中位数 `[最小值–最大值]`，单位 Mbit/s。
差值为 meow 相对 mihomo 的中位数差值。

| 通道 | 方向 | 流数 | meow | mihomo | 差值 |
| --- | --- | ---: | ---: | ---: | ---: |
| TLS | 上传 | 1 | 1264.041 [1231.395–1302.116] | 976.939 [969.431–989.391] | +29.4% |
| TLS | 上传 | 4 | 1006.124 [979.920–1011.314] | 913.198 [886.169–923.159] | +10.2% |
| TLS | 下载 | 1 | 819.086 [797.832–832.471] | 769.458 [726.582–774.157] | +6.4% |
| TLS | 下载 | 4 | 786.227 [771.040–787.427] | 669.681 [652.386–673.607] | +17.4% |
| DTLS | 上传 | 1 | 794.520 [771.113–797.064] | 806.988 [795.110–808.867] | −1.5% |
| DTLS | 上传 | 4 | 758.492 [691.157–763.799] | 845.336 [843.977–854.834] | −10.3% |
| DTLS | 下载 | 1 | 1000.999 [999.214–1004.049] | 805.066 [800.950–816.577] | +24.3% |
| DTLS | 下载 | 4 | 920.597 [914.524–926.392] | 759.189 [749.093–765.656] | +21.3% |

## 双向回显

TCP 每流发送并完整接收 64 MiB，四流合计 256 MiB，包含 SOCKS 建连时间。
UDP 使用 1200 字节载荷、窗口 16、每轮 8192 包。下表单位 **MiB/s**，
回显载荷只计一次，不能与上面的单向 Mbit/s 直接比较。

| 通道 | 负载 | meow | mihomo |
| --- | --- | ---: | ---: |
| TLS | TCP 单流 | 77.181 [70.845–86.926] | 45.885 [39.555–47.570] |
| TLS | TCP 四流 | 67.523 [65.542–89.033] | 57.081 [53.556–65.972] |
| DTLS | TCP 单流 | 50.367 [50.264–51.082] | 54.987 [53.374–60.426] |
| DTLS | TCP 四流 | 40.079 [37.096–49.127] | 60.255 [40.070–61.606] |
| TLS | UDP 窗口 16 | 42.535 [41.148–43.638] | 34.831 [33.338–35.386] |
| DTLS | UDP 窗口 16 | 42.552 [41.593–42.639] | 35.165 [34.379–35.456] |

TCP 内容校验全部通过；两个内核的六轮 UDP 采样均收到 8192/8192 个唯一且内容正确
的回复。DTLS TCP 单流慢 8.4%，四流慢 33.5%；四流存在明显轮次波动，表中保留范围。

128 字节回显延迟，单位 ms；每格为三轮各自 p50 / p95 / p99 的中位数，
并非合并全部请求后的分位数：

| 通道 | 负载 | meow | mihomo |
| --- | --- | ---: | ---: |
| TLS | TCP | 0.105 / 0.131 / 0.174 | 0.127 / 0.180 / 0.214 |
| TLS | UDP | 0.148 / 0.175 / 0.205 | 0.161 / 0.192 / 0.213 |
| DTLS | TCP | 0.102 / 0.138 / 0.160 | 0.115 / 0.138 / 0.170 |
| DTLS | UDP | 0.146 / 0.168 / 0.180 | 0.148 / 0.176 / 0.247 |

额外尝试在有限发送预算、TCP 正在发送时合并两个已就绪入站包。
三次 DTLS 四流回显为 49.982 / 36.439 / 42.167 MiB/s，中位数 42.167；
仍未消除差距，样本范围与原配置重叠。该实验已撤回，未进入实现提交或交付二进制。

## 方法与边界

- macOS ARM64 / Apple M4，Rust 1.98.0；mihomo 提交
  `260cce1faacd14f1e1123a01748dbf9d088d26e4`，Go 1.26.6，`with_gvisor`。
- 相同 Docker ocserv 1.3.0 镜像和 VPN 参数：双栈、MTU 1400、压缩关闭，
  TLS 1.3 AES-128-GCM、DTLS 1.2 PSK AES-128-GCM。`occtl` 核验实际通道。
- 两个内核均为独立完整进程，设置 `TOKIO_WORKER_THREADS=4`、`GOMAXPROCS=4`。
  相同 SOCKS5 入站、`MATCH,vpn` 路由和信任证书；CA 的配置语法按内核适配。
- iperf3 客户端 3.21、服务端 3.18；10 秒测量加 2 秒预热，使用接收端
  `sum_received.bits_per_second`。相同 SOCKS 转发器承载控制及数据连接。
- 两种内核各 24 个 iperf 样本，TCP/UDP 回显及延迟另行采样。正式采样期间
  未并行构建或运行其他测试；不是交错随机化的大样本统计等效检验。
- 本地 Docker、IPv4 目标、1/4 条 TCP 流；不涵盖 WAN 丢包、IPv6 吞吐、更多并发、
  内核 CPU/RSS。iperf JSON 的 CPU 与 TCP 指标属于 iperf 及本地转发连接，
  不能当作 VPN TCP 栈的直接指标。
- 这是 AnyConnect 相同参数的隔离性能基准。用户完整 YAML 的实际互通及 ARM64
  结果见[配置验证报告](../mihomo-yaml-parity-2026-09-10.md)，未把完整 YAML 当作吞吐负载。

复现沿用[现有测试驱动](../../crates/meow-app/tests/support/openconnect_benchmark.rs)：

```bash
# 先保存完整 app，再构建驱动，避免驱动所需的最小功能构建覆盖被测 app。
cargo build --locked --release -p meow-app
cp target/release/meow /tmp/meow-bench-full
cargo test --locked --release -p meow-app --no-default-features \
  --features openconnect-dtls,listener-mixed --test openconnect_e2e --no-run

# 使用上一命令给出的测试程序路径替换 <driver>。
MEOW_BENCH_WORKLOAD=iperf3 MEOW_BENCH_PROXY_KIND=meow \
  MEOW_BENCH_PROXY_BINARY=/tmp/meow-bench-full \
  <driver> benchmark_real_ocserv_tls_dtls --ignored --nocapture
```

回显时省略 `MEOW_BENCH_WORKLOAD`，设置 `MEOW_BENCH_TCP_MIB=64`。
对照改用 `MEOW_BENCH_PROXY_KIND=mihomo` 及对应二进制。
宿主机本轮用 `CARGO_PROFILE_RELEASE_STRIP=none` 绕过已有 strip 工具问题。

被测二进制 SHA-256：

```text
meow   fdaf6930267702f9ec7799b8a1f1037dc9bef12e97e3877de9ad781f25ae8382
mihomo c4723e8e58ba70468f03d31c02c1b739fe64d2f1bcff6350fbbdcaea50aea311
```
