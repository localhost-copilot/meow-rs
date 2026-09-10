# OpenConnect：Rust 1.91 / smoltcp 0.14 与 mihomo 的 iperf3 对照

结果：本机最终配置的 iperf3 上传／下载达到本轮“接近或更好”的预期；
**DTLS 四流双向回显仍落后 31.4%，本轮未解决这一差距。**
不能用单向 iperf3 的结果覆盖这一差距，也不能外推为所有负载都已对齐。

用户已接受将 workspace 的最低 Rust 版本从 1.89 提升至 1.91。
meow-netstack 升级为 smoltcp 0.14，应用测试中的独立模拟网关仍使用 smoltcp 0.12。
被测运行时代码见 `7777d81`，包含此前 `d94ab06` 的背压修复。
此前的 [Rust 1.89 回显基准](openconnect-dtls-2026-09-09.md) 是历史基线，
不能将其双向回显吞吐直接当作下述 iperf3 单向吞吐。

## 最终结果

[完整原始记录](openconnect-iperf3-2026-09-09.txt) 包含两种内核的 iperf3 JSON、
回显结果、服务器计数、协商通道和测试退出结果。
JSON 中的本机主机名已匿名化，测量字段未改动。
下表每格为三次采样的中位数 `[最小值–最大值]`，单位 Mbit/s。

| 模式 | 方向 | 流数 | meow | mihomo |
| --- | --- | ---: | ---: | ---: |
| TLS | 上传 | 1 | 1465.525 [1406.245–1492.018] | 1048.691 [1031.027–1090.105] |
| TLS | 上传 | 4 | 1155.651 [1128.989–1161.338] | 976.487 [966.395–1003.402] |
| TLS | 下载 | 1 | 826.614 [815.682–837.230] | 776.888 [759.063–817.631] |
| TLS | 下载 | 4 | 806.291 [801.086–809.000] | 693.783 [663.196–714.694] |
| DTLS | 上传 | 1 | 875.837 [875.254–901.503] | 801.681 [767.703–824.597] |
| DTLS | 上传 | 4 | 857.587 [834.559–857.650] | 866.279 [856.590–884.991] |
| DTLS | 下载 | 1 | 1173.443 [1168.857–1181.792] | 955.521 [923.046–956.570] |
| DTLS | 下载 | 4 | 1034.170 [985.517–1051.930] | 891.156 [884.654–907.098] |

DTLS 四流上传比本轮对照低 1.0%，单流／四流下载分别高 22.8%／16.0%。
参考内核也存在轮次间波动：首轮 DTLS 单流／四流上传中位数为 906.241／925.838，
本轮为 801.681／866.279 Mbit/s。两轮原始值均保留；不能仅因本轮参考值较低，
就断言 meow 的 DTLS 上传始终优于 mihomo。最终表是固定配置的三次采样，
不是交错随机化的大样本统计等效检验。

### 双向载荷回归

TCP 每流上传并完整接收 64 MiB；四流总计 256 MiB，包含 SOCKS 建连时间。
UDP 为 1200 字节包、窗口 16、每次 8192 包。仍是三次采样的中位数和范围，
单位为 **MiB/s，回显有效载荷只计一次**，不能与 iperf3 的 Mbit/s 表直接比较。

| 模式 | 负载 | meow，MiB/s | mihomo，MiB/s |
| --- | --- | ---: | ---: |
| TLS | TCP 单流 | 81.641 [79.311–84.954] | 49.605 [38.198–62.047] |
| TLS | TCP 四流 | 75.439 [71.671–77.884] | 62.980 [62.045–67.923] |
| DTLS | TCP 单流 | 56.536 [53.128–59.796] | 61.334 [58.903–62.324] |
| DTLS | TCP 四流 | 46.202 [42.323–50.722] | 67.305 [61.532–68.224] |
| TLS | UDP 窗口 16 | 45.601 [37.947–50.482] | 39.241 [37.486–40.176] |
| DTLS | UDP 窗口 16 | 45.628 [42.605–49.074] | 40.026 [39.596–40.066] |

DTLS TCP 单流／四流分别落后 7.8%／31.4%；四流差距超过本轮样本范围，仍需优化。
两种内核的 TCP 内容校验通过，UDP 每次均收到 8192 个唯一且内容正确的回复。
最终 meow 的 iperf3 和回显测量中，服务器 UDP 接收缓冲溢出增量均为 0；
mihomo 的 DTLS iperf3／回显分别为 232／222。这个计数不是上述应用 UDP 的丢包数。

128 字节回显延迟如下，单位 ms；每格为三轮各自 p50／p95／p99 的中位数，
不是合并所有请求重新计算的分位数。每轮原始分位数见记录。

| 模式 | 负载 | meow，p50 / p95 / p99 | mihomo，p50 / p95 / p99 |
| --- | --- | ---: | ---: |
| TLS | TCP | 0.105 / 0.140 / 0.150 | 0.138 / 0.163 / 0.170 |
| DTLS | TCP | 0.105 / 0.129 / 0.206 | 0.112 / 0.131 / 0.197 |
| TLS | UDP | 0.148 / 0.165 / 0.195 | 0.155 / 0.179 / 0.195 |
| DTLS | UDP | 0.140 / 0.156 / 0.174 | 0.149 / 0.164 / 0.181 |

## 测试方法

- macOS ARM64 / Apple M4，宿主机 Rust 1.98.0；最低版本另外在 Rust 1.91 Linux 容器验证。
- mihomo checkout：`260cce1faacd14f1e1123a01748dbf9d088d26e4`，Go 1.26.6，
  `CGO_ENABLED=0 go build -tags with_gvisor -trimpath`。
- 两种内核均为完整独立进程，设置 `TOKIO_WORKER_THREADS=4`、`GOMAXPROCS=4`。
  最终 meow 二进制使用默认 features 加 `openconnect-dtls`；测试驱动使用
  `--no-default-features --features openconnect-dtls,listener-mixed`。
  相同 SOCKS5/Mixed 入站、`MATCH,vpn` 路由、用户名密码、VPN DNS、双栈、MTU 1400、压缩关闭。
  mihomo 的 CA PEM 与 meow 的 CA 文件路径由驱动做语法适配，实际信任证书相同。
- 真实 Docker ocserv 1.3.0 / GnuTLS 3.8.9；同一服务器镜像和参数，固定现代兼容模式、
  TLS 1.3 AES-128-GCM 和 DTLS 1.2 PSK AES-128-GCM。
  `occtl` 独立核验会话和有效 MTU：TLS 1372、DTLS 1334。
- iperf3 客户端 3.21，VPN 内服务端 3.18（Debian 包 `3.18-2+deb13u2`）。
  每项 10 秒测量，加 2 秒预热；分别测量 1／4 流上传和 `-R` 下载。
  正式测量每项 3 次，诊断可显式设置 1 次；采样期间不并行构建或运行其他测试。
- iperf3 不直接支持 SOCKS。驱动创建本地 TCP 转发入口，将控制和数据连接全部经 SOCKS5
  送到 VPN 内 `192.0.2.1:5201`；两种内核使用相同转发器，性能路径不经过 UDP 故障注入器。
- 使用 iperf3 JSON 中接收端 `sum_received.bits_per_second`，单位为十进制 Mbit/s。
  客户端 JSON 的 TCP 重传／拥塞窗口是本地转发连接的指标，CPU 字段属于 iperf3 进程，
  都不能当作代理内核或 VPN TCP 栈的直接测量。
- 每个样本结束后读取服务器 IP/TCP/UDP 计数，读取发生在计时区间外。
  这些计数覆盖整个容器网络，不能将外层 UDP 计数直接当作应用 UDP 丢包率。

## 初始升级配置的对照

下表是 smoltcp 0.14 / CUBIC、原 32 KiB TCP 缓冲和共享预算的首轮结果，
每项为 3 个样本的中位数。它不是 Rust 1.89 的 iperf3 测量。

| 模式 | 方向 | 流数 | 初始 meow，Mbit/s | mihomo，Mbit/s |
| --- | --- | ---: | ---: | ---: |
| TLS | 上传 | 1 | 921.589 | 1110.235 |
| TLS | 上传 | 4 | 1041.408 | 1048.213 |
| TLS | 下载 | 1 | 771.241 | 768.736 |
| TLS | 下载 | 4 | 669.341 | 705.000 |
| DTLS | 上传 | 1 | 660.695 | 906.241 |
| DTLS | 上传 | 4 | 670.721 | 925.838 |
| DTLS | 下载 | 1 | 771.126 | 977.721 |
| DTLS | 下载 | 4 | 877.479 | 910.207 |

## 复现

宿主机需要安装 iperf3。服务器镜像内自动安装服务端；先从 meow-rs 构建：

```bash
docker build -t meow-openconnect-ocserv:test tests/openconnect
cargo build --locked --release -p meow-app --features openconnect-dtls
cp target/release/meow /tmp/meow-openconnect-benchmark
```

在指定 mihomo checkout 中执行前述 Go 构建命令，得到参考可执行文件，
然后从 meow-rs 目录执行：

```bash
MEOW_BENCH_WORKLOAD=iperf3 MEOW_BENCH_PROXY_KIND=meow \
  MEOW_BENCH_PROXY_BINARY=/tmp/meow-openconnect-benchmark \
  cargo test --locked --release -p meow-app --no-default-features \
  --features openconnect-dtls,listener-mixed --test openconnect_e2e \
  benchmark_real_ocserv -- --ignored --nocapture
```

对照时改为 `MEOW_BENCH_PROXY_KIND=mihomo`，并将 `MEOW_BENCH_PROXY_BINARY` 指向
相应 mihomo 可执行文件。诊断可设置 `MEOW_BENCH_MODE=off|require` 只运行一种模式，
或 `MEOW_BENCH_IPERF_SAMPLES=1` 缩短采样；正式报告必须记录实际样本数。
省略 `MEOW_BENCH_WORKLOAD` 时保留原 TCP/UDP 回显基准。
本报告回显使用 `MEOW_BENCH_TCP_MIB=64`；默认值为 8 MiB。
先复制被测二进制，避免后续编译测试驱动时覆盖它。

本机 LLVM strip 缺少动态库，构建时使用 `CARGO_PROFILE_RELEASE_STRIP=none`。
实测预先构建后直接运行 release 测试程序，避免将编译负载混入采样。

## 保留配置与适用范围

TCP 收发 socket 缓冲各 128 KiB，应用桥接和 UDP 缓冲保持 32 KiB。
相对原先每方向 32 KiB，每个 TCP socket 增加 192 KiB 的固定缓冲容量；本轮未测内核 RSS。
DTLS 使用 64 KiB 共享发送预算，每连接份额上限保持 32 KiB；高连接数时，预算会随
每流至少一个 MTU 的下限增长。空闲的已建立 TCP 连接仍参与份额分配，
`auto` 回退 TLS 后保留该会话的预算。这是一项保守的突发限制，不能代替完整的发送 pacing。

用户态栈只在没有 TCP 待确认发送数据时，一次处理最多 8 个已就绪的入站包；
小型 ACK／控制包不继续合并，整个过程不等待凑满批次。双向数据也可能携带 ACK，
有 TCP 发送数据时逐包处理，保留 ACK 驱动的发送节奏。读取应用数据时以现有桥接容量为上限，并使用安全的
`ReadBuf::uninit`，避免每次初始化整个临时缓冲。

DTLS 数据循环最多暂存一个未交付的入站包，在等待栈接收期间继续处理出站包和定时器。
原先在循环内直接等待接收队列空位，可能阻塞栈推进所需的出站 ACK。
新增受控通道测试验证队列满时出站仍推进、入站顺序不变；临时还原原逻辑后该测试超时失败，
恢复修复后通过。默认延迟 ACK 保持不变。

## 未保留的实验与回归边界

[诊断原始记录](openconnect-iperf3-2026-09-09-diagnostics.txt) 包含初始基线及下列对照。
其中单次 iperf3 诊断只用于筛选，不能替代正式三次采样。

- 只看 iperf3 时，128 KiB socket、64 KiB 共享预算、扩大应用读取和入站合并的组合看似良好：
  DTLS 单流／四流上传中位数为 897.348／840.969 Mbit/s。
  但同一二进制的 64 MiB 双向回显降至 3.633／12.372 MiB/s，该配置未保留。
- 恢复有限预算下每流 32 KiB 上限，并在 TCP 正在发送时禁止入站合并，修复了严重的
  单流回显退化；四流仍有差距。上述两项是在同一候选中调整，不能单独归因于其中一项。
- 相同缓冲和预算下改用 Reno，三次四流回显为 40.472／53.099／49.407 MiB/s，
  未解决差距，最终保留 CUBIC。
- 关闭延迟 ACK 后，三次四流回显为 29.892／26.592／25.955 MiB/s；单次 iperf3
  下载也下降到单流 1013.061、四流 897.419 Mbit/s。最终撤回此项。

部分慢速诊断中服务器 UDP 接收溢出为零，宿主机 UDP 满缓冲计数也没有增长，
因此不能把剩余差距统一归因于 Docker UDP 丢包。发送节奏、双向 TCP 推进和调度
仍需要进一步定位，扩大缓冲或更换拥塞算法不能据此认为已经解决。

## 适用范围

本次只测本地 Docker、IPv4 目标和 1／4 条 TCP 流；双栈是配置及互通验证范围，
不代表测过 IPv6 吞吐。WAN 延迟／丢包、更多并发、内核 CPU/RSS 仍需独立基准。
不应将本机结果表述为所有链路下与 mihomo 严格等效。

## 验证与二进制标识

- 最终代码的 workspace 单元测试和相关集成测试：23 个套件，1340 通过、0 失败、
  11 个按设计忽略；显式 Docker／参考网关验证另行运行。
- `cargo clippy --locked --workspace --all-targets --features meow-app/openconnect-dtls -- -D warnings`、
  `cargo fmt --all --check`、`git diff --check` 和相关 crate 的 `RUSTDOCFLAGS='-D warnings'` 文档构建通过。
- OpenSSL 独立服务端测试 2 通过，包含握手首包丢失重传和 UDP 黑洞截止；
  参考网关测试 1 通过，覆盖 App-ID PSK、ChaCha 注入恢复及两种错误密钥拒绝。
- 最终代码的真实 ocserv 测试 4 通过：TLS／DTLS 双栈互通、`auto` 阻断后保留原 socket
  回退 TLS 并恢复 DTLS、`require` 阻断后失败且不回退业务流量。
- 已先用 `rust:1.91-bookworm` 完成升级版本的全新 Linux 镜像构建；最终修复在该镜像
  上重新复制源码并增量构建，库测试 1、DTLS 后端 2、栈 socket 7、应用集成 13 通过。
  最终 release 客户端的真实 ocserv DTLS、VPN DNS、IPv4／IPv6 HTTP 验证通过，
  运行时 OpenSSL 3.0.20。
- 两种内核的最终 iperf3 各 24 个样本，以及 TCP／UDP 回显基准全部成功。

宿主机主要测试命令：

```bash
cargo test --locked --lib --bin meow --test sockets --test cstp --test auth \
  --test dtls_backend --test openconnect_config --test openconnect_e2e \
  --test openconnect_dtls_reference --features meow-app/openconnect-dtls
cargo test --locked -p meow-openconnect --features dtls \
  --test dtls_backend -- --include-ignored
MEOW_REFERENCE_GATEWAY=/tmp/meow-reference-gateway \
  cargo test --locked -p meow-app --features openconnect-dtls \
  --test openconnect_dtls_reference -- --ignored --nocapture
cargo test --locked -p meow-app --features openconnect-dtls \
  --test openconnect_e2e independent_ocserv -- --ignored --nocapture
```

被测二进制 SHA-256：

```text
meow   30048bbf6750cf101f8cb43ce20b9bc571b76d83aa8c4bb459c1afb34c4eb1e2
mihomo c4723e8e58ba70468f03d31c02c1b739fe64d2f1bcff6350fbbdcaea50aea311
```
