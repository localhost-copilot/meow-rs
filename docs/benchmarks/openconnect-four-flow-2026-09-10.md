# OpenConnect 四流性能调查

本轮在 `perf/openconnect-four-flow` 分支进行，发布基线为 `v0.23.1`。
服务器、账号、证书均来自本地 ocserv 测试夹具；不载入私有 YAML，
不发布节点名称、地址、端口、凭据、证书指纹或订阅内容。

候选版的四连接回显中位数较发布基线提高约 **28%**：profile B 与 mihomo
基本一致，profile A 仍低约 **10%**。无额外延迟时，单向四流上传低于 mihomo 约 **4–7%**，
下载高约 **18–19%**。因此已缩小主要四流差距，但不能宣称所有负载都已追平：
`iperf3 --bidir -P 4` 的上传较基线翻倍后，仍比 mihomo 低 **61–65%**。

## 正式结果

以下为 AES-128-GCM、未额外增加延迟时的三次测量中位数。
完整的 [126 个测量值](openconnect-four-flow-2026-09-10.samples.json) 保留每次结果；
`optimized` 表示候选版。没有剔除已完成的低吞吐样本，包括参考内核 A 组一次
22.134 MiB/s 的四连接回显。样本量较小，百分比描述本机测量，不表示置信区间
或 OpenWrt/WAN 的性能保证。

iperf3 接收端吞吐，单位 Mbit/s：

| 配置 | 负载 | v0.23.1 | 候选版 | mihomo | 候选版相对 mihomo |
| --- | --- | ---: | ---: | ---: | ---: |
| A | 四流上传 | 636.686 | 714.366 | 746.357 | -4.3% |
| A | 四流下载 | 852.883 | 823.919 | 701.032 | +17.5% |
| A | 同时收发：上传 | 40.048 | 85.769 | 221.957 | -61.4% |
| A | 同时收发：下载 | 684.840 | 739.109 | 695.384 | +6.3% |
| B | 四流上传 | 736.402 | 761.211 | 815.173 | -6.6% |
| B | 四流下载 | 895.015 | 913.605 | 765.631 | +19.3% |
| B | 同时收发：上传 | 40.994 | 86.289 | 246.732 | -65.0% |
| B | 同时收发：下载 | 764.865 | 790.238 | 698.566 | +13.1% |

相对发布基线，A/B 单向上传分别提高 12.2%/3.4%；下载分别为 -3.4%/+2.1%。
不能只保留候选版改善的方向。上表的同时收发为每方向四条数据连接，总计八条。

逐字节校验的 TCP 回显，单位 MiB/s，载荷只计一次：

| 配置 | 连接数 | v0.23.1 | 候选版 | mihomo |
| --- | ---: | ---: | ---: | ---: |
| A | 1 | 45.826 | 48.011 | 51.744 |
| A | 4 | 39.494 | 50.764 | 56.530 |
| B | 1 | 51.515 | 52.625 | 55.095 |
| B | 4 | 42.892 | 55.091 | 55.013 |

UDP 回显所有 18 次测量均收到 8192/8192 个正确载荷。窗口为 16 个包；A/B
候选版中位数 42.701/42.670 MiB/s，基线 41.573/42.231，mihomo 34.616/34.318。
这组有限窗口的回显结果不能当作无约束 UDP 最大吞吐。

## AES-256-GCM 补测

候选版使用与实际会话相同的 AES-256-GCM 套件，每组每个方向连续测量三次，
中位数如下，单位 Mbit/s。这些结果不与 AES-128-GCM 的参考内核合并比较。

| 配置 | 四流上传 | 四流下载 | 同时收发：上传 | 同时收发：下载 |
| --- | ---: | ---: | ---: | ---: |
| A | 727.223 | 846.537 | 78.083 | 729.681 |
| B | 770.870 | 888.934 | 90.592 | 792.055 |

这组补测和下面的延迟测量均保留了 [每次测量值](openconnect-four-flow-2026-09-10.additional.json)。

## 增加 30 ms RTT 的对照

profile B、AES-128-GCM，三轮独立进程、轮换运行顺序，中位数单位 Mbit/s：

| 负载 | v0.23.1 | 候选版 | mihomo |
| --- | ---: | ---: | ---: |
| 四流上传 | 12.122 | 12.118 | 14.218 |
| 四流下载 | 34.801 | 34.721 | 26.532 |
| 同时收发：上传 | 5.641 | 6.479 | 4.075 |
| 同时收发：下载 | 41.996 | 44.098 | 28.327 |

候选版单向上传/下载与基线分别相差约 -0.03%/-0.2%，同时收发的中位数分别
提高 14.9%/5.0%。相对 mihomo，单向上传仍低 14.8%，下载及同时收发更快。
无额外延迟时的优势与差距不能直接外推到高 RTT。

此前单次诊断中，基线下载为 44.229、候选版为 33.239；该差异触发了这组三轮
交错复测。单次诊断单独保存，不混入正式中位数。三轮结果未复现同等幅度的
单向回退，但仍不足以覆盖所有网络延迟、抖动、丢包和 OpenWrt 设备。

## 匿名配置与比较边界

| 参数 | profile A | profile B |
| --- | --- | --- |
| dtls-mode / dtls-key-exchange | auto / auto | auto / auto |
| mtu / base-mtu | 0 / 0 | 0 / 0 |
| ipv6-disabled | true | false |
| queue-length | 128 | 32 |
| dpd-interval / reconnect-timeout，秒 | 5 / 60 | 5 / 300 |
| remote-dns-resolve | true | true |
| 压缩请求 / 实际协商 | stateless / Identity | stateless / Identity |
| 服务器分配地址族 | IPv4 | IPv4 |
| 有效 DTLS MTU | 1214 | 1317 |
| 本地 ocserv mtu 参数 | 1280 | 1383 |

这些配置复现观察到的客户端选项与有效 DTLS 参数，不代表已知远端服务器的
完整配置、系统或链路。真实会话的 CSTP/DTLS MTU 相同；本地 ocserv 在 DTLS
建立前的 CSTP MTU 为 1252/1355。测试在预热和 `occtl` 确认 DTLS 建立后计时。

真实会话与 meow 协商 PSK AES-256-GCM。参考 mihomo checkout
`260cce1faacd14f1e1123a01748dbf9d088d26e4` 使用的 sing-openconnect
`a503d88051b3` 在 `connectModernPSK` 中没有提供该套件；本地服务器仅允许
AES-256-GCM 时，服务端报告没有共同套件，参考内核连接超时。
因此直接性能对照固定双方都支持的 AES-128-GCM；AES-256-GCM 单独验证 meow。
不能把两种密码套件的结果混作同参数比较，也不能把参考内核的连接失败记为吞吐为零。

## 方法

- Apple M4（10 核、24 GiB），macOS 26.6.2 ARM64，默认完整功能的独立
  meow 进程，与同一台主机上的 mihomo 对比。
  两者均为 4 个运行时工作线程，相同本地 SOCKS 转发器和 Docker ocserv 镜像。
- Docker 运行于 OrbStack Linux 7.0.14，宿主和虚拟机共用该机器的 CPU。
  Rust 1.98.0；参考内核使用 Go 1.26.6、`with_gvisor` 构建标签。
- iperf3 客户端 3.21，服务端 3.18；每次测量 10 秒，另有 2 秒预热。
  接收端有效吞吐按十进制 Mbit/s 记录。
- `-P 4` 上传和 `-R -P 4` 下载分别为四条数据连接。
  `--bidir -P 4` 为每方向四条、合计八条数据连接，另有控制连接。
  它与“四条连接每条同时收发”的 TCP 回显测试分开报告。
- TCP 回显每流 64 MiB，接收端逐字节校验，吞吐按单份有效载荷 MiB/s 记录。
- 每个计时区间外核验 DTLS 套件、MTU 和容器网络计数。
  iperf3 客户端的 TCP 重传、拥塞窗口属于本地转发连接，不能代表 VPN TCP 栈。
- 正式测量不并行编译、抓取 CPU profile 或运行其他负载。单次诊断只用于筛选方案。
- iperf 对每组配置进行三轮独立进程测量；每轮轮换基线、候选版和参考内核的
  顺序。回显每个进程连续测量三次。报告中位数，并保留每次测量的数值。
- 候选实现的源代码对应 `27a9c6e`，启用 SACK 最早缺口恢复、200 ms 实测 RTO
  下限和微秒协议时钟，发送预算仍为 64 KiB。

二进制 SHA-256（完整功能构建，速度敏感 crate 使用 `opt-level=3`）：

| 对象 | SHA-256 |
| --- | --- |
| meow v0.23.1 基线 | `f32a0b95ba15dea3f4fddc380d0ada3f8904d9a8daa206b1b9827915b1d11968` |
| meow 候选版 | `e3fb8bea0374cc7d9269f74287c64c66993a427f638432d543f4d877cacfc56e` |
| mihomo 参考版 | `c4723e8e58ba70468f03d31c02c1b739fe64d2f1bcff6350fbbdcaea50aea311` |
| ocserv 本地夹具镜像 | `46b4ec712830ff996cf02722d68ee6a69b4e65a1d90da2a3d7870e6e0ca82b29` |

## 丢包恢复定位

在独立的抓包诊断中，四流的 12 条客户端数据连接分别出现 1–5 次约
998–1003 ms 的发送停顿；单流未出现同类停顿。抓包中未发现任何一侧的
TCP 零窗口公告。可见累计 ACK 前存在数据缺口，约一秒后重传才继续推进。
这些诊断吞吐不计入正式结果。

上游 smoltcp 0.14.0 通过三个纯重复 ACK 触发快速重传；携带回显数据的 ACK
会重置该计数。候选实现根据协商过的 SACK 块判断最早缺口：缺口之后已确认的
连续数据超过两个发送 MSS 时，触发一次快速重传。这使用
[RFC 6675 的充分丢失判据](https://www.rfc-editor.org/rfc/rfc6675.html#section-4)，
并非完整的发送端 SACK scoreboard、RACK 或 Tail Loss Probe。

重复报告同一缺口不会重复触发重传；SACK 范围必须位于实际已发送的数据内。
只有累计 ACK 才释放发送缓冲。对没有足够 SACK 证据的尾部丢包，OpenConnect
启用 200 ms 的实测 RTO 下限，仍保留初始 1 秒 RTO、RTT/方差估计和指数退避。
这项策略不同于 [RFC 6298 建议的 1 秒下限](https://www.rfc-editor.org/rfc/rfc6298.html)，
参考 gVisor 发送端同样采用 200 ms 下限。vendored crate 默认仍为上游的 1 秒；
`meow-netstack` 明确启用该选项。

## 方案筛选记录

以下为诊断数据，不与最终交错对照的样本合并。

- 每次向 DTLS 队列批量提交 8 个已准备的数据包：两组配置的 iperf 未改善，撤回。
- 用独立 waker 识别空闲连接，按实际发送需求分配 64 KiB 预算：
  profile B 同时收发的上传从单次 52.134 提高到 86.821 Mbit/s，
  但 profile A 四连接回显三次中位数从 39.393 降至 31.226 MiB/s，撤回。
- 逐包处理 ACK、补充发送预算和发送回复，再批量交付应用数据：
  四连接回显仍回退，同时收发下载降至单次 442.117/465.382 Mbit/s，撤回。
- CPU 采样期间，宿主机 UDP 接收缓冲溢出增量为 0。
  这不能证明整个链路没有丢包；该轮被采样扰动的吞吐不计入正式结果。
- 小 MTU 配置的 UDP 回显使用 1186 字节载荷，另一配置使用 1200 字节。
  最初固定 1200 字节的 profile A 回显轮次未完成，已排除并重跑。

使用实验性的每连接 ACK 判断、毫秒时钟时，对固定发送预算的扫描如下。
每格为三次四连接 TCP 回显的中位数，单位 MiB/s。

| 发送预算 | profile A | profile B |
| --- | ---: | ---: |
| 32 KiB | 48.388 | 48.132 |
| 64 KiB | 33.201 | 47.149 |
| 128 KiB | 22.204 | 27.068 |

这说明扩大预算在当前路径上会降低回显吞吐；不能据此断言 32 KiB
也是高延迟、远程链路的最佳值。保留微秒时钟后，32 KiB 的单向四流上传
只有单次 608.238/606.180 Mbit/s，低于 64 KiB 发布基线的 702.094/760.902。
因此不采用这项预算缩减；每连接 ACK 判断也因回显回退而撤回。

## 复现

本轮验证包括与项目 CI 默认测试清单一致的本地回归：2176 项通过，0 失败，
4 项原有忽略；独立 ocserv 和应用路径端到端测试 21 项通过。SACK、序号回绕、
无效范围和低 RTT 尾部丢包退避均有确定性测试。另行验证了保留上游 1 秒 RTO
下限的特性组合。测试均使用本地夹具，没有在 CI 或远程节点进行跑分。
完整功能 release 构建、全工作区 Clippy（`-D warnings`）和格式检查通过；
用户原始 YAML 使用隔离资源目录进行 `-t` 校验也通过。私有配置及校验日志
留在本地，不包含在报告和提交中。

下一轮优先调查无额外延迟的同时收发上传，以及较高 RTT 下的上传预算。
应在现有丢包恢复基础上记录实际在途数据与恢复阶段，再评估完整 SACK 恢复、
RACK/TLP 和发送预算分配。此前扩大缓冲、按发送需求分配预算的方案存在回退，
本轮没有采用它们。该性能分支的实现与数据不改变已发布的 `v0.23.1`。

```bash
export CARGO_PROFILE_RELEASE_STRIP=none
docker build -t meow-openconnect-ocserv:perf tests/openconnect
cargo build --locked --release -p meow-app
cp target/release/meow /tmp/meow-openconnect-perf
cargo test --locked --release -p meow-app --no-default-features \
  --features openconnect-dtls,listener-mixed --test openconnect_e2e --no-run
```

先完成所有构建，再直接运行上述命令输出的测试可执行文件：

```bash
MEOW_BENCH_PROFILE=a MEOW_BENCH_MODE=auto \
MEOW_BENCH_CIPHER=AES-128-GCM \
MEOW_BENCH_OCSERV_IMAGE=meow-openconnect-ocserv:perf \
MEOW_BENCH_PROXY_KIND=meow MEOW_BENCH_PROXY_BINARY=/tmp/meow-openconnect-perf \
MEOW_BENCH_WORKLOAD=iperf3 MEOW_BENCH_IPERF_STREAMS=1,4 \
MEOW_BENCH_IPERF_SAMPLES=3 \
<test-executable> benchmark_real_ocserv_tls_dtls --ignored --exact --nocapture
```

`MEOW_BENCH_PROFILE=b` 选择另一组配置；参考内核使用 `MEOW_BENCH_PROXY_KIND=mihomo`
和相应独立二进制。`MEOW_BENCH_CIPHER=AES-256-GCM` 选择 meow 的实际协商套件。
省略 `MEOW_BENCH_WORKLOAD` 并设置 `MEOW_BENCH_TCP_MIB=64` 运行回显验证。
`MEOW_BENCH_DELAY_MS=30` 只在夹具容器的出口增加 30 ms 延迟，约增加 30 ms RTT；
它不修改宿主机、路由器或现有服务的网络接口。延迟测试须与无延迟结果分开报告。
`MEOW_BENCH_PROFILE=legacy` 保留此前夹具参数；本轮数据不可与此前不同参数的结果直接合并。
