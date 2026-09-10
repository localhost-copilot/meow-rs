# OpenConnect 四流性能调查

本轮在 `perf/openconnect-four-flow` 分支进行，发布基线为 `v0.23.1`。
服务器、账号、证书均来自本地 ocserv 测试夹具；不载入私有 YAML，
不发布节点名称、地址、端口、凭据、证书指纹或订阅内容。

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

- macOS ARM64，默认完整功能的独立 meow 进程，与同一台主机上的 mihomo 对比。
  两者均为 4 个运行时工作线程，相同本地 SOCKS 转发器和 Docker ocserv 镜像。
- iperf3 客户端 3.21，服务端 3.18；每次测量 10 秒，另有 2 秒预热。
  接收端有效吞吐按十进制 Mbit/s 记录。
- `-P 4` 上传和 `-R -P 4` 下载分别为四条数据连接。
  `--bidir -P 4` 为每方向四条、合计八条数据连接，另有控制连接。
  它与“四条连接每条同时收发”的 TCP 回显测试分开报告。
- TCP 回显每流 64 MiB，接收端逐字节校验，吞吐按单份有效载荷 MiB/s 记录。
- 每个计时区间外核验 DTLS 套件、MTU 和容器网络计数。
  iperf3 客户端的 TCP 重传、拥塞窗口属于本地转发连接，不能代表 VPN TCP 栈。
- 正式测量不并行编译、抓取 CPU profile 或运行其他负载。单次诊断只用于筛选方案。

## 复现

```bash
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
`MEOW_BENCH_PROFILE=legacy` 保留此前夹具参数；本轮数据不可与此前不同参数的结果直接合并。
