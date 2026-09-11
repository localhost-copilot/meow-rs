# GeoSite 紧凑 Trie 优化

这是 `8a8c786`，接在规则匹配器共享和规则集去重之后。优化只改变 GeoSite
的只读存储布局：加载阶段使用可变构建树，完成后将节点、边和标签放入连续
数组；普通规则集仍使用原有 `DomainTrie`。

离线组件测量使用配置引用的 222,447 个 GeoSite 模式和 931,129 个域名查询：

| 指标 | 原通用 Trie | 紧凑 Trie | 变化 |
| --- | ---: | ---: | ---: |
| 有效堆占用 | 5,328,047 B | 4,696,444 B | -11.9% |
| 查询匹配数 | 233,053 | 233,053 | 一致 |
| 五轮耗时中位数 | 144.356 ms | 140.409 ms | -2.7% |

大小和耗时均为同一进程中的组件测量，不包含配置解析和整个内核的固定开销。
所有查询结果一致，包含大小写、尾部点、精确域名、单标签通配符和后缀通配符。
程序化 `GeositeDB::insert` 仍在可变构建阶段插入，避免逐条插入重建整棵树。

在 ARM64 OpenClash 上使用同一份配置、同一 GeoSite 模式和
`geodata_loader=memconservative`，两版各自重启后等待相同时间，在无活动连接
时采样：

| 指标 | 紧凑优化前 | 紧凑优化后 | 变化 |
| --- | ---: | ---: | ---: |
| RSS | 38,204 KiB | 34,688 KiB | -3,516 KiB (-9.2%) |
| RSS 历史峰值 | 52,116 KiB | 48,464 KiB | -3,652 KiB (-7.0%) |
| 匿名 RSS | 27,864 KiB | 24,460 KiB | -3,404 KiB |
| 文件 RSS | 10,340 KiB | 10,228 KiB | -112 KiB |

两次 A/B 都保留了上一版核心作为回滚文件。紧凑版当前已运行在路由器上，
核心 SHA-256 为：

```text
d1c24aff475d2035b022ddceb1c677a07653872aeaa19b90135bbdd28946d55f
```

替换后的检查结果：98 个规则提供者、553,129 条提供者内容、134 条路由规则、
55 个代理注册项保持一致；两个 OpenConnect peer 的 HTTPS 健康检查通过；
DTLS、透明 HTTPS、Zashboard 和 Metacubexd 均正常。

验证命令：

```sh
cargo test --locked -p meow-trie --lib
cargo test --locked -p meow-rules --all-targets
cargo test --locked -p meow-config --test config_test
cargo clippy --locked -p meow-trie -p meow-rules --all-targets -- -D warnings
```

该优化没有改动 OpenConnect/DTLS、relay buffer、UDP 队列或 DNS 缓存容量，
因此没有把内存收益换成连接吞吐下降。包中只包含二进制和许可证，不含配置、
节点、凭据或抓包。
