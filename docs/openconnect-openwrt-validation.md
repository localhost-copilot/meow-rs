# OpenConnect DTLS：OpenWrt ARM64 验证

日期：2026-09-09（本地时间）。目标为用户指定的 ARM64。
实现提交：`8160585`。

## 实现

Linux musl 在启用 `openconnect-dtls` 时静态构建 OpenSSL 3.6.3（`openssl-src
300.6.1`），对 ssl/crypto 归档全部全局定义以及它们的引用添加 `meow_oc_` 前缀。
libc 等外部引用保留原名；构建会核对改名前后的定义集合，并拒绝残留的未加前缀引用。
只把加前缀后的归档所在目录交给链接器，原始 `libssl.a`／`libcrypto.a` 不进入搜索路径，
避免影响 BoringSSL 按同名归档进行的链接。
同时检查生成的 OpenSSL 配置确实禁用 DSO，避免 Cargo feature 合并意外启用动态加载。
OpenSSL 禁用共享库、外部 provider 模块，原 BoringSSL 控制 TLS 不变。

运行时沿用同一套 OpenSSL FFI、AsyncFd、握手重传和会话状态机，
`require` 不再因 musl 平台而失败，`auto` 仍支持 TLS 回退和 DTLS 恢复。
macOS／glibc 继续使用原动态隔离后端。

## 环境与方法

- 构建：Rust 1.91.0，GNU Linux ARM64 主机，cargo-zigbuild 0.20.1、Zig 0.13.0，
  目标 `aarch64-unknown-linux-musl`。GNU 构建主机允许 bindgen 加载 libclang。
- 交付二进制 features：`--no-default-features --features minimal,openconnect-dtls`。
- 系统：QEMU 11.1.1，官方 OpenWrt 24.10.7 armsr/armv8 initramfs，
  `r29197-ab4c7d6af7`、Linux 6.6.141。镜像按官方 SHA-256 校验。
- 网关：真实 Docker ocserv 1.3.0 / GnuTLS 3.8.9，临时自签 CA、测试账号，
  使用与 glibc 测试相同的服务器 fixture。
- 路径：OpenWrt 内安装 `.ipk` → 完整 meow 进程 → Mixed/HTTP 入站 →
  `MATCH,vpn` → OpenConnect → ocserv → VPN DNS、IPv4／IPv6 HTTP 与 TCP 回显。
- UDP 故障由 OpenWrt 虚拟机内的独立 nftables 表注入，只丢弃网关 DTLS 端口，
  不修改宿主机防火墙。`auto` 恢复检查保留同一条 HTTP CONNECT/TCP 回显连接。

## 验证项目

| 项目 | 结果 |
| --- | --- |
| 静态 ELF，无 INTERP、无 NEEDED | 通过；无需设备动态加载器或 `libssl` |
| musl 独立 OpenSSL DTLS 服务端 | 2 项通过，包含首包丢失重传、双向数据报、黑洞截止 |
| musl 入站背压测试 | 1 项通过 |
| musl 用户态 socket 测试 | 7 项通过 |
| musl 应用模拟网关 | 13 项通过、5 项按设计忽略；包含自动回退、双栈 TCP/UDP、VPN DNS |
| musl 独立参考网关 | App-ID PSK、ChaCha 注入恢复、两种错误密钥拒绝通过 |
| OpenWrt 安装及三种模式双栈访问 | 通过；实际 DTLS cipher 为 PSK-AES256-GCM-SHA384 |
| OpenWrt `require` UDP 阻断 | 原 TCP 连接关闭，不回退 TLS，通过 |
| OpenWrt `auto` UDP 阻断及恢复 | 同一 TCP 连接经过 DTLS → TLS → DTLS 后仍能回显，通过 |
| 宿主机回归 | 23 套件，1340 通过、0 失败、11 忽略 |
| Clippy、Rustdoc、格式及脚本语法 | 通过 |

真实 OpenWrt 的最终运行记录见 [验证输出](openconnect-openwrt-validation.txt)。
独立参考网关使用用户指定 mihomo checkout `260cce1faacd14f1e1123a01748dbf9d088d26e4`，
通过仓库的参考网关构建脚本交叉编译成 Linux ARM64 可执行文件。

## 交付及复现

构建和 OpenWrt 测试命令见 [使用说明](openconnect.md#openwrt--musl-构建)。
`tests/openconnect/Dockerfile.musl` 包含完整的静态编译及本地测试流程；
`tests/openconnect/test_openwrt.sh` 为显式运行的真实网关测试，不进入 CI。
CI 新增 ARM64 musl 静态构建和本地模拟测试；本地验证不代表远端 CI 已经运行。

最终构建在已验证的 GNU→musl 镜像上增量复制源码，重新运行相关测试并构建 release。
最终 OpenWrt 测试通过 `MEOW_IPK` 直接安装下表中的交付包，同时验证 OpenSSL 许可证文件。
未传 `MEOW_IPK` 时，脚本才会以测试版本号重新打包 `MEOW_BINARY`。

| 本地文件（`target/openwrt-dtls-dist/`） | 字节数 | SHA-256 |
| --- | ---: | --- |
| `meow-aarch64` | 10877320 | `3971615b61005501525fd7a284819fea5b85eee5a0488a571639b5d909e84793` |
| `meow_0.21.2-openconnect1_aarch64_generic.ipk` | 5654067 | `015ff0087a10f474f0b872d48793cc01f1f91816e029c18ede0e35a3197cf1bd` |

同目录还生成了 `aarch64_cortex-a53`、`aarch64_cortex-a72`、`aarch64_cortex-a76`
三个标签的包，二进制完全相同；设备上用 `opkg print-architecture` 确定应选的标签。
实际 QEMU 安装验证使用 `aarch64_generic`。上述哈希对应本地交付文件，重新打包后的
压缩包时间戳可能不同。

本报告记录的是 ARM64 虚拟机上的真实 OpenWrt 内核和用户空间，当时未连接物理路由器，
也未在路由器硬件上测量吞吐。x86_64、MIPS 和 32 位 ARM 不在本轮实测范围。
默认发布包仍未开启 OpenConnect。静态 OpenSSL 更新需要重新构建和替换 meow。

后续已完成 [ARM64 物理路由器验证](openconnect-router-validation.md)，包含三种模式、
双栈 TCP/UDP、DTLS 故障和恢复；该实机测试未进行满载吞吐对比。

资料：[OpenWrt 镜像及校验值](https://downloads.openwrt.org/releases/24.10.7/targets/armsr/armv8/)、
[openssl-src 构建库](https://github.com/alexcrichton/openssl-src-rs)、
[LLVM objcopy 符号重命名](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-redefine-syms)。
