# Windows Docker Android worker

Docker 管理 QEMU/KVM Ubuntu worker 与 API；guest 内运行 Redroid 和固定 Android Chrome。局域网启动见 [WINDOWS_LAN.md](WINDOWS_LAN.md)，已有验收结果见 [IMPLEMENTATION.md](../../IMPLEMENTATION.md)。

## 前提

- Linux x86_64 Docker engine 提供可执行的 KVM；每次启动由 `kvm_probe.py` 实跑 vCPU，失败不回退软件模拟。
- 源 VM 关机，准备其独立 qcow2 副本；用 `qemu-img compare` 核对逻辑内容并记录源盘前后 SHA-256。禁止可写挂载原盘或同时启动源 VM 与副本。
- 固定官方基础镜像与最终 image ID；QEMU/OVMF 使用 Debian 签名包，版本清单在 `/usr/local/share/fxfetch-packages.tsv`。
- Windows 的验证不适用于 Apple Silicon；新机器须另验架构、加速、网络和 worker。

## 私有配置

复制 `.env.example` 到私有位置并设置：

| 变量 | 目录内容 |
| --- | --- |
| `FXFETCH_ANDROID_STATE` | `root.qcow2,identity.json,OVMF_VARS_4M.fd` |
| `FXFETCH_ANDROID_CONFIG_DIR` | `android-worker.json`、专用 SSH key、固定 `known_hosts` |

`identity.json` 仅含小写标准 `uuid` 和冒号分隔小写 `mac`，沿用已核验源身份。网卡固定 PCI `00:03.0`、磁盘 virtio-blk，启动后检查 `enp0s3`。EFI 变量首次从镜像模板复制，此后持久保存。

配置中的 key/known_hosts 使用容器路径 `/run/fxfetch-worker/<filename>`；API 包装器复制到私有卷并设权限。保留 guest helper、环境、Chrome/Trichrome 的准确摘要。迁移 NoCloud 机器可保留原 `seed.iso`（≤1 MiB、只读），不要使用网站提供的磁盘。

磁盘、EFI、密钥、认证数据库和业务材料不进入源码。

## 构建与启动

构建 `Dockerfile` 和 `Dockerfile.api`，准备 Compose 配置，再按 [启动与 LAN 指南](WINDOWS_LAN.md)运行。默认只发布网页 `127.0.0.1:18765`。

Debian 默认使用 HTTPS 官方源，保留证书、Release 签名和包摘要校验。必要时可显式传 `--build-arg DEBIAN_MIRROR=mirrors.ustc.edu.cn`。构建专用 `--add-host` 只能使用当次核验的公共地址，不能固化历史 CDN IP 或改宿主 DNS。

打包需叠加 `compose.build.yaml`、使用 API `builder` 目标，只读挂载预置 Linux SDK 和字体，重新配置容器工具路径及原私有签名。不能直接使用 Windows SDK 或盘符路径；构建不自动下载 SDK、Chrome 或目标应用。

## 网络与资源

API 使用 `network_mode: service:android-worker`。QEMU guest 为 `10.0.2.15`，宿主侧 `10.0.2.2` 连接共享命名空间回环。

| 内部端点 | 地址，不对 LAN 发布 |
| --- | --- |
| SSH | `127.0.0.1:12222` |
| CDP | `127.0.0.1:19222` |
| 连接前守卫 | `127.0.0.1:18767` |

worker 仅获得 `/dev/kvm`：无 privileged、Docker socket、宿主网络或案件共享目录；只读根、删除 capabilities、禁止提权。guest 为 4 GiB / 2 vCPU，worker 容器内存上限 6 GiB、无额外 swap；API 独立限额，日志限量。

## 验收与维护

依次验证 KVM、磁盘、guest/SSH 身份、`recover-idle`、实时 lease、合成下载、内外层阻断、取消和独立期限。SSH healthcheck / Compose healthy 仅说明可达，不能启用采集；原 VirtualBox 收据不能替代 Docker 验收。

维护前确认无活动 lease，让 guest 有序关机再停止 Compose。TERM 通过 QMP 请求 ACPI 关机并最多等待 5 秒确认；`guest_acpi_shutdown_acknowledged` 只表示请求被接受，仍须检查实际退出。

参考：[KVM API](https://www.kernel.org/doc/html/latest/virt/kvm/api.html)、[QEMU 网络](https://www.qemu.org/docs/master/system/devices/net.html)。
