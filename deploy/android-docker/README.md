# Docker 管理的 Android Chrome worker

此部署把既有 Ubuntu Android worker 放在 Docker 管理的 QEMU/KVM 中；Ubuntu 内的 Redroid、固定 Chrome、双层防火墙、独立数据卷和任务期限仍由既有 guest helpers 管理。容器本身不启动采集，也不下载浏览器或运行目标 APK。

## 运行前提

- Linux x86_64 Docker engine 能提供 `/dev/kvm`，且 `kvm_probe.py` 的实际 vCPU 执行成功。只有设备文件存在不足以通过；失败不回退 TCG。
- 使用已验收 Ubuntu worker 磁盘的**独立 qcow2 副本**，源 VM 必须关机。通过 `qemu-img compare` 核对全部逻辑内容，并记录源磁盘转换前后 SHA-256；禁止直接挂载原盘为可写。
- 固定镜像基础为官方 Python Debian 镜像 digest。QEMU/OVMF 来自 Debian 签名仓库，镜像内 `/usr/local/share/fxfetch-packages.tsv` 保存实际软件版本；部署记录应固定最终 image ID。
- Docker Desktop / WSL 的 KVM 能力可能随宿主配置或升级变化，每次 worker 启动都会重新执行探针。本目录不修改宿主内核、Hyper-V、全局 DNS 或代理。
- 这是 x86_64 KVM 路线。不能把 Windows 的成功外推到 Apple Silicon Mac mini；目标机器必须另行验证架构和加速能力，或连接独立的已验收 worker。

## 私有目录

将 `.env.example` 复制到私有位置并设置两个目录：

| 变量 | 内容 |
| --- | --- |
| `FXFETCH_ANDROID_STATE` | `root.qcow2`、`identity.json` 和本环境独立的 `OVMF_VARS_4M.fd` |
| `FXFETCH_ANDROID_CONFIG_DIR` | API 使用的 `android-worker.json`、专用 SSH key、固定 `known_hosts` |

`identity.json` 只允许 `uuid` 和 `mac` 两个字符串，分别为标准小写 UUID 和冒号分隔的小写 MAC。迁移副本应填写源 worker 的已核身份，不能使用示例机器身份。网卡固定 PCI `00:03.0`，磁盘为 virtio-blk；启动后仍须确认原 `enp0s3` 配置正常。EFI 变量文件首次从镜像内 OVMF 模板复制，随后只保存在该私有目录。

配置 JSON 中的 key 和 known_hosts 路径必须改为容器内 `/run/fxfetch-worker/<filename>`。API 启动包装器会将选定文件复制到其私有持久卷并设置权限，再生成内部配置。保留 guest session helper、environment helper、Chrome 和 Trichrome 的准确 SHA-256；不得因迁移清空校验。磁盘、EFI 状态、SSH 私钥、认证数据库和实际业务数据均不进入源码交付。

迁移已使用 NoCloud 的机器时，可在私有 state 内保留原部署的 `seed.iso`（≤1 MiB，只读连接），防止更换虚拟硬件后丢失原 cloud-init 实例身份；不得放入网站提供的磁盘或安装镜像。

## 网络与权限

`api` 使用 `network_mode: service:android-worker`。QEMU 用户态网络保留 guest 地址 `10.0.2.15`、宿主侧 `10.0.2.2`，后者连接共享 namespace 的回环地址。SSH 为 `127.0.0.1:12222`，CDP 为 `127.0.0.1:19222`，连接前守卫为 `127.0.0.1:18767`；Compose 不发布这三个端口。验收配置仅发布宿主 `127.0.0.1:18765` 的网页 API。

worker 仅获得 `/dev/kvm`，没有 privileged、Docker socket、宿主网络、共享案件目录或物理设备。根文件系统只读、capabilities 全部移除并禁止提权；guest 内存固定 4 GiB / 2 vCPU，容器内存上限 6 GiB、无额外 swap。API 与 worker 分别设置内存和进程限额，日志滚动限量。

SSH banner healthcheck 只表示控制链路可达。API 使用前还必须执行固定 guest helper 的 `recover-idle` 和实时身份/防火墙/磁盘证明；不能凭 Compose healthy 启用 Chrome。

## 构建与验收

先构建 `Dockerfile` 和 `Dockerfile.api`，再按 Compose 启动专用 worker。Debian 源使用 HTTPS、禁用 apt 代理与重试。如果本地 DNS 给出代理虚拟地址，应通过可信公共 DNS 重新核验官方源；可以仅为该次构建使用 `--add-host deb.debian.org:<verified-public-ip>`，不得把临时 CDN IP 写成发行默认值。

默认仓库仍为 `https://deb.debian.org`。该链路持续过慢时，可为本次构建传入 `--build-arg DEBIAN_MIRROR=mirrors.ustc.edu.cn`；这是 Dockerfile 明确允许的另一处 [Debian 镜像](https://mirrors.ustc.edu.cn/help/debian.html)。仍验证 HTTPS 证书、Debian Release 签名及包摘要，不禁用验证，也不修改宿主 DNS。`--add-host` 应使用当次公共 DNS 核验结果，而不是复制历史 CDN 地址。

依次完成 KVM 执行、磁盘完整性、guest 启动、SSH host key、`recover-idle`、实际 lease、合成下载、内外层阻断、任务取消与独立期限验收。迁移前的 VirtualBox 收据只能证明源环境，不能替代 Docker 下的这些验收。网页业务与打包验证由主部署流程负责。

Docker TERM 会经本 worker 的 QMP Unix socket 请求 ACPI 关机，并在总计 5 秒内等待对应命令 ID 的确认；异步事件不会被误当成命令回复。重复信号不重复发请求，控制失败只记录原因且继续监督 QEMU。`guest_acpi_shutdown_acknowledged` 只表示 QEMU 接受请求，仍须检查容器正常退出，不能据此认定 guest 已关机。正常维护优先在确认无活动 lease 后让 guest 有序关机，再停止 Compose；不得同时启动原 VM 和该副本。

保留 APK 打包时，使用 `compose.build.yaml` 与 `Dockerfile.api` 的 `builder` 目标，并只读挂载预置的 **Linux** Android SDK 和字体。容器内重新配置工具链路径与私有签名状态；Windows SDK/build.json 绝对路径不能直接复用。构建镜像不自动下载 Android SDK、Chrome 或目标应用。

依据：[Linux KVM API](https://www.kernel.org/doc/html/latest/virt/kvm/api.html)、[QEMU 网络文档](https://www.qemu.org/docs/master/system/devices/net.html)。
