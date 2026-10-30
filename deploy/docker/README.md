# 独立 Docker 部署

用于独立 HTTP 服务及后续 Mac mini 迁移。默认项目名 `fxfetch-portable`，只发布 `127.0.0.1:18765`；镜像默认不含 Chrome、Android、SDK 或签名密钥。Mac 尚未验收；Windows Android 路线见 [android-docker](../android-docker/README.md)。

## 启动与停止

在项目根目录下的 `deploy/docker` 执行：

```sh
cp .env.example .env
docker compose config --quiet
docker compose build api
docker compose run --rm --no-deps api check
docker compose run --rm --no-deps api init
docker compose up -d --no-build api
```

`init` 在终端设置口令并只保存哈希，随后打开 <http://127.0.0.1:18765>。`check` 核对容器配置且不访问目标；`doctor.server` 是普通 CLI 配置，容器入口以 check 为准。

停止用 `docker compose down`，不加 `--volumes`。状态、证据和签名在命名卷中；停止服务或通过 SQLite 备份 API 做一致性备份。重启将遗留任务标为 interrupted，不重放入口。

## 可选网页离线分析

默认镜像不包含 fxapk，分析默认关闭。容器入口不读取迁移来的 `server.json`（包括其中的 `fxapk_executable`），避免采用宿主的程序路径、监听地址或代理配置。

部署者先在派生 API 镜像中按固定 fxapk 版本及其锁文件建立独立 Linux 环境，或只读挂载已经兼容该镜像的环境，再在 `.env` 设置：

```dotenv
FXFETCH_FXAPK=/opt/fxapk/venv/bin/fxapk
```

这是**容器内的绝对程序路径**，不是安装指令、宿主目录或 shell 命令；包含空格的路径仍作为单个文件名处理。不接受相对路径、Windows/UNC 路径和控制字符。留空关闭分析；路径不存在或不可执行时，服务仍可启动，但 `web_analysis.enabled` 为 false。

设置变量不会安装或挂载 fxapk。Linux 环境须匹配镜像的 Python 3.12、CPU 架构和系统库，venv 的解释器及脚本 shebang 路径须在容器内成立；不能复用 Windows/macOS venv，也不要把 fxapk 依赖混装进 fxfetch。UID/GID 10001 需有读取/执行权限，程序环境保持只读，输出仅写入私有状态卷。镜像及挂载由部署者预置，不添加网络权限、Docker socket 或运行时下载行为。

`docker compose config --quiet` 和 `api check` 只校验部署配置，不运行 fxapk。重建/更新 API 容器后，通过登录后的能力接口确认配置；能力可用只证明可执行文件能解析，仍需用合成数据包验收真实离线分析、取消和报告下载。`--offline` 契约不是操作系统断网沙箱，不能据此声称 NAS/Docker 全链路已验收。原数据包、APK/IPA 和报告分开保存，WebView APK 不参与此分析。

## 可选 APK 构建

预置 **Linux** SDK 的 `platforms/android-35/android.jar` 与 `build-tools/37.0.0`，在 `.env` 设置绝对路径 `FXFETCH_LINUX_SDK`：

```sh
docker compose -f compose.yaml -f compose.build.yaml build api
docker compose -f compose.yaml -f compose.build.yaml run --rm --no-deps api init-build \
  --sdk /opt/android-sdk --build-tools /opt/android-sdk/build-tools/37.0.0 --java-home /opt/java
docker compose -f compose.yaml -f compose.build.yaml run --rm --no-deps api doctor
docker compose -f compose.yaml -f compose.build.yaml up -d --no-build api
```

builder 镜像增加 JDK 17，SDK 只读挂载；后续构建部署命令始终带两个 `-f`。不使用 Windows/macOS SDK 二进制或盘符路径。

迁移时安全保留 `.build-private/application.p12`、`password` 和数据库映射，重新配置容器工具路径，不重新生成原签名。可选字体需另行预置，使用容器绝对路径并保留固定摘要与许可检查。构建不联网补工具或目标资源。

| 主机 | 路线与验证边界 |
| --- | --- |
| Intel Mac | linux/amd64 API 和 Linux x86_64 SDK；仍须 Mac 实机验收 |
| Apple Silicon | 原生 linux/arm64 API；依赖 wheels 可解析不等于运行通过 |
| Apple Silicon APK 构建 | 另评估 amd64 仿真或外部构建 worker，不承诺 Linux ARM64 SDK 可用 |

参考：[多平台构建](https://docs.docker.com/build/building/multi-platform/)、[Android Linux 要求](https://developer.android.com/studio/install#linux)。

## 网络与资源

容器非 root UID/GID 10001、只读根、无 capabilities、禁止提权；限制 256 PID、3 GiB 总内存和 2 CPU，`/tmp` 为 128 MiB tmpfs。无 Docker socket、宿主 PID/网络、ADB 或 CDP。持久卷至少 8 GiB 可用空间；scratch 使用软预算，不能称为硬 quota。

POSIX wrapper 在 exec 前设置每进程 `RLIMIT_AS`；Linux parent-death signal 清理嵌套执行。每进程地址空间限制与 cgroup 整容器内存限制分别生效。

采集直连，入口清除 HTTP/HTTPS/ALL_PROXY（含大小写），不接宿主代理；这不改变 Docker 拉取镜像、宿主 VPN 或透明路由。

## 局域网发布

`FXFETCH_PUBLIC_IP` 只接受明确 RFC1918/IPv4 回环 IP。内外端口同号以匹配 Host/Origin；网段冲突须同时调整 `FXFETCH_CONTAINER_SUBNET,FXFETCH_CONTAINER_IP,FXFETCH_TRUSTED_PEERS`，不能扩大到全部私网。

默认只信任桥接网关 /32 和自身 /32。Mac 先保持回环完成登录、上传和下载，再用第二台 LAN 设备验收。Docker NAT 可能改写 peer，不能依赖 X-Forwarded-For 恢复来源；需宿主防火墙限制 LAN 来源，未验证前保留回环发布。

参考：[Docker Desktop 网络](https://docs.docker.com/desktop/features/networking/)、[端口发布](https://docs.docker.com/engine/network/port-publishing/)。

## Android 与迁移验收

Android 与本 Compose 分离，见 [worker 说明](../../scripts/android-worker/README.md)。Docker Desktop 能跑 API 不代表具备 Binder、Android 内核或匹配的 Chrome 架构；现有 worker 回环地址也不能直接当成跨主机 endpoint。API 不获得 Android 特权，不公开 ADB/CDP/Docker socket。

`tests/linux_container_acceptance.py` 使用断网容器、合成页面、固定工具和字体验证；不涵盖原包取得、Android 安装或第二台 LAN 设备。结果见 [IMPLEMENTATION.md](../../IMPLEMENTATION.md)。

构建上下文按 `.dockerignore` 允许列表提供，不含运行数据、工具、APK、HAR、密钥或虚拟环境。Mac 迁移至少补验登录/会话、扫码进程、合成采集、取消超时、SDK 签名、字体、重启不重放及第二台 LAN 来源限制和下载完整性。
