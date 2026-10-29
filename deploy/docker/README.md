# fxfetch 的独立 Docker 部署

这一部署供后续迁移到 Mac mini；不接管当前 Windows LAN 服务。默认项目名 `fxfetch-portable`，只发布 `127.0.0.1:18765`。镜像内运行轻量 API/静态前端及现有受限 HTTP 采集子进程，默认没有 Chrome、Android、SDK 或签名密钥。构建能力在工具链未配置时明确禁用。

## 本机启动

在项目根目录的 `deploy/docker` 中操作：

```sh
cp .env.example .env
docker compose config --quiet
docker compose build api
docker compose run --rm --no-deps api check
docker compose run --rm --no-deps api init
docker compose up -d --no-build api
```

`init` 在终端隐藏输入并确认密码，只保存哈希。随后访问 `http://127.0.0.1:18765`。`check` 只核对容器配置，不解析目标；`doctor` 只核对本地能力，其 `server` 字段仍是普通 CLI 的配置，不代表容器入口配置，以 `check` 为准。停止使用 `docker compose down`，不要加 `--volumes`；状态、证据、签名身份保存在本项目命名卷中。

容器固定为非 root UID/GID 10001、只读根文件系统、删除所有 Linux capabilities、禁止提权、256 PID、3 GiB 总内存与 2 CPU；无 Docker socket、宿主 PID/网络、ADB 或 CDP 映射。`/tmp` 为 128 MiB tmpfs；任务和构建 scratch 位于持久卷。持久卷需至少 8 GiB 可用空间，仍采用现有软磁盘预算，不能当成硬文件系统 quota。没有自动重启策略；显式重启后遗留任务为 `interrupted`，不重放入口。

应用统一直连，入口清除大小写形式的 HTTP/HTTPS/ALL_PROXY，`Settings.proxy_host=None`；不接宿主代理。Docker Desktop 自己的镜像拉取、宿主 VPN/透明路由属于宿主网络配置，不能据清除进程变量声称这些已被改变。

## Mac 架构与 APK 构建

| 目标 | 当前部署路径 | 验收边界 |
| --- | --- | --- |
| Intel Mac mini | 原生 `linux/amd64` API；Linux x86_64 SDK + JDK 构建 | Windows Docker 的 Linux x86_64 验收不替代 Mac 主机网络验收 |
| Apple Silicon Mac mini | 原生 `linux/arm64` API，运行依赖提供 ARM64 wheels | ARM64 wheels 可解析不等于 ARM64 容器已运行 |
| Apple Silicon 上构建 APK | 可单独评估 `linux/amd64` 容器仿真，或未来外部构建 worker | 不将 Windows/macOS SDK 二进制直接挂到 Linux；不默认承诺 Linux ARM64 SDK 工具可用 |

Docker 官方说明跨架构镜像需要对应变体或仿真，编译类任务在仿真下可能明显变慢：[多平台构建](https://docs.docker.com/build/building/multi-platform/)。Android 官方当前列明 Linux ARM CPU 不受 Android Studio 支持；这并不自动证明每个 SDK 文件的架构，部署仍须检查 `aapt2`、`zipalign` 的 ELF 架构并实跑：[Linux 系统要求](https://developer.android.com/studio/install#linux)。

需要打包时，先在私有目录预置 **Linux** Android SDK：`platforms/android-35/android.jar` 和 `build-tools/37.0.0`。下载和许可确认在工具链准备阶段完成，APK 构建阶段不联网补工具或目标资源。在 `.env` 设置绝对路径 `FXFETCH_LINUX_SDK`，然后：

```sh
docker compose -f compose.yaml -f compose.build.yaml build api
docker compose -f compose.yaml -f compose.build.yaml run --rm --no-deps api init-build \
  --sdk /opt/android-sdk --build-tools /opt/android-sdk/build-tools/37.0.0 --java-home /opt/java
docker compose -f compose.yaml -f compose.build.yaml run --rm --no-deps api doctor
docker compose -f compose.yaml -f compose.build.yaml up -d --no-build api
```

`builder` 镜像只增加 JDK 17；SDK 只读挂载，密钥和密码在私有状态卷内生成。后续所有构建部署命令均带两个 `-f`。不复制 Windows `build.json` 的盘符路径；跨机迁移签名身份时应独立安全迁移 `.build-private/application.p12` 与 `password`，重新写容器绝对工具路径，不重新生成替换原签名。字体也必须另行预置并配置容器绝对路径；没有字体配置仍可构建，但体积和字体效果不同。原有固定字体摘要与许可校验不放宽。

POSIX 执行现在由独立 Python wrapper 在 `exec` 前设置 `RLIMIT_AS`，不在线程内使用 `preexec_fn`。Linux parent-death signal 使被监督的嵌套执行会随父 worker 终止；受控 JVM 预留和 glibc arena 上限解决小地址空间中的启动/签名问题。`RLIMIT_AS` 是**每进程虚拟地址空间限制**，不是进程树 RSS 总额；Compose 的 cgroup 另设整容器 3 GiB 总内存上限。Windows Job Object 行为和 JVM 参数不变。

## 局域网入口

`.env` 的 `FXFETCH_PUBLIC_IP` 只接受明确 RFC1918 或 IPv4 回环地址，禁止 `0.0.0.0`、公网 IP 和域名。容器内部同样绑定明确私网 IP；发布端口与内部端口保持同号，以匹配现有 Host/Origin 检查。桥接网段冲突时须同时调整 `FXFETCH_CONTAINER_SUBNET`、`FXFETCH_CONTAINER_IP` 和 `FXFETCH_TRUSTED_PEERS`，不能用所有私网或全部地址绕过冲突。

默认只信任桥接网关 `/32` 与自身 `/32`（健康检查）。在 Mac 上先保留回环发布完成登录、上传和下载验收，再用第二台 LAN 设备验证。Docker Desktop 转发可能改变真实 socket peer；不能凭 HTTP `X-Forwarded-For` 恢复可信来源。若 peer 是 NAT 网关，应用无法据其判断原始 LAN 客户端网段，必须由 Mac 宿主防火墙限制允许的 LAN 来源；只绑定 LAN IP 本身不等于来源网段过滤。未完成此项时保留 `127.0.0.1`，不扩大应用白名单掩盖缺口。[Docker Desktop 网络](https://docs.docker.com/desktop/features/networking/)、[端口发布](https://docs.docker.com/engine/network/port-publishing/)说明转发与指定主机 IP 的边界。

## Android Chrome 的独立环境

Redroid 需要受控 Linux 内核及 Binder 等支持，官方示例涉及特权容器；Mac Docker Desktop 能跑普通 Linux 应用不代表其 VM 内核已满足 Android 要求。Redroid 的 amd64/arm64 镜像也不自动解决内核、驱动、Chrome APK、连接前网络防护和下载限额。[Redroid 官方文档](https://github.com/remote-android/redroid-doc)。

Android 环境与本 Compose 分离，见 [Android worker 准备](../../scripts/android-worker/README.md)。当前 `task_worker` 是 API 启动的本地子进程；另有本机 SSH Android worker 适配，但其固定回环地址指的是运行 API 的主机/命名空间，不能直接套用到 Docker 容器并声称已连接宿主 VM。通用跨主机 worker endpoint、网络路径及迁移合同尚需实现和验收。未来接入须有明确任务授权、会话和证据合同、认证、取消/超时、连接前出站防护与硬限额验收。API 容器不获得 Android 特权，也不公开 ADB、CDP 或 Docker socket。

## 验证与迁移

本次可复核的 Linux 验收脚本为 `tests/linux_container_acceptance.py`，使用合成页面、固定工具和字体，在 `--network none` 容器中验证；原包取得、Android 安装运行、完整离线业务和第二台 LAN 设备不属于该验收。具体结果由主项目 `IMPLEMENTATION.md` 或私有验收回执记录，不把配置文件存在当运行成功。

源码迁移只需本目录、`src`、`pyproject.toml`；`.dockerignore` 按允许列表发送构建上下文，不包含 `.runtime`、`.tools`、原始材料、APK、HAR、密钥或本机虚拟环境。命名卷单独备份；不在运行中复制 SQLite 数据库冒充一致性备份。先停止本项目容器或用 SQLite 备份 API，再迁移状态。Mac 验收至少涵盖登录/会话、二维码独立进程、合成采集、超时取消、SDK 签名、重启不重放、字体实际入包，以及真实第二台 LAN 设备的来源限制和下载字节一致性。
