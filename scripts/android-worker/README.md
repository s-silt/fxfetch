# Android worker 准备

本目录准备独立 Ubuntu / Redroid / Android Chrome 环境与受控会话。当前 Windows 运行入口为 [Docker QEMU/KVM 部署](../../deploy/android-docker/README.md)；下面 VirtualBox 命令仅用于原始环境准备，不是当前 Docker 启动步骤。

## 环境与私有文件

原环境：VirtualBox 7.2.16、Ubuntu 24.04（20261017 官方云镜像）、2 CPU / 4 GiB、16 GiB 独立磁盘、Binder、Redroid Android 14 amd64。Redroid 固定为：

`sha256:11d58a64bfbde2253d1cce81bff409ff58174980222d1bada232d9ef59181191`

Android /data 使用独立 2 GiB ext4 卷。VM 不共享文件夹、USB、剪贴板、拖放或远程桌面。身份、SSH key、known_hosts、磁盘、Chrome 资产、已验收 baseline 与收据只保存在私有 `.runtime/`，不随源码发布。

新机器必须重新准备与验收，不能复制旧状态或摘要冒充环境就绪；当前健康以能力与任务检查为准。

## 原始 VM 准备

从仓库根目录使用项目 Python 环境：

```powershell
.venv\Scripts\python.exe scripts\android-worker\prepare_vm.py status
.venv\Scripts\python.exe scripts\android-worker\prepare_vm.py download
.venv\Scripts\python.exe scripts\android-worker\prepare_vm.py prepare
.venv\Scripts\python.exe scripts\android-worker\prepare_vm.py start
```

下载使用 HTTPS、校验固定发行摘要、失败保留部分文件且不自动重试。prepare 拒绝已存在的 VM 名称/目录，生成专用 SSH key 和 NoCloud ISO；私钥 ACL 限操作者。start 使用 headless VirtualBox，不安装 Windows 服务。

复制 `guest_environment.py` 到专用 VM 后运行 `sudo python3 guest_environment.py prepare`。仅做基础设施测试时使用 `start-offline`：先安装 deny 规则，再启动 Android，并安排 600 秒独立停止。`stop` 停止指定容器且保留 deny 规则。

## Chrome 资产

验收使用固定 Chrome/Trichrome **145.0.7632.218**（version code **763221838**），不称为当前最新稳定版。原 API34 `download-chrome-image` 得到 Chrome 113，不能用于当前浏览器准备。

```powershell
.venv\Scripts\python.exe scripts\android-worker\download_api37.py
.venv\Scripts\python.exe scripts\android-worker\extract_api37.py
```

工具下载固定官方 API37 r08 归档，再离线提取 system/product 镜像到 `.runtime/android-worker/downloads/`。已有输出须匹配大小与摘要；解包另需至少 9 GiB 空间。下载按 64 MiB 范围请求，失败退出；复核后用 `--resume` 续传，最终仍校验整个文件。

工具不挂载镜像、不提取/安装 APK、不启动 Android，也不启用采集。随后通过受控本地工具完成浏览器提取、签名检查和安装，建立并验证新 baseline；不使用第三方 Chrome 镜像或运行任意 APK。

| 资产 | SHA-256 |
| --- | --- |
| Chrome | `e19853ab32bb80fb99e5aa4fa511e75193c690cf2f37922a3e9eb5894e03b6dc` |
| Trichrome | `5266ae77797dc67fd77394e96de2e3e8ad124c58e21cfff91ee46d040680041c` |

## 控制与网络边界

| 端点 | 原始 Windows VM 路线 |
| --- | --- |
| SSH | 主机 `127.0.0.1:12222` |
| ADB | guest `127.0.0.1:15600`，不向主机/LAN 映射 |
| CDP | 主机 `127.0.0.1:19222` 经 SSH 到 guest `127.0.0.1:9222` |
| 唯一数据出口 | 主机守卫 `127.0.0.1:18767`，guest 经 `10.0.2.2:18767` 到达 |

Android namespace 禁止其他 TCP/UDP/IPv6、私网、宿主和直接 DNS 出站；Docker DNS 委派另行做泄漏测试。浏览器代理参数本身不是隔离边界，守卫直连目标而不接上游代理。

固定 begin/status/end、状态锁、lease 专属 staging、每任务数据恢复、不可变容器 ID 清理及 guest 原生期限共同控制会话。实时证明核对 helper/environment、Chrome/Trichrome 安装摘要及静态库版本/路径。目标 URL 只作为结构化数据，不能进入 shell。

## 放行验收

启用 API Android 能力前，逐项验证：

1. 浏览器身份、CDP、同会话 Cookie/一次性票据和原响应下载到 API 附件。
2. 内层 8 项与外层 INPUT/FORWARD 阻断、允许 broker 路径、后台连接和 DNS 隔离。
3. 实际 /data 为 2,147,483,648 字节，写满返回 ENOSPC，清理测试文件。
4. 取消后启动不同 lease/容器；guest 原生期限独立到期，拒绝旧证明并关闭隧道/守卫。

这些合成场景已有历史通过记录，见 [IMPLEMENTATION.md](../../IMPLEMENTATION.md)；不是新机器验收，也不代表手机安装或真实网站通过率。about:blank、可读 CDP、配置存在和缓存能力均不足以放行。

## 停止与恢复

```powershell
.venv\Scripts\python.exe scripts\android-worker\prepare_vm.py stop
```

仅向登记 VM 发 ACPI。注销前核 UUID/配置路径并确认已停止，使用精确 UUID 且不加 `--delete`；不执行全局 VM/WSL/Docker/nftables 清理。

`guest_session.py recover-idle` 只接受 `{"lease_id":"00000000000000000000000000000000"}`，拒绝活动 lease，仅清理本项目过期容器并恢复挂载/deny 规则，不启动 Android。`resume_worker.py` 另核 VM UUID、名称与配置路径。活动 lease 期间不并发运行恢复、bootstrap 或验收。

Mac 的 API 与特权 Android 环境须分离，重验内核、架构、Chrome、网络及控制合同；不向 API 暴露 Docker socket、ADB、CDP 或案件目录。

参考：[Ubuntu 镜像](https://cloud-images.ubuntu.com/noble/20261017/)、[Google SDK 元数据](https://dl.google.com/android/repository/sys-img/google_apis/sys-img2-3.xml)、[Redroid](https://github.com/remote-android/redroid-doc)、[NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html)。本项目未引入 Damru、Mobilebridge 或模拟器农场源码。
