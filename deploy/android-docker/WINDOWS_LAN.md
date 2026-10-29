# Windows Docker 的局域网入口

默认 Compose 仅发布 `127.0.0.1:18765`。只有 Android 合成下载、会话清理和隔离验收通过后，才切换为局域网入口。本文不是已通过第二台设备验收的声明。

## 有界启动入口

准备好本地镜像、独立磁盘和私有环境文件后，可使用专用启动脚本：

```powershell
& .\scripts\start-android-docker.ps1 -EnvFile .\.runtime\docker-worker\compose.env
```

已审阅的构建资源和 LAN 覆盖文件通过 `-OverrideFile` 依次传入；LAN 发布还必须提供 `-LanSubnet`。已配置防火墙时，普通用户可执行启动和只读验证，无需管理员窗口。启动器先核对最终 Compose 模型的唯一 IPv4 发布端口、API Host/Origin、固定本地镜像与服务名称。LAN 模式只调用防火墙脚本的 `-VerifyOnly`，缺规则或冲突时停止，不自动创建或扩大规则。

启动器给 Docker Linux engine 共计 90 秒恢复时间。仅当固定 `docker-desktop` WSL 发行版中没有 `/dev/kvm` 时，按其中确认的 Intel/AMD CPU 厂商加载现有 `kvm_intel`/`kvm_amd` 模块；模块不可用则停止，不下载模块、不修改内核/全局 WSL 配置、不回退软件模拟。worker 容器入口还会执行真实 KVM vCPU 探针，设备文件存在本身不足以放行。

Compose 启动使用 `--no-build --pull never --no-recreate --wait --wait-timeout 300`。不会自动构建或下载镜像、安装浏览器、启动旧 VirtualBox VM，也不会替换正在运行的容器。完成后核对实际发布端口、镜像 ID 和 API Origin；若现有容器与配置不同，停止并提示另做空闲切换，而不是自动重建。失败不会自动删除已启动的容器，以免干扰已有任务。

容器健康仅表示服务可用；脚本明确输出 `android_download_verified=false`，不把启动完成当作已完成 Chrome 下载验收。脚本的策略与超时行为使用 mock 测试；真实环境启动验收必须另记收据。

## 主机防火墙

专用脚本的预览、`-VerifyOnly` 和匹配已有规则的核对可使用普通 PowerShell；只有创建缺失规则才要求管理员权限，权限检查在第一次写入之前执行。以下地址仅为部署示例，应替换为本机实际的 RFC1918 IPv4 地址及其局域网网段：

```powershell
& .\scripts\configure-docker-lan.ps1 -LanIP 192.168.50.10 -Subnet 192.168.50.0/24 -Port 8765 -PythonPath .\.venv\Scripts\python.exe -WhatIf
& .\scripts\configure-docker-lan.ps1 -LanIP 192.168.50.10 -Subnet 192.168.50.0/24 -Port 8765 -PythonPath .\.venv\Scripts\python.exe
& .\scripts\configure-docker-lan.ps1 -LanIP 192.168.50.10 -Subnet 192.168.50.0/24 -Port 8765 -PythonPath .\.venv\Scripts\python.exe -VerifyOnly
```

脚本只管理 `fxfetch-Docker-LAN-<port>-<ip>` 下的两条规则：先为所选 IPv4 地址和 TCP 端口阻止允许网段的精确 IPv4 补集，再允许该网段。`Program=Any` 用于覆盖 Docker Desktop 的端口转发进程；规则仍严格限定到单个本地地址和端口。旧的 Python 程序专用规则不能替代这两条 Docker 规则。

本机必须已经配置所选地址，三个 Windows 防火墙配置文件必须全部启用。已有同名规则会逐项核对；完全一致时不写入，有冲突时停止，不覆盖。只存在匹配的阻止规则时可以安全补充允许规则。创建后重新检查 ActiveStore；未生效时应停止发布。脚本不修改全局防火墙策略、其他应用规则、路由器或 UPnP，也不建立 IPv6 入口。

## Compose 发布

私有部署覆盖文件应让 `android-worker` **只发布** `LAN_IP:8765:8765/tcp`，同时把 API 的 `FXFETCH_PUBLIC_IP` 设置为同一个 LAN_IP、`FXFETCH_PORT` 设置为 `8765`。容器仍绑定 `172.30.247.2`，API 与 worker 仍共享网络命名空间。

容器入口当前共用同一个端口值生成监听地址和 HTTP Host/Origin 白名单。因此不能只把宿主 8765 映射到容器 18765。覆盖时也不能意外合并保留默认的回环发布条目。先运行 `docker compose ... config --format json`，核对最终模型仅有一个发布端口，再启动。不得发布 12222（SSH）、19222（CDP）、18767（连接守卫），不得使用 `0.0.0.0`、`::` 或宿主网络模式。

`FXFETCH_TRUSTED_PEERS` 仍只包含已核验的 Docker 网关地址；不要把它改成全部私网以“修复”访问。上线核验包括实际容器 PortBindings、Windows 监听地址、未登录接口拒绝、正确 Host/Origin 和错误 Host 拒绝。第二台局域网设备的登录与下载需要独立测试，本机回环或本机访问自己的 LAN 地址不能代替。

## 能确认的边界

Docker NAT 可能将所有客户端转换成同一个网关地址，因此 API 的 socket-peer 检查不能单独判断原始客户端是否来自局域网。Windows 入站防火墙在转发前限制可见源地址，API 不信任转发头。主机只发布局域网 IPv4、外网源地址被上述补集规则拒绝；但如果上游路由器主动把公网连接转发并转换为允许的 LAN 源地址，服务无法恢复那个原始来源。不得据此宣称抵御所有上游 NAT/转发配置；部署时应保持没有该端口的路由器公网映射。

本机规则的配置验证与跨设备网络测试是两件事。日志及验收收据应分别记录，不能凭 Compose healthy 或规则存在就宣称局域网下载成功。
