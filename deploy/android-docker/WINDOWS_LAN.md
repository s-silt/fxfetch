# Windows Docker 局域网入口

默认仅发布 `127.0.0.1:18765`。完成 Android 合成下载、隔离及清理验收后再开放 LAN；第二台设备的登录下载必须单独测试。

## 1. 准备发布配置

先完成 [worker 部署](README.md)。私有 Compose 覆盖文件须满足：

- `android-worker` **仅发布** `LAN_IP:8765:8765/tcp`；API 设置同一 `FXFETCH_PUBLIC_IP` 与 `FXFETCH_PORT=8765`，容器仍绑定 `172.30.247.2`。
- 内外端口同号，以匹配 Host/Origin；不能仅把宿主 8765 映射到容器 18765。
- 通过 `docker compose ... config --format json` 确认覆盖后只有一个端口，未合并保留默认条目。
- 禁止 `0.0.0.0`、`::`、宿主网络；不发布 SSH 12222、CDP 19222 或守卫 18767。
- `FXFETCH_TRUSTED_PEERS` 只保留已核验 Docker 网关，不扩大为全部私网。

## 2. 配置主机防火墙

替换以下示例 IP 和网段。预览与只读核验可用普通 PowerShell；创建缺失规则才需要管理员：

```powershell
& .\scripts\configure-docker-lan.ps1 -LanIP 192.168.50.10 -Subnet 192.168.50.0/24 -Port 8765 -PythonPath .\.venv\Scripts\python.exe -WhatIf
& .\scripts\configure-docker-lan.ps1 -LanIP 192.168.50.10 -Subnet 192.168.50.0/24 -Port 8765 -PythonPath .\.venv\Scripts\python.exe
& .\scripts\configure-docker-lan.ps1 -LanIP 192.168.50.10 -Subnet 192.168.50.0/24 -Port 8765 -PythonPath .\.venv\Scripts\python.exe -VerifyOnly
```

本机须有该地址，三个 Windows 防火墙配置文件全部启用。脚本仅管理 `fxfetch-Docker-LAN-<port>-<ip>` 下的两条规则：先阻止允许网段的 IPv4 补集，再允许指定网段。`Program=Any` 覆盖 Docker 转发，仍限定单 IP/端口；旧 Python 专用规则不能替代。

同名规则一致则不写，冲突则停止；创建后复核 ActiveStore。不会修改全局策略、其他应用、路由器、UPnP 或建立 IPv6 入口。

## 3. 启动

```powershell
& .\scripts\start-android-docker.ps1 -EnvFile .\.runtime\docker-worker\compose.env
```

构建资源与 LAN 覆盖文件通过 `-OverrideFile` 依次传入，LAN 模式还须提供 `-LanSubnet`。启动器仅执行防火墙 `-VerifyOnly`；缺规则或冲突即停止。

启动器核对单一发布端口、Host/Origin、固定本地镜像和服务名；给 Linux engine 90 秒恢复时间。仅在固定 `docker-desktop` 中缺少 KVM 时，按 CPU 厂商加载已有模块；不安装模块、改内核/全局 WSL 配置或退回软件模拟。

Compose 使用 `--no-build --pull never --no-recreate --wait --wait-timeout 300`。不下载、重建或替换正在运行的容器；配置不一致时另做空闲切换，失败不自动清理已有容器。

## 4. 验证

核对实际 PortBindings、Windows 监听、镜像 ID、API Origin、匿名请求拒绝和错误 Host 拒绝，再从第二台 LAN 设备完成登录及下载字节校验。

启动器输出 `android_download_verified=false`：启动成功不等于 Chrome 下载验收。Docker NAT 可能将所有客户端变成网关 peer，API 不信任转发头，来源限制依靠转发前的宿主防火墙。保持无路由器公网映射；上游 NAT 若改写为允许的 LAN 来源，应用无法恢复原始来源。
