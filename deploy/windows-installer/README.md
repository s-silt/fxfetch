# Windows 离线安装

安装目标为 Windows 11 x64、Intel/AMD、硬件虚拟化开启的独立电脑，建议 16 GB 内存及至少 60 GiB 可用空间。安装器使用 Windows 自带 .NET Framework 界面、随包 Python 运行时、Docker Desktop / WSL 离线安装文件、本地容器镜像和干净 Ubuntu 软件模板。采集网站时仍需要网络。

## 使用

1. 将完整离线包复制到新电脑并解压。不要只复制 EXE。
2. 双击 `fxfetch-setup.exe`，允许 Windows 管理员授权。选择独立安装目录、本机局域网 IPv4 和允许访问的网段。
3. 选择预设口令，或设置至少 12 位的自定义口令；阅读 Docker Desktop 订阅协议及所附第三方许可后勾选接受。
4. 点击“开始安装 / 继续安装”。需要重启时会停止并明确提示，不强制重启。保存工作、手动重启后，运行桌面的 `fxfetch Setup` 续装快捷方式，或安装目录中的 `fxfetch-setup.exe`；也可再次运行原安装包并选择同一目录继续。自定义口令不会落盘，续装时须重新输入。
5. 安装成功后自动打开网页，并创建当前用户的桌面快捷方式。以后使用快捷方式或安装目录的 `fxfetch.exe` 启动。局域网设备使用安装完成时显示的地址访问；地址变化时需要重新配置局域网规则，不能直接绑定所有网卡。

安装包不包含旧电脑的任务数据库、原包、TLS 材料、浏览历史或签名密钥。预设口令仅以哈希保存在私人安装包的 `defaults.json`，不得加入公开源码仓库；两个实例各自保存任务、生成签名和 SSH 控制身份。

新安装保留 APK 打包、图片扫码、Android Chrome 和 fxapk 离线分析；API 镜像必须已经包含完整工具，缺少离线分析可执行文件时安装不会声称全部功能就绪。DNS 顺序沿用本次已验证部署的 `cloudflare,google`，管理员可在私有 `runtime.env` 中修改为允许的服务商；公网检查和默认严格校验证书后有界续行策略保持生效。本版支持新安装及同一安装包续装，不自动覆盖不同版本的已有部署。

首次安装包含 Android 初始化和逐机验收，耗时明显长于以后的启动；窗口会显示镜像导入、浏览器初始化、下载、隔离和超时检查等阶段。正常启动后会再次检查实际 Chrome 和打包能力，只有网页能响应但 Android 未就绪时不会报告安装成功。

## 离线范围与限制

安装过程不下载 Docker、WSL、容器镜像、Android 浏览器、SDK、字体或 Ubuntu 组件。WSL MSI、Docker EXE 的发布者签名必须验证；全部随包文件校验通过后才执行安装。Windows 系统组件通过 DISM `/LimitAccess` 启用，如果本机组件源损坏或缺失，明确失败并要求修复系统，不偷偷联网下载。硬件虚拟化关闭时需要在 BIOS/UEFI 启用；程序不会修改固件设置。

第一次配置 WSL/虚拟机平台可能需要重启。安装器需要用户接受 Docker 协议；Docker Desktop 的使用仍须符合其订阅条件，安装器不替用户判断授权资格。参考 [Docker Windows 安装说明](https://docs.docker.com/desktop/setup/install/windows-install/)、[Docker 订阅协议](https://www.docker.com/legal/docker-subscription-service-agreement/) 和 [Microsoft WSL 离线安装说明](https://learn.microsoft.com/en-us/windows/wsl/install#offline-install)。

KVM vCPU、Android 隔离、合成下载、取消及期限测试必须在每台新机器通过后，才发布正常服务。Docker 显示 healthy 不能替代这些检查。不轮换浏览器指纹、不安装目标 APK，也不自动访问曾经提交的网址。

LAN 仅发布所选私有 IPv4 的 8765 端口，宿主防火墙限制到明确子网；不开放 SSH/CDP/守卫端口，不创建路由器公网映射。不同电脑使用独立命名卷；同一电脑若已有其他 fxfetch 部署，安装器拒绝覆盖。第二台设备的访问、登录与下载字节验证仍需要在实际局域网完成。

配置和结构化进度固定 UTF-8；兼容 UTF-8 BOM，支持中文路径和空格，不修改系统代码页。安装中断保留原始诊断和安装目录；不自动清空旧数据，不在恢复时重做采集任务。

## 从源码构建

运行 `scripts/windows-installer/build.ps1 -OutputDirectory <构建目录>` 生成安装器和启动器。编译使用系统 .NET Framework C# 编译器，不需要 Node/Electron。由 `build_bundle.py` 组装已经验证的离线组件；该脚本不下载组件，不读取现有任务卷。

干净 Android 软件模板必须由 `provision_guest.prepare_template` 从固定官方 Ubuntu 源建立，封存前移除构建 SSH 身份、机器标识及 cloud-init 日志。不能将正在运行的磁盘或已有业务 worker 当作模板。新机器从模板建立独立身份，离线安装预置 Chrome，再执行本机合成验收。模板制作阶段的网络依赖与最终用户的离线安装阶段分开记录。

当前实际验收与尚未验证的平台范围，以项目 IMPLEMENTATION 最新安装章节为准；不要把脚本存在或安装包已组装写成另一台电脑已安装成功。
