# fxfetch

局域网网址取包工具：粘贴网址或上传二维码图片，解析并下载 APK / IPA；未取得原包时，可手动将网页打包为 Android WebView 应用。

## 功能

- **取包**：优先 APK，确认无 APK 后再尝试 IPA；支持下载候选选择、进度显示和完整性校验。
- **扫码**：支持图片选择、拖入和粘贴，多码由用户选择；输入和识别不访问目标网址。
- **动态页面**：默认 HTTP 采集，必要时使用已配置并通过环境检查的 Android Chrome worker。
- **网页打包**：点击「打包 APK」生成签名应用，可附带已保存的局部离线页面；构建不重新访问目标。

## 部署与启动

完整 Android Chrome 环境见 [Windows Docker 部署](deploy/android-docker/README.md)，需要可用的 KVM 和单独准备的 worker 环境。

仅运行基础 HTTP 服务，需要 Python 3.11+，在项目目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock
.\.venv\Scripts\python.exe -m pip install -e . --no-deps
.\.venv\Scripts\python.exe -m fxfetch init --out .runtime/service
.\.venv\Scripts\python.exe -m fxfetch serve --out .runtime/service --host 127.0.0.1 --port 8765
```

打开 <http://127.0.0.1:8765> 登录。首次 `init` 在终端设置至少 12 位口令，已有配置无需重复初始化。

局域网访问需配置具体私网 IP、允许的客户端子网及防火墙，见 [Windows LAN](deploy/android-docker/WINDOWS_LAN.md)。普通 HTTP 不加密传输。

## 可选：启用 APK 打包

准备 JDK 17、Android SDK Platform 35 和 Build Tools 37.0.0，将以下路径替换为实际安装位置：

```powershell
.\.venv\Scripts\python.exe -m fxfetch init-build --out .runtime/service `
  --sdk "C:\Android\Sdk" `
  --build-tools "C:\Android\Sdk\build-tools\37.0.0" `
  --java-home "$env:JAVA_HOME"
.\.venv\Scripts\python.exe -m fxfetch doctor --out .runtime/service
```

备份服务目录时保留 `.build-private` 和 SQLite 数据库，以保留签名、包名及版本映射。

## 使用须知

- 受阻、失败或解析不完整不代表没有 APK；Chrome 能力以实时环境检查为准。
- 生成的 WebView APK 不是网站原包，局部离线内容不等于完整离线业务；手机安装运行仍未验收。
- 刷新页面会清空当前会话记录并停止未完成任务，后端原始文件保留。
- CLI `fxfetch <url>` 默认只做离线分类；显式使用 `--authorized-active` 才发起采集。

## 文档

- [Android worker](scripts/android-worker/README.md) · [Docker / Mac 部署说明（Mac 未验证）](deploy/docker/README.md)
- [API](API.md) · [实现状态与验收](IMPLEMENTATION.md)
- [开发任务书](TASKBOOK.md) · [选型依据](RESEARCH.md) · [贡献约定](AGENTS.md)

