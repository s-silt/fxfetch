# fxfetch

## 离线交给 fxapk 分析

后台保存的任务 ZIP 可以直接交给离线适配入口；原 APK/IPA 仍单独处理。
fxapk 需在另一个环境按其锁定依赖安装，本项目不安装或导入 fxapk。

```bash
fxfetch prepare-analysis task.zip --out new-analysis
fxfetch analyze-data task.zip --out another-analysis --fxapk /path/to/fxapk
```

`prepare-analysis` 仅校验和整理，不需要安装 fxapk。`analyze-data` 在相同步骤后，通过有时间、内存及日志上限的子进程执行 `fxapk analyze-web --offline --fmt json`；不下载网页、不联网富化、不执行 APK 或网页脚本。`--fxapk` 只能是操作者信任的本地可执行文件路径或 PATH 名称，不是 shell 命令；`--timeout` 默认 300 秒，允许 1–3600 秒。输出目录必须不存在，拒绝覆盖。

浏览器保存的通用 `.body` 文件，在请求、响应和保存事件能明确关联时，按响应 MIME 选择 HTML/JS/JSON 等解析器；DOM 快照单独标注为渲染材料。响应关联或 MIME 冲突时不猜类型，保留缺口并退回内容识别。文件字节不改写；回执保留原文件名、哈希、保存观察序号、响应观察序号及 frame/session/target。MIME 只是解析器选择依据，不证明内容可信，脚本中的静态跳转仍不是实际访问。

输出分开保存：
- `source.zip`：经过校验的原始数据包副本，不修改原包。
- `input/`：正文、DOM 和派生 HAR；只有此目录交给 fxapk，任务清单和来源日志不混入正文扫描。
- `analysis.json`：原包哈希、原 manifest、逐文件及 HAR 条目到原观察序号的映射、跳过原因、采集缺口与分析状态。报告中的 `web/material-NNNN.*` 和 `web/observed.har#/log/entries/N` 可据此回查原件。
- `report/input.json`：fxapk 原生报告；保留其原有哈希旁文件，不重写报告。
- `fxapk.stdout.log` / `fxapk.stderr.log`：有界执行日志。整个目录是私有材料，不能直接公开。

HAR 是适配投影，不是新的浏览器抓包：仅按 collector / attempt / request 标识匹配；无响应的尝试使用状态 0，不把许可等同实际收到响应。不同会话、候选链接、未知关联及 frame 导航不拼成跳转链；未投影观察仍在原 ZIP，索引列出数量。HTTP Location 表示观察到的跳转指向，不表示目标已访问。广告和第三方请求不按域名删除。

输入限制：单文件 8 MiB、总正文及 HAR 80 MiB、最多 2000 文件和 1000 HAR 请求，预算外材料留在原包并明确列出。fxapk 自身的读取缺口保留在报告和回执中。无可分析材料不返回分析成功；fxapk 缺失、失败或超时仍保留整理结果。完整性通过不证明内容真实、来源归属或采集完整，回执覆盖范围始终为 partial，外部 APK/IPA 未由此验证。

本入口只接收 `fxfetch.task-evidence.v1` ZIP，不替代旧 `capture-web` / `export-web` 格式，不修改 fxapk 的 APK 流程，WebView APK 不在这条衔接链内。服务 UI 自动启动分析和真实站点验收不在本入口范围。

## 统一任务与网页材料数据包

服务端每个已执行的普通下载任务只运行现有采集工作流一次，并在任务结束后离线生成独立数据包 ZIP。原 APK / IPA 仍通过原 artifact 接口单独下载；ZIP 只包含明确记录的网页响应材料、有限观察记录和清单，并以外部引用记录原始包的类型、大小、哈希、来源和校验状态，不复制 APK / IPA 字节。失败或没有网页材料的任务也会尽力生成含有结果与缺口的记录。数据包下载不访问目标站点。

`GET /api/jobs/{id}/data-package` 与任务及 artifact 使用相同会话所有权检查。旧任务没有归档时状态为 `unavailable`。离线 `fxfetch verify-data ARCHIVE.zip` 检查 ZIP 结构、清单和列入清单文件的哈希；它不验证外部引用的原始 APK / IPA 字节。数据包保留必要的私有来源 URL 和正文，分享前应按敏感数据处理。

独立的 `capture-web` / `export-web` / `verify-web` 仍保留原有的 `fxfetch.web-evidence.v1` 行为与边界。

`fxfetch capture-web URL --authorized-active --collector http --out NEW_DIR` 只执行一次有界的被动访问。不带 `--authorized-active` 时仅离线分类 HTTP(S) 地址，不创建输出目录；HTTP 模式只执行一次 GET 及受保护的 HTTP 重定向。浏览器模式示例为 `fxfetch capture-web URL --authorized-active --collector browser --service-root .runtime/service --out NEW_DIR`，需要已有的 Android worker 配置，绝不会静默回退到 HTTP。两种模式都不会跟随链接、点击、扫描二维码后继续请求或声称覆盖整个站点。

`fxfetch export-web CAPTURE_DIR --out NEW_BUNDLE_DIR` 与 `fxfetch verify-web BUNDLE_DIR` 都是离线目录操作。该 v1 证据包保留私有 URL 查询参数和响应内容，不会匿名化；哈希只提供完整性校验，不证明真实性。统一任务的独立 ZIP 使用 `fxfetch.task-evidence.v1`，只从已观察到的明确路径构建，不会重放采集。

### 模块边界

- `web_capture` 负责授权后的输出目录、采集生命周期、日志收尾和摘要保存；`web_http` 负责有界 HTTP 访问，`web_browser` 负责既有 Android worker / browser gateway 生命周期。
- `web_materials` 投影并校验已保存材料；`browser_web_evidence` 只整理浏览器观测，不发送 CDP 命令、不管理预算或权限。
- `task_evidence_recorder` 记录任务内实际观察；`task_evidence_io` 负责受限 ZIP 构建和离线验证；`task_evidence` 管理归档元数据与状态。统一任务归档不改变原下载结果。
- `web_evidence` 仅编排离线导出与验证；`web_evidence_schema`、`web_evidence_io`、`web_provenance` 分别负责纯 schema 校验、安全文件操作和日志/材料溯源校验。

局域网网址取包工具：粘贴网址或上传二维码图片，解析并下载 APK / IPA；未取得原包时，可手动将网页打包为 Android WebView 应用。

### 网页材料的结果口径

- `captured` 仅表示取得本次访问的材料，不表示采全网站；跳转正文、脚本或交互未覆盖时会列入 `gaps`。
- HTTP 收到安装包、ZIP 或通用二进制响应时，保留已接收的有界材料，但标记 `unsupported_download_response`，不当作网页采集成功。
- 访问控制页即使正文被截断，仍保留 `blocked` 和正文缺口；来源日志写入失败不能报告采集成功。日志截断时 CLI 返回非零退出码，材料仍可离线导出并保留不完整说明。
- `export-web` / `verify-web` 输出原采集结果、覆盖范围及缺口。校验通过只表示材料包满足校验规则，不把原来的 `blocked` / `failed` 改为成功，也不证明网站内容真实。

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
