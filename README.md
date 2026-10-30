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
- `native-report/input.json`：私有保存的 fxapk 原稿，不进入下载报告。
- `report/input.json`：发布用报告；只有能回查已保存源码中的具体完整值与位置的密钥线索才保留，纯启发式提示及重复摘要移除。保留的静态线索也不代表凭据有效或解密成功，过滤计数与新哈希在 `analysis.json` 中记录。
- `fxapk.stdout.log` / `fxapk.stderr.log`：有界执行日志。整个目录是私有材料，不能直接公开。

HAR 是适配投影，不是新的浏览器抓包：仅按 collector / attempt / request 标识匹配；无响应的尝试使用状态 0，不把许可等同实际收到响应。不同会话、候选链接、未知关联及 frame 导航不拼成跳转链；未投影观察仍在原 ZIP，索引列出数量。HTTP Location 表示观察到的跳转指向，不表示目标已访问。广告和第三方请求不按域名删除。

输入限制：单文件 8 MiB、总正文及 HAR 80 MiB、最多 2000 文件和 1000 HAR 请求，预算外材料留在原包并明确列出。fxapk 自身的读取缺口保留在报告和回执中。无可分析材料不返回分析成功；fxapk 缺失、失败或超时仍保留整理结果。完整性通过不证明内容真实、来源归属或采集完整，回执覆盖范围始终为 partial，外部 APK/IPA 未由此验证。

本入口接收 `fxfetch.task-evidence.v1` / `v2` ZIP，不替代旧 `capture-web` / `export-web` 格式，不修改 fxapk 的 APK 流程，WebView APK 不在这条衔接链内。

### 网页端手动离线分析

后端需先独立安装 fxapk，再在原有 `serve` 命令追加 `--fxapk`，例如 Windows：

```powershell
.\.venv\Scripts\python.exe -m fxfetch serve --out .runtime/service --fxapk "C:\Tools\fxapk\Scripts\fxapk.exe"
```

也可在服务根的 `server.json` 配置 `fxapk_executable`。默认未启用；网页不能指定可执行文件、参数或材料路径，能力检查只确认程序可解析，不证明已实测可用，也不自动安装。

上述 `serve` / `server.json` 配置用于直接运行 Python 服务；Docker 入口不读取宿主配置。容器部署使用 `FXFETCH_FXAPK` 指定预置的 Linux 程序绝对路径，见 [Docker 离线分析部署](deploy/docker/README.md#可选网页离线分析)。

数据包就绪后，点击「离线分析数据包」启动独立后台任务。页面加载、轮询和下载不会启动分析；失败、取消或重启后不自动重跑。原采集的 blocked/failed 结论不因分析完成而改变。支持取消；刷新清空取消本会话未完成分析并隐藏历史，后台文件保留，其他会话不受影响。

报告 ZIP 与 APK/IPA、原始数据包分开下载，仅包含经过证据筛选的 JSON 报告及来源回执，不包含原始数据包、安装包、执行命令和执行日志。回查原件需同时保存原始数据包；原生报告也可能含敏感线索及 fxapk 记录的主机材料目录，下载前注意保密。页面不渲染目标 HTML 或报告正文。

提交时只检查任务归属和归档就绪元数据，固定该归档的路径、大小与哈希；完整 ZIP 校验、材料准备和报告整理都在可取消的受限后台进程执行。归档内容损坏或与已保存摘要不符会令分析失败，不会发布报告。

分析串行执行：最多 10 个排队任务，每个采集任务最多 10 次分析、同时最多一次；排队上限 600 秒，执行总期限默认 360 秒（含材料准备），内存限制 2 GiB。时间和内存限制不是操作系统断网沙箱；离线性依赖明确传入 fxapk 的 `--offline` 契约。真实站点、Android worker 与 NAS/Docker 需另行验收。

## 统一任务与网页材料数据包

服务端每个已执行的普通下载任务只运行现有采集工作流一次，并在任务结束后离线生成独立数据包 ZIP。原 APK / IPA 仍可单独下载；v2 ZIP 的 `attachments/` 同时包含已完整接收的原包与实际保存的 TLS DER 证书，清单记录类型、大小、SHA-256、来源、请求关联及校验状态。完整但校验失败的原包保留失败提示，不作为成功 artifact。附件不进入网页正文扫描。失败或没有网页材料的任务也会尽力生成含有结果与缺口的记录。数据包下载不访问目标站点。

`GET /api/jobs/{id}/data-package` 与任务及 artifact 使用相同会话所有权检查。旧任务没有归档时状态为 `unavailable`。离线 `fxfetch verify-data ARCHIVE.zip` 检查 ZIP 结构、清单和列入清单文件的哈希；它验证 ZIP 内原件字节的完整性，但不重新进行 APK 结构、签名或安全性验证；未嵌入的外部原包仍未验证。HTTP 证书保存同一次实际连接的 leaf DER，并区分已验证与证书错误后继续的未验证连接。Chrome 被动读取本次隔离会话中 TLS 网络事件的证书原件，并尽力读取站点证书快照。分别标明浏览器网络事件范围与 origin 快照范围，保留原链序号；无法确认请求关联时不填目标 URL、不伪称逐连接证据。跟踪限额处理，不导出原始网络日志、不新增目标请求。合法链成员可以部分保存，未取得、超时和缺链均显示提示。仅有指纹的历史 TLS 证书无法还原。数据包保留必要的私有来源 URL 和正文，分享前应按敏感数据处理。

独立的 `capture-web` / `export-web` / `verify-web` 仍保留原有的 `fxfetch.web-evidence.v1` 行为与边界。

`fxfetch capture-web URL --authorized-active --collector http --out NEW_DIR` 只执行一次有界的被动访问。不带 `--authorized-active` 时仅离线分类 HTTP(S) 地址，不创建输出目录；HTTP 模式只执行一次 GET 及受保护的 HTTP 重定向。浏览器模式示例为 `fxfetch capture-web URL --authorized-active --collector browser --service-root .runtime/service --out NEW_DIR`，需要已有的 Android worker 配置，绝不会静默回退到 HTTP。两种模式都不会跟随链接、点击、扫描二维码后继续请求或声称覆盖整个站点。

`fxfetch export-web CAPTURE_DIR --out NEW_BUNDLE_DIR` 与 `fxfetch verify-web BUNDLE_DIR` 都是离线目录操作。该 v1 证据包保留私有 URL 查询参数和响应内容，不会匿名化；哈希只提供完整性校验，不证明真实性。统一任务的独立 ZIP 使用 `fxfetch.task-evidence.v2`（兼容读取 v1），只从已观察到的明确路径构建，不会重放采集。

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

新网页任务默认“先校验，仅证书错误时继续”，也可选“严格校验，证书错误时停止”。HTTP 每个连接先严格验证，仅 `SSLCertVerificationError` 允许向同一已验证公网 IP 重握手一次，原 HTTP 请求不会因此重放；Chrome 保持严格验证，只针对已允许请求产生的真实证书错误事件有界继续。超时、一般握手失败及地址检查错误不放行。任务策略与实际降级分别记录，正常证书不会显示“已忽略”风险。发生降级时，错误、风险、证书原件或获取缺口随数据包保留；完整包结构不代表来源可信。公网防护、预算和包校验保持生效，不改变系统信任、当前设备直接下载或生成 APK 的 TLS 设置。核心与 CLI 默认严格。Chrome 的逐事件继续仅处理可确认归属的顶层页面请求；无法可靠关联的嵌入页面证书错误保留失败或缺口，不猜测关联。

DNS 默认使用 AliDNS（223.5.5.5），仅传输或服务失败时尝试 DNSPod（119.29.29.29）。解析中的非公网/特殊地址记录为 `dns_unsafe_answer`，不会丢弃异常 AAAA 后连接 A，也不会用备用服务绕过安全拒绝；解析服务自己的 HTTPS 证书始终严格验证。连接地址须匹配所查询名称及其有效 CNAME 链，不能采用响应中的无关地址。HTTP 和 Android Chrome 采集的数据包会保留有界 DNS 诊断：服务商、查询类型、响应码、解析记录与拒绝原因；超限明确标记省略。保存的是解析记录和响应摘要，不声称保存 DNS 响应原件。旧任务没有记录的 DNS 答案不能事后还原。网页仅显示简短原因，正常关闭浏览器不会再记为公网拒绝；解析失败、连接失败、传输中断和预算耗尽分别显示。地址检查通过也不代表地址归属可信或必有 APK。

- 受阻、失败或解析不完整不代表没有 APK；Chrome 能力以实时环境检查为准。
- 生成的 WebView APK 不是网站原包，局部离线内容不等于完整离线业务；手机安装运行仍未验收。
- 刷新页面会清空当前会话记录并停止未完成任务，后端原始文件保留。
- CLI `fxfetch <url>` 默认只做离线分类；显式使用 `--authorized-active` 才发起采集。

## 文档

- [Android worker](scripts/android-worker/README.md) · [Docker / Mac 部署说明（Mac 未验证）](deploy/docker/README.md)
- [API](API.md) · [实现状态与验收](IMPLEMENTATION.md)
- [开发任务书](TASKBOOK.md) · [选型依据](RESEARCH.md) · [贡献约定](AGENTS.md)


网页主入口优先展示网址、图片和开始采集；证书策略在默认折叠的“高级设置”中，默认为先验证、仅证书错误时继续。通用链接识别支持明确的 Get APK/Get Android app 标签、直接导航包地址及有界内嵌 JSON 下载字段。多包仍由操作者选择；JSON 超限或截断记为覆盖缺口，不猜接口或扩展任意 XHR。公网地址检查失败不能解释成没有 APK，证书策略也不会放宽地址检查。
