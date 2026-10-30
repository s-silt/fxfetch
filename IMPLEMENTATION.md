# 实现状态与验收

## 校验失败原文件下载（2026-10-30）

- 任务增加独立 `rejected_files` 列表及只读附件接口。完整保存但归档校验失败的 APK/IPA 可以下载原字节，保留 `failed`、错误原因及原哈希，不进入成功 `artifacts`，也不影响已有网页打包入口。
- 兼容可严格关联的旧 HTTP 完整失败记录；新 Chrome 完整失败流补充完整性及校验元数据。旧 Chrome 缺乏完整传输证明的文件、截断、取消、超时及普通网页不开放下载。列表只做轻量检查，下载前重新核对文件大小、SHA-256、当前任务目录边界及链接类型，并通过已打开的文件流返回。
- 网页将“下载原文件（校验失败）”与“打包 APK”放在任务结果附近、进度记录之前。打包仍需单独点击，生成包与失败原文件分别展示；刷新清空记录规则保持不变。
- Windows 全量 **1118 passed、10 skipped、0 failed**；Ruff、Pyright 通过。跳过为平台或符号链接权限条件，Linux 断网、非 root 容器的相关 **33 项全部通过**，包含真实符号链接拒绝。保留既有依赖弃用提示。
- 本机真实 Chrome 与本地 API 验证失败原文件下载字节/哈希一致、原状态不变、点击前零构建请求、点击后一次构建、两个下载入口独立。桌面与 375px 窄屏前后四张截图检查通过；本轮界面测试使用合成构建器，不代表重新验收真实 SDK 构建或手机安装。
- Docker API 已更新，84 个源码文件及入口与本地一致，Android worker 未重建；5 项口令及签名等私有配置摘要不变。旧任务原文件经实际 HTTP 接口下载 79,725,136 字节并核对哈希，任务数据库行不变、校验失败保留；未重新访问目标。匿名、Host、静态资产及能力检查通过。

## 最新本机合并验收（2026-10-30）

- 三方合并上游 `386419ca26cf547e5d78bf2c0c5df3299d584330` 的 11 个文件，保留本机二维码、脚本文件链接、数据包及分析轮询修复。入口、测试和验收文档冲突已逐项整理；未提交或推送。
- 容器分析配置统一为上游 `FXFETCH_FXAPK`，只接受容器内绝对 Linux 路径，空值关闭分析，不读取宿主 `server.json`。本机可选分析镜像、Compose overlay 和已有部署配置同步迁移；旧 `FXFETCH_FXAPK_EXECUTABLE` 不再用于容器启动。
- 合并后 Windows 全量 **1086 passed、9 skipped、0 failed**；容器配置及真实 fxapk API 定向 **28 passed**。Ruff 与 Pyright 包含 Docker 入口并通过；跳过项为 Linux/POSIX 行为及 Windows 目录符号链接权限，保留既有依赖弃用提示。
- Linux 断网、非 root、只读根、无 capabilities 的容器检查 **40 passed、4 skipped**，包含真实 fxapk CLI/service/API。四项跳过是容器缺少 Compose CLI，已在 Windows 主机通过。未改依赖版本。
- Docker API 已切换到合并版本，83 个源码文件及容器入口与本地一致。Android worker 未重建，口令及签名等 5 项私有文件摘要不变；认证拒绝、Host 拒绝、静态资产和 Chrome 能力检查通过。实际 HTTP API 的合成离线分析、报告 ZIP 下载及原采集状态保持检查通过。
- 合并前已用授权网址验证本轮采集代码：原入口自动解析到内联脚本中的文件地址，约 12 秒收齐文件，全程 HTTP，无 Android Chrome。目标文件自身存在归档/签名异常，仍记录校验失败，未冒充取得有效 APK；合并未更改这部分采集代码。真实材料与独立复核收据只保存在私有运行目录，不随源码交付。

## 二维码覆盖与动态接续修复（2026-10-30）

- 页面图片先按 URL 或内嵌内容摘要去重，再优先扫描带明确二维码提示的图片；重复图片不会消耗额外名额。每页最多扫描 8 张，未扫描内容仍记录覆盖缺口，不能据此认定没有 APK。
- 仅当页面已确认需要浏览器、二维码缺口属于图片数量上限或图片来源未就绪时，允许接续一次 Android Chrome。保留原 HTTP 部分覆盖记录并共享剩余时间、请求和存储预算；解码、安全检查及预算失败不会借此重试。明确 APK 地址仍优先走 HTTP。
- HTML 8 MiB 硬上限约束所有内嵌 base64 的总解码量；图片发现阶段不解压像素。补充去重、后置二维码优先、动态接续、原包优先、原始记录保留及预算边界回归。
- 新增有界的内联脚本文件地址提取：完整 APK/IPA URL 字面量声明，且变量只用于明确的 location 导航赋值时，进入已有 HTTP 候选流程。不执行脚本，不解析动态拼接，不提取注释、字符串或正则里的伪代码；多个 APK 保留选择，APK 优先于 IPA 和扫码。
- 二维码阶段全量 **1042 passed、9 skipped、0 failed**；追加脚本提取后的最终全量 **1072 passed、9 skipped、0 failed**，另两项正则字面量回归单独通过。Ruff 与 Pyright 通过。跳过项为 Linux/POSIX 专用检查及 Windows 目录符号链接权限检查；保留既有 Starlette/httpx 弃用提示。
- Docker API 已更新，83 个源码文件与本地一致；Android worker 未重建，5 项口令/构建配置及签名文件校验一致。匿名接口 401、错误 Host 400、5 项静态资产和 Android Chrome 能力检查通过。
- ZIP 在本机 LAN 上已完成长度、SHA-256 与传输结束检查。Chrome 的 HTTP 不安全下载阻止是客户端安全判定，不修改文件响应、读取上限或浏览器安全设置。排查入口见 [LAN 部署说明](deploy/android-docker/WINDOWS_LAN.md)。

## 本机第二轮同步：网页离线分析（2026-10-30）

同步上游 `d78f5da63ff86f5595518e50ffd163b4d1adc3ad`，保留上一轮数据包终态、私有权限和 Windows 文件替换修复。本节为当次本机验收；下方各阶段记录仅代表相应历史范围。

- 网页可显式启动、取消离线分析，并单独下载报告 ZIP。仅分析本次已保存的数据包，采集结果与分析结果分开；页面加载、轮询和下载不会启动分析。
- 修复提交分析成功后紧接着列表读取失败导致停止轮询的问题：先保留后端返回的分析状态，再刷新列表；当前和后台任务均持续有界间隔的 GET 轮询，不重复 POST。Node 回归覆盖连续两次读取失败后恢复。
- 本机真实 Chrome 完成登录、数据包就绪、点击分析、真实 fxapk 子进程、报告 ZIP 下载及内容核验。原 `blocked` 状态及原数据包摘要不变，重复状态/附件读取不重跑；桌面与 375 像素窄屏截图检查通过。
- 最终全量 **1022 passed、9 skipped、0 failed**，其中五项使用本机真实 fxapk 的服务/CLI 离线联调。跳过项仍为平台专用进程/套接字及 Windows 目录符号链接权限检查；一条既有 Starlette/httpx 弃用提示。Ruff、Pyright、JavaScript 语法和前端合成回归通过。
- Docker 增加可选分析镜像层和锁定依赖；fxapk 1.21.0 安装在独立虚拟环境，不更改采集服务依赖。无外网测试容器完成 **22 项**分析、权限及真实 fxapk 联调，审计钩子未记录 DNS/连接尝试。能力配置由容器管理员指定，网页不接受程序路径或命令。
- 当前运行的 Docker API 已启用离线分析。通过实际 HTTP API 提交本地合成数据包、等待完成并下载报告 ZIP，核验原采集结果保持不变；完成后清空专用测试会话。API、Android Chrome 和 APK 打包能力检查通过，未重建 Android worker；口令配置与签名文件校验一致。
- 本轮没有访问真实目标、安装目标 APK 或开展第二台设备 LAN 验收。报告是 JSON 与来源回执的 ZIP，不是完整案件报告，也不证明网站材料完整或经营者归属。离线性依赖 fxapk 的 `--offline` 契约，生产 API 仍保留授权采集所需网络。

## 网页端离线分析（本地开发）

- 增加独立分析队列及会话隔离的状态、取消与报告 ZIP 下载接口，网页只显示任务摘要，不渲染目标正文。分析不会占用采集或 WebView APK 构建线程。
- 仅显式点击启动；页面加载、轮询和下载都不执行分析。服务端配置可信 fxapk 程序，独立受限子进程仍调用原有离线适配，不修改 fxapk。
- 原 APK/IPA、任务数据包和分析报告独立；blocked/failed 等原采集结论不会因分析完成而覆盖。取消、超时、清空和重启不允许迟到报告重新发布。
- 最终定向回归：14 passed、1 skipped（该可选服务联调另行通过）；真实 fxapk 的服务子进程联调 1 项、原 CLI 联调 4 项通过。Ruff、Pyright、Node 语法与前端合成脚本通过；子进程审计钩子已加载，未记录 DNS/连接尝试。
- 本轮全量：992 passed、27 skipped、2 failed。两项失败为旧测试在 Windows 默认 cp1252 下读取 UTF-8 文件，设 `PYTHONUTF8=1` 后仅复测这两项，2 passed；未重跑全量，不能称全量全绿。
- 已检查合成状态下的面板渲染；这不是实际登录、提交、下载的浏览器操作验收。真实站点、Android worker、NAS/Docker 未验收。

## Windows 本机同步验收（2026-10-30）

本轮同步 GitHub `774eee7b06d92dec9fdd2097e1c48344eeb577a6`，保留 HTTP 优先、前端直接下载、脚本内容页追踪和原会话下载。新增统一任务数据包下载及 `prepare-analysis` / `analyze-data` 离线衔接。以下为本轮结果；后续章节保留上游各阶段历史记录，不能视为同一次验收。

- 修复排队取消后数据包长期显示中断，以及采集异常后未封存已保存材料的问题。未执行的取消任务显示数据包不可用，运行中的异常任务保留失败结果并封存材料。
- 独立网页采集、导出在写入前设置私有目录权限；Windows ACL 与 Linux 0700 均验证，权限失败停止，不覆盖原目录。
- 修复 Windows 轮询元数据时偶发的替换冲突：只对明确的 Windows 文件访问冲突最多尝试三次，累计等待 60 毫秒；磁盘不足等其他错误立即返回，永久权限错误仍报失败。
- 最终全量测试：**1006 passed、9 skipped、0 failed**，包括四项真实 fxapk CLI 离线联调。跳过为 Linux 专用进程/套接字检查及当前 Windows 无权限创建目录符号链接的两项检查；保留一条既有 Starlette/httpx 弃用提示。Ruff、Pyright 通过。
- 已安装桌面 Chrome 的本地合成测试：**102 passed**。新增包用途搭配真实 EvidenceJournal 的单次票据、脚本 HTML 附件、资源取消恢复验证；下载包哈希一致。合成的大型 data URL 按预算省略有明确记录，不冒充完整覆盖。
- 网页实测：前端直接下载不创建后台采集任务，五种网址补齐规则、非法协议拒绝、新数据包下载及未登录拒绝均通过；桌面和 375 像素窄屏截图已检查。
- Docker 同运行环境的无外网容器：五项统一采集检查和四项权限检查通过。实际 Android Chrome 经受限任务子进程取得 **13,607,818 字节的合成 APK**，API 附件哈希一致；独立 ZIP 保存两项网页材料，原 APK 字节不重复装入 ZIP。任务结束后 Android 租约释放，调试端口关闭。HTTP 前置阶段由测试夹具明确返回需要浏览器，不访问真实域名。
- 本轮只做合成靶场和离线集成，没有复测真实网址、安装目标 APK 或开展第二台设备的 LAN 验收。桌面 Chrome、实际 Android、界面和 Docker 检查各有独立范围。

上一轮同步时 fxapk 离线分析仅有 CLI；本轮新增网页分析入口，见最新验收。四项联调使用本机已安装的 fxapk，Docker API 镜像未额外安装 fxapk。生成 WebView APK 和采集原包结果继续分别记录。

## 上游容器配置验收记录

以下两节来自本次合入的上游记录，保留其验证范围；本机合并后的复测另列于本文开头。

### Docker fxapk 配置接缝本地验证（2026-10-30）

- 修复容器入口未传递 fxapk 配置的接缝：两套 Compose 均支持部署者指定 `FXFETCH_FXAPK`，只接受容器内绝对 Linux 路径，留空默认关闭；不读取宿主 `server.json`，不自动安装或挂载程序，现有隔离配置不变。
- 定向容器部署、Android API 启动与分析 service/API 测试：52 passed、1 skipped（可选真实 fxapk 服务集成未配置），1 条既有 Starlette/httpx deprecation warning。
- Ruff 及 `src`、`deploy/docker/entrypoint.py` Pyright 检查通过；Pyright 均为 0 errors、0 warnings、0 informations。
- `PYTHONUTF8=1` 且未设置 `FXAPK_EXECUTABLE` 的唯一全量回归：1007 passed、27 skipped、0 failed；1 条既有 Starlette/httpx deprecation warning。跳过项为 1 个可选服务集成、5 个 Linux 浏览器网关、15 个 PowerShell 防火墙、4 个可选 fxapk CLI 联调和 2 个 POSIX/Linux 进程限制测试。
- 使用仓库已固定的 Python 3.12 基础镜像摘要、生产 runtime 锁文件及独立测试锁文件构建 linux/amd64 测试镜像，`pip check` 通过；没有更改依赖版本。
- Linux 断网容器内的配置、分析 service/API 与进程限制回归：45 passed、5 skipped。容器使用非 root、只读根和源码、无 capabilities、禁止提权、3 GiB 内存及 256 PID 限制。跳过项为 4 个容器内缺少 Compose CLI 的配置测试（已在 Windows 主机通过），以及 1 个未配置真实 fxapk 的可选服务联调。
- 该轮 Linux 测试使用合成材料及替代 fxapk runner，不代表真实 Linux fxapk、NAS 实机、Android worker 或浏览器端到端验收；后续真实 fxapk 联调见下一节。
- 本地日志保存在 `.runtime/container-analysis-validation/`。

### 真实 Linux fxapk 合成联调（2026-10-30）

- 使用 Python 3.12.16 / linux/amd64，在独立 venv 中按 fxapk 提交 `1259a1c22bbb5ed9a465758ebfd4fbea38881ae8` 的完整锁文件安装 fxapk 1.21.0，安装源码使用 `--no-deps`。fxapk 源码及两侧依赖版本未改，两侧 `pip check` 均通过。
- 断网、非 root、只读容器内，4 项 CLI 混合材料联调、1 项服务子进程联调、1 项新增认证 API 联调全部通过：6 passed、0 skipped，1 条既有 Starlette/httpx deprecation warning。各用例网络审计加载标记存在，未出现网络尝试标记。
- 新增 API 回归通过真实 fxapk 完成提交、轮询、报告 ZIP 下载，核对报告大小/哈希、原始数据包不变、原采集 blocked 结果不被覆盖，以及新会话读取状态/报告返回 404。报告仍保留 partial 覆盖，未把分析成功写成采集完整。
- 已人工核对保存的 API 报告：仅含 `analysis.json` 和 `report/input.json`，原生报告 offline、无 load errors；合成正文线索及明确 HTTP 跳转保留，未认证目标归属。
- Ruff、Pyright 通过。本轮只增加可选集成测试，未重跑 Windows/全量；上一轮 1007 passed、27 skipped 为历史结果。API 使用 TestClient，不是浏览器或真实 TCP/Compose 端到端，也不代表 NAS 实机、Android worker 或真实站点验收。
- 日志及合成产物保存在 `.runtime/container-analysis-validation/`；镜像环境仅用于本地验收，没有把 fxapk 自动装入默认生产镜像。

## fxapk 离线衔接（后续本地实现）

- `prepare-analysis` 校验统一任务 ZIP 并整理独立输入；`analyze-data` 通过受限子进程调用已安装的 `fxapk analyze-web --offline --fmt json`。不修改 fxapk 源码，不改 APK/WebView 流程。
- 原始 ZIP、manifest、观察日志保留在分析输入之外；HAR 只投影明确请求身份及响应，来源映射指向原观察序号。候选、未知关联、frame 导航等未投影观察仍在原包，不冒充实际请求。
- `analysis_materials` 从明确关联的响应 MIME 选择解析器，避免浏览器 `.body` 脚本被作为普通文本漏掉静态跳转分析；同 URL 不够构成关联，冲突和未知保留为缺口。DOM、响应正文和截断前缀仍分别标注，字节和哈希不改写。
- 第一版实测：72 项定向测试、1 项真实 fxapk CLI 合成联调通过；全量 969 passed、23 skipped。Windows Python 3.13 / fxapk 1.21，未做 NAS/Docker 验收。这是后续 MIME/混合材料补修之前的结果，不代表补修后验证。
- MIME/来源补修后：81 项定向测试通过；最终类型标注修正后，真实 fxapk CLI 四个合成案例全部通过，全量 978 passed、26 skipped、0 failed，Ruff/Pyright 通过。四个可选集成用例已单独运行；其余跳过为平台相关。普通页面、blocked、合成包分离案例覆盖 JS 静态跳转、JSON 接口、第三方请求、未知/拒绝/失败请求、DOM 和截断前缀；子进程审计钩子确认加载，未记录 DNS/连接尝试。使用合成浏览器观察，不代表实际 Chrome 或 Android 采集验收。
- 上述 CLI 阶段未接入网页分析按钮；后续网页端本地改动见本文开头。页面载入、轮询和数据包下载均不得启动分析。
- 本地合成观察和真实 fxapk 子进程联调不等于真实浏览器采集验收；真实站点、Android worker、网页分析 UI 尚未验收。

## 独立网页材料采集（第一阶段）

本阶段实现为独立且有界的 `fxfetch capture-web` 工作流，包含 HTTP/浏览器采集器、每次采集独立的 JSONL provenance ledger，以及基于 `fxfetch.web-evidence.v1` 的离线目录导出/验证（例如 `fxfetch export-web CAPTURE_DIR --out NEW_BUNDLE_DIR`、`fxfetch verify-web BUNDLE_DIR`）。覆盖范围始终为 partial；浏览器命令必须显式提供 `--service-root .runtime/service` 并使用已有受保护的 Android worker。证据包可能包含私有查询参数和正文，不会匿名化；ledger 只适用于独立采集，不升级旧服务下载任务。本阶段没有 HAR、UI 或 fxapk 集成，也不改变既有下载行为。字节预算不包含 JSONL ledger 与元数据开销。验证覆盖合成真实 Chrome，实际 Android wrapper 尚未测试；哈希只保证完整性，不是真实性认证。

网页采集已按职责拆为生命周期编排、HTTP/浏览器采集、材料整理、浏览器观测、schema 校验、安全文件操作及来源关联校验。浏览器观测模块不发送 CDP 命令；传输与权限控制仍由原采集引擎管理。

统一下载任务的数据包采用独立 `fxfetch.task-evidence.v1` schema：传输观察者记录实际保存的正文和有界观察；每个已执行任务在终态后离线封存独立 ZIP，包括失败结果。原始 APK / IPA 继续单独保存在 artifact 路径，不作为 ZIP 材料；`GET /api/jobs/{id}/data-package` 只读取已就绪归档，`verify-data` 离线验证 ZIP。这个新 ZIP 不替代或修改 `fxfetch.web-evidence.v1`。

本轮合并重整增加了包用途浏览器的事实观察、带生命周期收据的有界 JSONL、来源关联校验、包字节排除、API 封存状态和安全封存限制。本地最终验证的失败、修复和限制记录如下；不将这些检查扩展解释为真实网站、DNS 或 Android worker 验证。

以下为此前独立网页模块重构及较早项目验收的历史记录，不代表本轮任务数据包重整的检查结果。此前网页改动曾有全量回归 896 passed、22 skipped；后续小修的定向回归为 64 passed，合成 Chrome 选择为 9 passed、59 deselected，Ruff 与 Pyright 通过。历史记录还包括 869 passed、7 项平台专用跳过等不同范围的结果，不应相互合并。本轮最终聚焦验证结果记录在下方。

### Codex 审查问题修复与本地验证（2026-10-29）

- 网页用途响应处理完成即返回，不再落入取包分支二次消费；模拟 CDP 回归覆盖 302 跳转与两种用途的单次读取。
- 浏览器按实际字节识别 ZIP/APK/IPA 容器前缀，完整正文及失败/限额截断前缀均记录 `package_stream`；不足四字节但仍可能匹配容器签名的失败前缀也保守排除。标记不代表包结构校验成功，不凭该标记创建 artifact。回归贯穿响应分发、来源日志、ZIP 封存及离线校验。
- 维护线程直接终结排队超时任务后走统一离线封存，记录 `queue_timeout` / `not_started`；封存期间保持 `building`，结束前不可下载。实测覆盖已有运行任务、真实维护循环、暂停封存、ZIP 内容及归档所有权清理。
- 数据库终态提交后先落盘最终证据摘要，再封存独立 ZIP；封存阻塞期间摘要已提交，原始结果不等待 ZIP。数据库与文件仍是两个提交步骤，读取测试按 `terminal_status=committed` 有界等待，而非固定延迟。
- 定向集成测试：101 passed。最后的证据落盘顺序修复后，相关 API/维护线程回归：15 passed。浏览器回归最后定向运行：模式/正常正文归档 1 passed，包正文及失败前缀归档 4 passed；各组有重叠，不相加当总数。
- 本轮唯一一次全量：938 passed、22 skipped、2 failed。证据摘要时序失败已修复；取消测试单项复测通过，但首次失败根因未确认。两项之后均定向通过，最后修改后未再跑全量，不能宣称最终全量全绿。
- Ruff 通过；最终 Pyright 为 0 errors、0 warnings、0 informations；CRLF-aware diff 检查通过。存在一条既有 Starlette/httpx deprecation warning。
- 真实 Chrome 合成子集 6 skipped（当前环境未找到已安装 Chrome，未自动下载）。模拟 CDP 不等于真实浏览器验收。没有访问真实站点、DNS、进行 UI/Android worker 测试或 fxapk 联调，也没有再次调用付费模型。

### 后续 Codex 审查三项修复与本地验证（2026-10-29）

- 浏览器网页模式按公开 CDP target ID 关联渲染后的验证码/设备拒绝快照；同 URL 的弹窗挑战仅记日志，不改变主页面结果。模拟浏览器回归分别验证干净 200 正文与渲染 DOM。
- HTTP 网页采集延迟加载浏览器模块；新进程通过拒绝所有 Playwright 导入的导入钩子验证离线预览和本地合成 HTTP 采集。
- 在构造 `ZipFile` 前独立有界解析 ZIP/标准 ZIP64 结束记录及中心目录：最多 2002 项、目录不超过 8 MiB，并检查期限、声明数量和目录边界；不解压正文。小型 ZIP64 有效包及超限/伪造计数等输入均有回归覆盖。
- 定向浏览器、网页采集和任务归档测试：58 passed；Ruff 通过；Pyright 为 0 errors、0 warnings、0 informations。
- 本轮唯一一次全量 pytest：953 passed、22 skipped、0 failed。跳过项为 5 个 Linux 浏览器网关、15 个需 PowerShell 的防火墙和 2 个 POSIX/Linux 进程限制测试。存在一条既有 Starlette/httpx deprecation warning。
- 未访问真实站点或 DNS，未安装 Chrome，未运行应用服务器。详细输出保存在 `.runtime/review-task-evidence/fix-logs/codex-*.log`。

### ZIP EOCD 复审补充（2026-10-29）

- 归档预检只接受尾部最后一个 EOCD 签名并要求注释长度精确到达 EOF；注释内伪造的、长度不匹配且声明超大目录的 EOCD 在构造 `ZipFile` 前被拒绝。有效普通注释及既有小型 ZIP64 回归仍通过。
- `tests/test_task_bundle.py`：34 passed。此补充修订未重跑全量；上节 953 passed、22 skipped、0 failed 仍仅记录 `e622e85` 修订的全量结果。

### 前一轮任务数据包重整的本地验证（2026-10-29，修复前历史）

- 两个定向回归预检：2 passed，1 条既有 Starlette/httpx deprecation warning。
- 唯一一次全量 pytest（修复前）：928 passed、22 skipped、4 failed，1 条既有 Starlette/httpx deprecation warning。4 个失败分别是浏览器清理异常保留挑战结果、两个构建任务缺少任务目录、HTTP 保存正文的日志路径字段被省略。
- 修复后仅重跑受影响测试：4 passed；因遵守单次全量运行要求，未在修复后重跑全量套件。全量结果因此不能表述为修复后全绿。
- 已恢复原有独立 WebView 构建磁盘计量；两个 task supervision 回归复测为 2 passed。
- 22 个跳过项：5 个 Linux 浏览器网关行为、15 个需 PowerShell 的防火墙测试、2 个 POSIX/Linux 进程限制测试。未启用 live-site、Chrome UI 或 Android worker 测试。
- Ruff `check src tests`：通过；Pyright `src`：0 errors、0 warnings、0 informations；Node `--check`：`app.js` 与 `data-package.js` 均通过。
- `git diff --check` 因 Windows `core.autocrlf=true` 将 CRLF 报为新增行尾空白而退出 2；`git -c core.whitespace=cr-at-eol diff --check` 通过，未见其他空白问题。
- 本轮没有进行真实目标、DNS、浏览器 UI 或 Android worker 测试。

以下为 2026-10-29 的既有能力及历史记录，不代表本轮重新运行所有历史验收；实时可用性以 `/api/capabilities` 和实际任务结果为准。

## 当前能力

| 模块 | 已实现 |
| --- | --- |
| 输入 | URL 离线补齐、图片二维码识别、多码选择和编辑；预览不访问目标 |
| HTTP | APK 优先、IPA manifest、逐跳记录、候选选择、包结构与完整性校验 |
| Android Chrome | HTTP 需要动态处理或收到 403/429/502/503 时，最多尝试一次独立浏览器会话；不继承 HTTP Cookie，共享剩余预算 |
| 动态下载 | 原 Chrome 会话处理页面、按钮、Cookie 和一次性票据；从原响应流保存文件，不重发下载 GET |
| 内容页追踪 | 读取已下发 DOM 文件锚点，以及验证页面内联脚本中的字面量 HTML GET 地址；多地址须选择，循环停止 |
| 网页服务 | 登录、会话隔离、CSRF/Origin/Host 校验、幂等、进度、取消、附件下载和刷新清空 |
| APK 构建 | 固定 WebView 模板、持久签名、域名命名和版本映射；可包含清理后的局部静态内容及固定字体 |
| 部署 | Windows Docker 管理 QEMU/KVM Ubuntu worker 与独立 API；使用固定 Redroid / Chrome 环境 |

浏览器已处理慢脚本、DOM 重绘、重复按钮、div/span 下载控件及无关资源失败。连续 30 秒无实质进展停止观察；接收正文仍受原读取和总任务预算约束。

“直接下载到当前设备”由客户端浏览器访问明确 APK/IPA 链接，不创建后端任务，也不表示服务端已校验文件。候选子任务另起请求会话，不继承父任务 Cookie。

## 历史验收记录（不代表本轮重整已重跑）

以下为不同范围的历史验收，数量不能相加为同一次测试结果；它们不验证本轮任务数据包改动。

| 范围 | 记录结果 |
| --- | --- |
| 最新 Windows 标准回归 | 869 passed，7 项 Linux/POSIX 专用跳过；Ruff、Pyright、JS 语法检查通过 |
| 最新桌面 Chrome 合成回归 | 95 passed；桌面与 375px 界面、直链下载及零目标请求预览通过 |
| Docker Linux 专项 | 43 passed，覆盖网关、进程限制及平台专用行为 |
| Windows Docker 启动器 | 最后定向回归 17 passed；普通用户实际启动通过 |
| Android 完整合成链路 | 隔离 task_worker → Android Chrome → 原响应下载 → API 附件，13,607,818 字节，SHA-256 一致，关键请求各一次 |
| Android 隔离与期限 | 内外层阻断、允许 broker 路径、2 GiB 数据卷写满、取消及后继会话、210 秒 guest 原生租约到期通过 |
| Linux APK 构建 | 非 root、断网、3 GiB cgroup 下完成签名构建；核验 Manifest、DEX、ZIP、中文资源及字体 |
| 本机服务入口 | 本机 LAN 地址、匿名接口 401、错误 Host 400、静态文件一致性和能力检查通过 |

Docker 迁移使用已关机源盘的独立 qcow2 副本，逻辑内容比对与源盘前后摘要一致。修复了 worker 线程额度、Linux TIME_WAIT 端口重用和 QMP 关机确认；实际停机、重启已验证。

## 限制与未完成项

- 第二台真实 LAN 设备、手机安装运行和 Mac 部署仍未验收。
- 不支持通用验证码求解、硬件证明绕过、blob 下载或人工原 Chrome 会话续接。
- Worker/SharedWorker/ServiceWorker/worklet 超出当前支持范围时拒绝并保留覆盖缺口；不能推断所有动态页面均可处理。
- 取得已下发文件不代表验证码或设备验证通过；失败、受阻、超限和覆盖不足不能写成“没有 APK”。
- 局部网页快照不是完整离线业务，生成 WebView APK 不是目标原包；构建成功不等于手机可用。
- Chrome 启动、网络隔离、磁盘和租约须逐环境验收；历史成功、配置存在或 Compose healthy 都不能替代实时证明。

## 运行记录与复核入口

私有收据位于 `.runtime/android-worker/`、`.runtime/docker-worker/`、`.runtime/android-docker-api/`、`.runtime/live-download-20261029/` 及 `.runtime/service/`，不随源码交付。详细旧记录可查 Git 历史。

部署见 [Windows Docker](deploy/android-docker/README.md) 和 [LAN 入口](deploy/android-docker/WINDOWS_LAN.md)；接口见 [API](API.md)，工程验收要求见 [任务书](TASKBOOK.md)。
