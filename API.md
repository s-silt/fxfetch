# HTTP API v1

## 模型设置

以下接口须登录，两个 POST 另须同源 Origin 和 CSRF；不接受客户端提供供应商地址或密钥。

| 接口 | 输入与结果 | 供应商请求 |
| --- | --- | --- |
| `GET /api/model-settings` | 返回 `{current_model}` | 无 |
| `POST /api/model-settings/refresh` | `{}`；返回 `{current_model, models: [模型 ID], list_token}` | 一次已配置 HTTPS 模型接口的 `/models` GET |
| `POST /api/model-settings` | `{model, list_token}`；返回 `{current_model}` | 无 |

列表仅显式点击获取，不自动请求、重试或保存。每服务同时一次、调用间隔至少十秒，严格 TLS、默认直连且拒绝重定向；独立受限进程整体执行最多三十秒、内存 256 MiB，响应最多 1 MiB、1000 个模型，每个 ID 为 1–200 个 ASCII 可见字符。列表令牌仅存内存，绑定当前会话及配置摘要，十分钟过期；服务重启、配置变化或列表被替换后须重新获取。只可保存该列表中的 ID，保存保留密钥、接口、其他字段和文件权限。设置由服务共用，用于之后的图标识别和 AI 辅助选择；列表中存在不代表模型支持图片或推理可用。

保存的响应丢失或超时时，前端显示「保存结果未确认」，只调用 `GET /api/model-settings` 核对实际当前值；核对失败提供手动再次核对入口，不重发保存、列表或推理请求。核对及迟到响应受登录/清空状态代次保护。

模型服务默认直连。后端私有配置可选 `vision_proxy`，仅接受显式端口的本机 HTTP 代理（回环或 Docker 的 `host.docker.internal`），只应用于配置模型接口及其 `/models`；不改变 SerpApi、采集请求或系统代理。严格 TLS、拒绝重定向和无自动直连回退保持生效；网页不能修改代理。

错误代码包括 `model_list_busy`、`model_list_cooldown`、`model_list_invalid`、`model_list_limit`、`model_list_expired`、`model_not_available`、`model_settings_changed`、`model_settings_unavailable` 及既有供应商错误。失败不改变当前模型，也不透传供应商响应正文。

## AI 辅助选择

`POST /api/jobs` 新增严格布尔字段 `gemini_select`，默认 `false`。网页默认勾选后随明确的开始采集动作提交 `true`；离线预览、上传和读取均不调用模型。

任务发现多个候选后，在原任务隔离 worker 与执行期限内最多进行一次模型判断。只提交候选名称、域名及截断路径，不提交查询参数或页面正文。`result.candidate_advice` 记录 `state`、`reason`、`candidate_index` 及请求/返回模型名称；`selected` 仅代表建议，不代表下载成功。

生产模型判断另用独立受限子进程：上限三十秒、256 MiB、16 KiB 输出，并按父任务剩余预算扣除至少五秒结果保存余量。预算不足返回 `manual/ai_budget_insufficient`，硬超时返回 `manual/ai_timeout`，进程异常返回 `manual/ai_worker_failed`。原采集 outcome、reason 和候选不被这些建议失败覆盖，取消仍受整个任务进程树约束，无模型重试。

建议可附 `elapsed_seconds`、`timeout_seconds`、安全的 `request_timing` 与 `error_detail`；后者仅含固定错误码和有效 HTTP 状态，不附供应商正文、密钥或端点。

有效建议在 supervisor 提交原结果后，按原继续下载合同创建独立子任务，沿用该任务 TLS 策略，标记 `input.selection_method=ai`。子任务不继承自动选择，实际下载结果在子任务中查询；原结果不改写。关闭、取消、清空、重启、模型失败或不确定时不自动创建新下载。

本页是网页服务的接口约定；项目与部署入口见 [README](README.md)，实际验收范围见 [IMPLEMENTATION.md](IMPLEMENTATION.md)。后端执行采集、构建和分析，前端使用同源 JSON API；图片上传使用 multipart 的 `file` 字段，所有响应默认禁止缓存。计划接口不视为已提供。

| 查找内容 | 章节 |
| --- | --- |
| 登录、会话与请求认证 | [会话与请求](#会话与请求) |
| 任务接口、附件、证书和策略字段 | [任务数据包](#任务数据包) |
| 结果含义、失败分流与期限 | [状态与结果](#状态与结果) · [下载分流](#下载分流与特殊结果) · [时限与进度](#时限与进度) |
| 服务能力与可选配置 | [能力与服务配置](#能力与服务配置) · [离线内容与字体](#离线内容与字体) |
| 离线分析与会话清理 | [离线网页分析](#离线网页分析) · [刷新与清空](#刷新与清空) |

## 会话与请求

`GET /api/session` 返回 `{authenticated, csrf_token, expires}`。`POST /api/login` 接收 `{password}`，成功设置 HttpOnly / SameSite=Strict 会话 Cookie；写请求必须具有与服务地址一致的 Origin。登录后所有写请求另需 `X-CSRF-Token`。`POST /api/logout` 使会话失效。单会话 8 小时，不因重新登录自动获得其他会话的任务。

## 任务数据包

每个执行中的普通下载任务在原工作流完成后离线封存一个独立 ZIP；采集工作流不会重放。原 APK / IPA 仍可单独下载，v2 ZIP 另在 `attachments[]` 纳入已完整接收的 APK/IPA 原字节与实际保存的 TLS DER 证书；校验失败的完整原包标为 `validation.status: failed`，不会成为成功 artifact。网页材料仍由 `files` 描述，不包含二进制附件。ZIP 归档失败不会改写原任务结果或移除已保存 artifact。

`GET /api/jobs/{id}` 返回独立的 `data_package` 状态：`pending`、`building`、`ready`、`failed` 或 `unavailable`。就绪时带有 `filename`、`size`、`sha256` 、`web_materials` 和 `attachments: {packages, certificates, bytes}` 摘要；失败时提供 `reason_code`。旧任务没有该归档时显示 `unavailable`。`web_materials` 总是标注 `coverage: "partial"`。新归档另带 `tls_certificates: {state, http_certificates, chrome_certificates, association_limited, reasons}`；state 为 `not_applicable`（没有相关观察）、`saved`、`partial` 或 `not_captured`。Chrome 原件齐全但仅有 origin 或浏览器网络事件范围关联时为 saved 且 association_limited=true。

`GET /api/jobs/{id}/data-package` 使用与任务/artifact 相同的会话认证、所有权和归档可见性规则；仅就绪归档可下载，返回 `application/zip`、附件文件名及 `Cache-Control: no-store`。读取、下载或刷新任务不会触发目标网络访问。

离线 CLI `fxfetch verify-data ARCHIVE.zip` 有界验证 ZIP 路径、清单、观察记录和归档材料哈希；不会解压归档。其成功仅说明 ZIP 内列明的材料及附件原字节/绑定通过完整性检查，不表示 APK 结构、签名或安全性验证通过；外部引用的未嵌入原包仍未验证。HTTP 原件来自同一次实际连接，默认验证身份；实际发生证书错误后继续时独立标记未验证；Chrome 在隔离采集会话内被动读取普通 `netlog` 类别的 `SSL_CERTIFICATES_RECEIVED` 事件，能取得的原 DER 记录 `capture_source: chrome_netlog_ssl_certificates_received`、`association: browser_network_event`、`request_association: unknown`，保留事件 PID、source ID、时间及链序号。不能可靠绑定请求时 `source_url` 为空、不猜 origin；原 trace 仅在内存中限额处理，不打包网络日志。另通过 CDP 尽力读取已观测 HTTPS origin 的证书快照，记录 `capture_source: chrome_cdp_network_get_certificate`、`association: origin_snapshot` 与 `request_association: observation_trigger_only`。origin 快照附件保留会话/目标、触发响应、origin、观察/保存时间及原始链序号，不声称属于该次具体连接；仅有指纹的历史证书不能还原。合法链成员可以部分保存，缺失及获取失败明确记入 gaps。

Host 由启动参数明确允许。上传鉴权在 multipart 解析前完成，先有界收取最多 11 MiB 的请求，再交给解析器；文件最多 10 MiB、总上传时间 30 秒、单次解码。支持的静态图片格式在受限进程内验证和扫码，具体格式见下文。

任务和构建提交都需要 `Idempotency-Key`（8–128 个 ASCII 字符）。同会话相同键、相同参数返回原记录；不同参数返回 409。网络中断时重试原键，不要因为刷新生成新任务。

| 方法 / 路径 | 输入和返回 |
| --- | --- |
| `GET /api/capabilities` | HTTP/Chrome/构建能力及明确不可用原因；不探测目标 |
| `POST /api/preview` | `{url}` → `{kind,url,request_url,original_input,normalized,network_requests:0}` |
| `POST /api/qr-images` | multipart `file` → 图片 `id`、解码状态、哈希、候选、截断信息；无目标请求 |
| `GET /api/qr-images/{id}/thumbnail` | 当前会话图片的服务端 JPEG 缩略图，不返回原图元数据 |
| `POST /api/jobs` | `{url,tls_policy?}` 或 `{image_id,candidate_id,url?,tls_policy?}`；显式授权本次采集；202 返回 job |
| `GET /api/jobs` | 当前会话最新 50 个任务摘要；`active_builds` 为排队/运行构建数量 |
| `DELETE /api/jobs` | 认证、Origin、CSRF 后清空当前会话记录，停止未完成任务；重复调用幂等 |
| `GET /api/jobs/{id}` | 当前任务、结果、进度、产物、构建和可封装网页候选 |
| `POST /api/jobs/{id}/continue` | `{candidate_id,tls_policy?}`；选择精确下载候选后创建独立子任务，202 返回 child job |
| `POST /api/jobs/{id}/cancel` | 取消排队或运行任务；重复操作幂等 |
| `POST /api/jobs/{id}/web-apk-builds` | `{candidate_id}`；手动点击后构建，202 返回 build |
| `GET /api/jobs/{id}/web-apk-builds/{build_id}` | 构建状态/结果/已登记产物 ID |
| `POST /api/jobs/{id}/web-apk-builds/{build_id}/cancel` | 取消构建进程树 |
| `GET /api/jobs/{id}/artifacts/{artifact_id}` | 已登记附件，文件名来自受控配置；无路径参数 |
| `GET /api/jobs/{id}/rejected-files/{file_id}` | 已完整保存但包校验失败的原文件；只读附件下载，不改变任务结果 |

二维码候选保留原始文本、严格解码结果与坐标；`url=null` 表示不可直接提交。多码必须选择。`truncated=true` 时须裁剪重新识别。提交的 `url` 是对所选二维码的编辑值，来源仍保留。原始 itms-services 文本作为 manifest 入口处理，不安装描述文件。

`tls_policy` 接受 `auto` 或 `strict`，新网页任务和候选子任务默认 `auto`，每次提交独立固化。auto 仍先验证证书，仅真实证书校验错误允许有界继续；strict 在证书错误时停止。核心与 CLI 默认 strict。兼容旧输入 `ignore_tls_errors`（严格 JSON 布尔值）：true 映射 auto、false 映射 strict；与显式 `tls_policy` 冲突返回 422。幂等参数包含策略，同键改变策略返回 409。同一次提交的网络错误重试保留冻结参数，下一新任务恢复 auto。

任务公开 JSON 的 `tls_policy`、`input.tls_policy` 与新数据包清单保留策略。`tls_fallback` 用 `state`（pending/recorded/unavailable）、`observed`、`count` 和固定 `reasons` 区分实际降级、未发生及记录缺失。采集前写 `task_tls_policy`，实际证书错误与继续分别保留证据，不能仅凭 auto 将所有连接记为 ignored。HTTP 严格验证成功仍为 `verified_tls_socket`，证书错误后继续为 `unverified_tls_socket`，需可追溯到对应失败和降级记录。Chrome 保留真实事件范围，无法与具体请求可靠关联的证书不能声称已验证或已降级。旧归档没有 `tls_policy` 时仍按原手动忽略字段解释，不改写历史含义。缺失原件继续记缺口。`downloaded` 仅表示传输和包结构校验通过，不证明服务器身份或软件安全；策略不影响公网守卫、预算、当前设备直接下载、系统信任或 WebView APK。


网址输入可直接使用裸域名、`www` 域名和路径：缺少协议时补 `https://`，`//host/path` 补为 HTTPS，`https:/host/path` 补齐斜杠；已有 `http://` 保留。查询参数、转义和片段不因补齐被改写。前端提交前使用同一个离线 preview 规范化规则；preview 不解析 DNS、不访问目标。直接提交 jobs 也应用相同规则，发生补齐时 `input.original_input` 保存原始文本，`input.entry_url` 保存实际入口。`javascript/data/file/ftp/intent` 等显式其他协议不改写成 HTTPS；既有严格 `itms-services` manifest 入口仍单独处理。补齐不代表地址已通过公网连接检查。

## 状态与结果

采集状态为 `queued → running → completed/cancelled`；服务重启会将遗留排队/运行任务置为 `interrupted`，不重放入口。源输入落盘失败也置 `interrupted`，绝不执行未固化的输入。

`outcome` 与运行状态分开：`downloaded`、`not_found`、`blocked`、`failed`；未执行为 null。`not_found` 仅代表本次完整静态范围内无包。脚本、挑战、多个未选候选、超限和错误都不能据此回退 IPA。中间发现事件的 outcome 可为 null。

`result.offline` 返回 `{available,bytes,coverage,reasons}`，仅说明可加入 APK 的局部静态内容。已保存响应的正文、头、宿主文件路径和其他私有材料不通过任务 JSON 公开。

构建状态为 `queued → running → built/failed/disabled/cancelled`，重启为 `interrupted`。构建成功不修改原采集 outcome。`origin=downloaded_original` 为下载原包，`origin=generated_webview` 为生成包。

任务详情另有 `rejected_files`，成员为 `{id,filename,kind,size,sha256,validation_status:"failed",reason_code}`。仅展示完整接收、可关联到明确 APK/IPA 包校验失败的文件，不加入 `artifacts`，不将任务改为 `downloaded`，不影响已有网页打包候选。旧 HTTP 记录仅在完整正文、响应和最终错误能严格对应时兼容；旧 Chrome 记录缺少完整性证明则不展示。

原文件下载沿用会话归属与归档可见性规则，校验当前任务目录内的普通文件、大小和 SHA-256 后，返回 `application/octet-stream`、附件文件名、`Content-Length`、`Cache-Control: no-store` 和 `nosniff`。传输的仍是原始字节；不重抓目标、不修复压缩条目、不重新签名。截断、超时、取消、普通网页、越界路径、链接文件或摘要不符均不提供该入口。刷新清空记录后该下载也不可见。

只有任务结束、没有下载原包、且存在合法网页候选时可构建。客户端提交候选 ID，不提交任意网页、路径、包名、脚本或签名选项。打包交付仅一个 APK；离线资源只在 APK 内，不附带证据清单。

错误有两种兼容格式：`{error:{code,message?}}` 或 `{detail:code}`。未认证 401，Origin/CSRF 403，不属于当前会话的对象 404，幂等/队列冲突 409，过大上传 413，忙碌/登录限流 429，构建能力缺失 503。

前端每个活动任务按 1.5–5 秒自适应轮询，隐藏页面或无活动任务停止；轮询和恢复只读状态，不能重启采集。会话失效后停止请求并重新登录。

DNS 进度事件为 `dns_resolution_observed` / `dns_resolution_failed`，公开字段仅保留 `provider`、`query_type`、固定 `reason_code` 与已有任务/URL 引用。完整有界 `dns_record` 只写入私有观察记录并随数据包保存，包含解析答案、分类、响应摘要和省略标记；摘要不等于 DNS 响应原件。`dns_unsafe_answer` 表示答案中含不允许连接的地址，任务失败且覆盖不完整，不代表没有 APK；`dns_tls_verification_failed` 指解析服务自身证书失败，不受目标证书自动续行策略影响。正常浏览器关闭不发拒绝事件；实际拒绝、建立连接失败、已连接传输中断、预算和取消分别使用 `browser_connection_blocked`、`browser_connection_failed`、`browser_transport_failed`、`browser_budget_exhausted`、`browser_connection_cancelled`。

### 下载候选继续

任务详情的 `download_candidates` 为 `{id,url,kind,source_url,label,child_job_id}` 列表，仅取自该任务最终未决的 `result.selection_candidates`。候选 ID 绑定父任务和地址，客户端不能用任意 URL 替换。旧记录缺少精确选择集时列表为空，`download_selection_unavailable=true`，需重新提交入口。

`POST /api/jobs/{id}/continue` 需要所属会话、Origin、CSRF 和 Idempotency-Key。父任务须已 completed 且未取得原包。一个候选最多有一个子任务，一个父任务同时最多有一个 queued/running 子任务；其结束后可选其他候选。`continuation_active_child_job_id` 及兼容字段 `continuation_child_job_id` 只指当前活动子任务，各候选自己的 `child_job_id` 保留历史结果。

子任务 `input` 保存 `parent_job_id,parent_entry_url,selected_candidate_id,source_url,selected_candidate_kind,continuation_depth`；`session_continuity=independent_request_session,cookies_inherited=false`。不重新访问父入口、不导入父 Cookie，保留父结论；最多 4 层并拒绝去片段后的祖先循环，查询参数仍保留。每个子任务重新使用普通有界采集预算，全部清空时父子一并隐藏及取消。活动冲突 `continuation_active`、重复选择 `candidate_already_selected`、深度/循环错误均明确拒绝。

## 下载分流与特殊结果

HTTP 优先；需要动态处理或收到 403/429/502/503 时最多尝试一次独立 Android Chrome 会话。结果 `landing.http_resolution` 保留 HTTP 结果与 `new_browser_session=true,cookies_inherited=false`，两阶段共享预算。客户端直链下载不调用 `/api/jobs`，不产生服务端 `downloaded` 结论。

| 场景 | 字段 / 原因码 |
| --- | --- |
| DOM 文件锚点 | `mechanism=rendered_package_link,same_browser_session=true` |
| 验证页已下发文件链接 | `verification_passed=false,continuation=explicit_dom_package_link` |
| 内联脚本字面量 HTML GET 内容页 | `kind=http,action=script_content_link`；跳转 `mechanism=script_content_link,same_browser_session=true`；验证观察 `continuation=explicit_script_content_link` |
| 内容页循环 / 提取限额 | `browser_content_loop` / `browser_script_limit` |
| Flutter 超限 / 需要运行 | `flutter_source_download_limit` / `flutter_runtime_required` |
| 设备验证 | `device_verification_required`，outcome 为 blocked |
| 编码缺口 | `text_charset_conflict,text_charset_unsupported,text_decode_failed` |
| 验证结构 / 动态依赖 | `challenge_detected` / `browser_required` |

只追踪已下发明确地址，不求值动态表达式、不重放 POST。文件取得与验证观察分别记录；这些错误、覆盖缺口或站点验证不表示“没有 APK”，也不判断网站性质。读取预算见 [任务书](TASKBOOK.md)。

## 时限与进度

`capabilities.task_limits` 返回 `collection_seconds=600,build_seconds=900,queue_budget=separate_same_duration`。排队和执行分别计时，各阶段共享任务期限，不能由客户端放宽。

生产 `execution_limit_method=isolated_process_tree`，并分别返回 `collection_limit_method,build_limit_method`；测试注入标为 `mixed_or_injected` / `injected_test_callable`，HTTP 不能选择该模式。到期或取消终止整个进程树，拒绝迟到成功附件。

| 超时 | 结果 |
| --- | --- |
| 采集执行 | `failed/task_timeout`，覆盖 partial |
| 构建执行 | `failed/build_timeout` |
| 排队 | `queue_timeout`，覆盖 not_started |

任务和 `builds[]` 的 `progress` 字段：

- `event`：最新事件；`events`：最多 128 项，每项有递增 `seq` 和 Unix 秒 `at`，采样合并后序号可不连续。
- `started_at,deadline_at,timeout_seconds,execution_limit_method`：执行信息；`queue_deadline_at,queue_timeout_seconds`：排队信息。
- 跳转：`from_url,to_url,mechanism`；传输：`received_bytes,total_bytes,complete`。未知总长为 null；complete 仅表示响应结束，file_verified 才表示文件检查通过。

采集事件：`request,response_received,redirect,page_received,download_candidate,download_started,download_progress,response_progress,response_complete,file_verifying,file_verified,challenge_detected,browser_required,browser_preparing,browser_started,browser_connection_blocked`。
终态：`task_completed,task_timeout,cancelled,queue_timeout`。

构建阶段：`building,build_preparing,build_resources,build_compiling,build_signing,build_verifying,build_saving`；终态按 `built,failed,disabled,build_timeout,cancelled` 展示。后台传输进度最多每秒更新一次，另保留起止样本；客户端倒计时不能替代后端停止确认。

## 能力与服务配置

`capabilities.chrome` 使用后台只读探测，每实例最多一个探测，完成后缓存 30 秒。`checking` 表示检查中，`cached` 表示展示缓存；探测不导航目标，实际任务仍需新 lease 和实时环境证明。`android-worker.json` 是服务端私有配置。

`server.json` 仅接受 `host,port,allowed_networks,proxy_host,proxy_port,fxapk_executable`；绑定具体 RFC1918/IPv4 回环地址，按真实 socket peer 校验，不信任转发头。`fxapk_executable` 默认 null（不启用离线分析），只能由后端配置可信程序；`serve --fxapk` 可覆盖本次启动。当前部署 `proxy_host=null`，仅直连。DNS 默认 AliDNS 223.5.5.5，服务/传输失败才回退 DNSPod 119.29.29.29。

兼容的代理候补只允许服务端显式配置回环 CONNECT 地址：初始传输失败且无响应/会话推进时，最多一次独立尝试，共享总预算；访问控制、证书、守卫失败或覆盖缺口不触发切换。`capabilities.network_policy` 声明模式；`network_mode,network_attempts` 和 `network_attempt_started,network_fallback,network_attempt_completed` 保留各次结果。兼容字段不表示当前启用代理。

客户端不能修改绑定地址、网段、DNS、代理、worker 或字体路径。

## 离线内容与字体

图片接受 PNG/JPEG/WebP/HEIF/BMP/GIF/TIFF/AVIF 的受支持静态格式，拒绝动画和多帧；扫码候选不证明包存在。具体资源预算见任务书。

可选 `offline-font.json` 仅含 `path,license_path,size,sha256,git_blob_sha1,license_sha256`。绝对本机路径、固定 Noto Sans CJK SC Sans2.004 字体及许可摘要均需校验，拒绝重解析点。结果 `font_applied,font_reason` 记录实际应用及失败/跳过原因。

构建结果包含 `offline_content_kind`（`site_snapshot` / `connection_page`）、`offline_content_reason,resource_bytes,resource_files,size`。resource_bytes 为离线资源及许可的未压缩总量，size 为成品大小。离线资源上限 28 MiB，APK 上限 30,000,000 字节。无快照时只提供联网指引，不修改原采集结果。

## 离线网页分析

以下接口只使用该任务后台已就绪的 `fxfetch.task-evidence.v1` / `v2` ZIP，不接受用户文件路径、URL、程序路径或执行参数。所有接口检查当前会话及父任务归属；父任务归档后返回 404。写接口沿用 Origin、CSRF；创建还必须提供 Idempotency-Key。

| 方法 / 路径 | 行为 |
| --- | --- |
| `POST /api/jobs/{id}/analyses` | 空 JSON `{}`，202 返回独立分析任务；同键重试返回同一记录 |
| `GET /api/jobs/{id}/analyses/{analysis_id}` | 读取状态，不执行分析 |
| `POST /api/jobs/{id}/analyses/{analysis_id}/cancel` | 取消排队或运行中的分析，阻止迟到成功发布报告 |
| `GET /api/jobs/{id}/analyses/{analysis_id}/report.zip` | 仅完成状态可下载；再次核对文件路径、大小及 SHA-256，附件响应 no-store |

`capabilities.web_analysis` 包含 `enabled,reason_code,online:false,timeout_seconds,queue_timeout_seconds`；不返回程序路径。任务详情增加 `analyses[]`，列表增加 `active_analyses`。状态为 `queued,running,completed,failed,not_analyzed,cancelled,interrupted`；公开记录含 ID、状态、时间、原因码和 `report_ready`，不含原报告、命令、日志或宿主路径。原采集结论保持不变，`coverage=partial`。

每个任务同时最多一个活动分析，全局排队最多 10 个，每任务累计最多 10 次；来源不可用、已有活动分析、额度超限返回 409，fxapk 未配置或不可用返回 503。无可分析材料为 `not_analyzed`，不能当成功。排队期限 600 秒，整个子进程（含校验、材料准备）执行期限 360 秒、内存 2 GiB；达到期限或取消终止进程树，不发布迟到报告。

提交不解析 ZIP，只固定已就绪归档的来源路径、大小和 SHA-256。完整校验及报告整理由后台受限进程完成；损坏或摘要不匹配会异步失败，而非在 POST 请求线程展开材料。

报告 ZIP 只含 `analysis.json` 与 `report/input.json`。发布前剔除缺少可定位原文完整值的硬编码密钥提示及重复摘要；已保留线索只说明静态字面值，不证明凭据有效或解密成功。原 fxapk 输出私有保留于 `native-report/`，旧报告发布也执行同一过滤，回执记录发布 JSON 的哈希。原件按回执映射从独立数据包回查；不包含 APK/IPA、原始 ZIP 或执行日志，回执中的程序路径和命令不导出。原生报告仍可能包含敏感线索及 `meta.web_evidence.source_dir` 主机材料目录，不在网页中直接渲染；普通状态 JSON 不暴露这些内容。

服务重启将未完成分析置为 `interrupted/service_restarted`，不自动重试。刷新清空取消并隐藏当前会话分析，保留后台原文件，跨会话不可访问。

## 刷新与清空

### 后台保存期限

任务及其关联采集、打包、解析全部结束后保留 7 天，后台每分钟分批检查到期任务，删除任务原文件（含校验失败文件）、生成 APK、网页材料、数据包、解析报告及相关数据库记录。排队、执行中、尚未退出的工作进程和正在传输的下载受到保护，不会中途删除。运行期间新建关联操作会重新计算全部操作的结束时间；刷新、读取、下载和归档不会重置期限。服务停机期间不执行清理，启动后继续检查。

任务详情 `retention` 提供 `days=7`、`protected_active`、`finished_at` 和 `expires_at`（Unix 秒；仍有活动操作时后两者为 null）。旧任务没有独立结束时间时，首次升级以原记录最后更新时间回填。到期文件不可再次下载，用户已下载到自己电脑的副本不受影响。刷新隐藏的任务及会话过期的任务也按此规则清理。服务口令、签名密钥、环境配置不属于清理范围。

刷新按钮和整页刷新调用 `DELETE /api/jobs`，重置输入并取消当前会话未完成任务。记录在任务、构建、附件接口不可见，迟到写回不恢复显示；其他会话不受影响，后端原文件保留。演示文件接口已移除。


## 名称搜索与截图识别（可选）

新网页只需应用显示名称。截图先读名、人工确认或修改后再搜索；包名、签名和哈希不作为输入前置。

- `POST /api/icon-recognitions`：multipart `file`，必需 `Idempotency-Key`；仅识别截图并保留清理后的预览/图标，不检查SerpApi额度、不上传到搜图服务、不发起搜索。结果 `mode=recognize,result=recognized` 表示等用户确认名称，`search_attempts=0`。
- `POST /api/name-searches`：JSON `{name, recognition_id?}`，必需 `Idempotency-Key`；名称是1–100字符纯文本，规范化空白，拒绝控制符、网址及可改变固定范围的搜索运算符。`recognition_id` 可选，须属于当前会话、识别成功且未隐藏；用于保留原图、模型识别原名和用户修改后的名称。无图片时只需搜索服务配置，不调用模型或Lens。
- 两者共用 `GET /api/icon-searches/{id}`、取消、清空、所有权和7天保留；新增 `mode` 与名称任务的 `query_name`。同一个幂等键不能跨输入模式、名称或来源复用。识别和搜索分别计次，共用全服务单槽及滚动24小时20任务限制。
- 名称任务配置 Koodous 时先执行一次按名称的 API 查询（单页、最多20条）；若同时配置 SerpApi，再查询一次安卓下载页。未配置 Koodous 时执行样本库网页索引和安卓下载页两次固定网页查询。`catalog_status` 区分 `hit/no_record/failed/unconfigured`，保留 `count,returned,page_returned,truncated,next_page_available,coverage_complete` 及安全错误码；游标响应未提供总数时 `count=null`，不能变为0或无记录。接口失败不能记作无记录。
- API 样本候选 `category=sample_record,channel=koodous_api`，只投影名称、包名、版本、SHA-256与按SHA生成的固定详情URL。网页结果 `category=sample_index/download_page/web_candidate` 按实际域名、路径与文本依据分类；所有候选始终 `verified=false,downloadable=null`。API记录和资料页均不能直接 `collect`，不代表已取得原始APK或下载权限。
- 纯名称追踪保存 `source/name-search.json`，输入类型 `name_search`；关联截图时另复制原图/图标，并保留 `recognition_id`、原识别名称和 `query_name`。只输入、读取、识别或显示候选都不访问目标网站。
- `library_queries` 是供用户复制的库内名称检索式与官方外部入口，`queried=false`；不表明本服务有该库搜索/下载权限。平台未授权与未收录分开。

以下旧 `/api/icon-searches` 单步图标搜索合同为兼容保留；新网页不再使用其Lens流程。

MalShare 操作使用当前名称搜索的样本记录。能力 `icon_search.malshare_enabled` 表示已有私有配置。调用者提交候选 ID，服务从保留结果中取得哈希。

- `POST /api/icon-searches/{id}/candidates/{candidate_id}/malshare/lookup` 接收空 JSON 对象，使用原会话、CSRF 和幂等键，查询所选 SHA-256。
- 同一路径末尾改为 `download` 时，由用户显式请求取回已命中的样本。服务验证完整文件的 SHA-256 与 APK 结构后返回本地文件入口。下载权限、超时、校验和磁盘异常保留独立失败状态。
- `GET /api/icon-searches/{id}` 附带已保存的 MalShare 操作结果。读取搜索、刷新网页和取回已保存附件仅访问本机状态。使用 `file_url` 时仍需所属搜索会话。

MalwareBazaar 使用相同的会话、CSRF 和幂等规则。能力字段为 `icon_search.malwarebazaar_enabled`，本地查询或取回结果位于搜索结果的 `malwarebazaar` 字段。

- `POST /api/icon-searches/{id}/candidates/{candidate_id}/malwarebazaar/lookup` 查询所选记录的 SHA-256。
- `POST /api/icon-searches/{id}/candidates/{candidate_id}/malwarebazaar/download` 取回该库已命中的记录，校验从归档中解出的 APK。
- `GET /api/icon-searches/{id}/candidates/{candidate_id}/malwarebazaar/file` 获取当前会话中已验证并保留的文件。

所有接口沿用登录、CSRF、Host/Origin 与会话所有权检查。文件选择、预览和结果展示不访问第三方或候选站点；只有点击搜索的 POST 才授权本次第三方识图和搜索。扫码仍完全离线。

- `POST /api/icon-searches`：multipart `file`，必需 `Idempotency-Key`，返回 202 和任务 ID。仅接收单张有效图片，10 MiB / 2500 万像素；支持 PNG/JPEG/WebP/HEIF/AVIF/BMP/GIF/TIFF，拒绝动画、多页与 SVG。原图经方向校正、去元数据、缩放后交给模型；仅裁出的图标交给搜图服务。
- `GET /api/icon-searches/{id}`：状态 `running/completed/partial/failed/cancelled`、阶段、识别名称、置信度、请求/返回模型名、候选、错误与到期时间。`completed` 只表示搜索过程完成；候选始终 `verified=false`、`downloadable=null`。

  新记录的 `timing` 含 `started_at,stage_started_at,stage_elapsed_seconds,total_seconds`、已结束的 `stages[{stage,elapsed_seconds}]` 与 `requests[{stage,route,response_wait_seconds,body_read_seconds,total_seconds,http_status,error_code}]`。`route` 仅为 `direct/configured_proxy`，不公开代理地址。等待响应包含网络和供应商处理；旧记录没有该字段时仍可读取。`error_detail` 保留失败阶段、固定 code 及可得的 HTTP 状态。父进程终止搜索时补结算当前阶段，保留已发现候选；网页的本地计时不自行判定任务结束。
- `GET /api/icon-searches/{id}/image/{preview|icon}`：当前会话的干净 JPEG 预览。
- `POST /api/icon-searches/{id}/cancel`：取消本次工作进程。
- `POST /api/icon-searches/{id}/collect`：`candidate_id`、`tls_policy`，必需 `Idempotency-Key`。仅接受已结束且未过期、请求与来源校验通过的候选。明确选择才进入既有有界 HTTP / Chrome 采集；纯名称复制文本来源，有截图时另复制图像证据。搜索本身不创建下载成功记录。

供应商错误区分 `icon_provider_auth`（401）、`icon_provider_forbidden`（403）、`icon_provider_quota`（429）、`icon_provider_http`（其他 HTTP）、`icon_provider_timeout`、`icon_provider_tls`、`icon_provider_proxy`、`icon_provider_connection`、`icon_provider_response_invalid`、`icon_provider_incomplete`。错误响应可附安全整数 `error.http_status`；不透传供应商正文或异常文本，不自动重试。
- `DELETE /api/jobs` 同时取消并隐藏本会话搜索，不影响其他会话。重启只标记中断，不重试搜索。

全服务一个搜索槽位、每 24 小时最多 20 次提交、单次 180 秒/768 MiB 工作进程预算。先检查 SerpApi 免费方案且至少余 2 次；每次最多 1 次 Google Lens 搜图和 1 次名称 Android/APK 网页搜索，不自动分页/重试/购买额度。低置信度无名称时只搜图一次。各任务结果及图片结束后保留 7 天；运行中不删，刷新不延长。选择下载时独立复制来源，后续按下载任务保留期限处理。
