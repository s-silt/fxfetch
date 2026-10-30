# HTTP API v1

后端为唯一采集与构建执行端。前端使用同源 JSON API；图片上传使用 multipart 的 `file` 字段。所有响应默认禁止缓存。未在本文件列出的计划接口尚未提供。

## 会话与请求

`GET /api/session` 返回 `{authenticated, csrf_token, expires}`。`POST /api/login` 接收 `{password}`，成功设置 HttpOnly / SameSite=Strict 会话 Cookie；写请求必须具有与服务地址一致的 Origin。登录后所有写请求另需 `X-CSRF-Token`。`POST /api/logout` 使会话失效。单会话 8 小时，不因重新登录自动获得其他会话的任务。

## 任务数据包

每个执行中的普通下载任务在原工作流完成后离线封存一个独立 ZIP；采集工作流不会重放。原 APK / IPA 保持为单独的 artifact 下载，ZIP 仅含明确记录的网页材料、有限观察、清单和原包的外部引用，不含 APK / IPA 字节。ZIP 归档失败不会改写原任务结果或移除已保存 artifact。

`GET /api/jobs/{id}` 返回独立的 `data_package` 状态：`pending`、`building`、`ready`、`failed` 或 `unavailable`。就绪时带有 `filename`、`size`、`sha256` 和 `web_materials` 摘要；失败时提供 `reason_code`。旧任务没有该归档时显示 `unavailable`。`web_materials` 总是标注 `coverage: "partial"`。

`GET /api/jobs/{id}/data-package` 使用与任务/artifact 相同的会话认证、所有权和归档可见性规则；仅就绪归档可下载，返回 `application/zip`、附件文件名及 `Cache-Control: no-store`。读取、下载或刷新任务不会触发目标网络访问。

离线 CLI `fxfetch verify-data ARCHIVE.zip` 有界验证 ZIP 路径、清单、观察记录和归档材料哈希；不会解压归档。其成功仅说明 ZIP 内材料通过检查，不说明外部引用的 APK / IPA 字节已被本次验证。

Host 由启动参数明确允许。上传鉴权在 multipart 解析前完成，先有界收取最多 11 MiB 的请求，再交给解析器；文件最多 10 MiB、总上传时间 30 秒、单次解码。支持的静态图片格式在受限进程内验证和扫码，具体格式见下文。

任务和构建提交都需要 `Idempotency-Key`（8–128 个 ASCII 字符）。同会话相同键、相同参数返回原记录；不同参数返回 409。网络中断时重试原键，不要因为刷新生成新任务。

| 方法 / 路径 | 输入和返回 |
| --- | --- |
| `GET /api/capabilities` | HTTP/Chrome/构建能力及明确不可用原因；不探测目标 |
| `POST /api/preview` | `{url}` → `{kind,url,request_url,original_input,normalized,network_requests:0}` |
| `POST /api/qr-images` | multipart `file` → 图片 `id`、解码状态、哈希、候选、截断信息；无目标请求 |
| `GET /api/qr-images/{id}/thumbnail` | 当前会话图片的服务端 JPEG 缩略图，不返回原图元数据 |
| `POST /api/jobs` | `{url}` 或 `{image_id,candidate_id,url?}`；显式授权本次采集；202 返回 job |
| `GET /api/jobs` | 当前会话最新 50 个任务摘要；`active_builds` 为排队/运行构建数量 |
| `DELETE /api/jobs` | 认证、Origin、CSRF 后清空当前会话记录，停止未完成任务；重复调用幂等 |
| `GET /api/jobs/{id}` | 当前任务、结果、进度、产物、构建和可封装网页候选 |
| `POST /api/jobs/{id}/continue` | `{candidate_id}`；选择精确下载候选后创建独立子任务，202 返回 child job |
| `POST /api/jobs/{id}/cancel` | 取消排队或运行任务；重复操作幂等 |
| `POST /api/jobs/{id}/web-apk-builds` | `{candidate_id}`；手动点击后构建，202 返回 build |
| `GET /api/jobs/{id}/web-apk-builds/{build_id}` | 构建状态/结果/已登记产物 ID |
| `POST /api/jobs/{id}/web-apk-builds/{build_id}/cancel` | 取消构建进程树 |
| `GET /api/jobs/{id}/artifacts/{artifact_id}` | 已登记附件，文件名来自受控配置；无路径参数 |
| `GET /api/jobs/{id}/rejected-files/{file_id}` | 已完整保存但包校验失败的原文件；只读附件下载，不改变任务结果 |

二维码候选保留原始文本、严格解码结果与坐标；`url=null` 表示不可直接提交。多码必须选择。`truncated=true` 时须裁剪重新识别。提交的 `url` 是对所选二维码的编辑值，来源仍保留。原始 itms-services 文本作为 manifest 入口处理，不安装描述文件。

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

以下接口只使用该任务后台已就绪的 `fxfetch.task-evidence.v1` ZIP，不接受用户文件路径、URL、程序路径或执行参数。所有接口检查当前会话及父任务归属；父任务归档后返回 404。写接口沿用 Origin、CSRF；创建还必须提供 Idempotency-Key。

| 方法 / 路径 | 行为 |
| --- | --- |
| `POST /api/jobs/{id}/analyses` | 空 JSON `{}`，202 返回独立分析任务；同键重试返回同一记录 |
| `GET /api/jobs/{id}/analyses/{analysis_id}` | 读取状态，不执行分析 |
| `POST /api/jobs/{id}/analyses/{analysis_id}/cancel` | 取消排队或运行中的分析，阻止迟到成功发布报告 |
| `GET /api/jobs/{id}/analyses/{analysis_id}/report.zip` | 仅完成状态可下载；再次核对文件路径、大小及 SHA-256，附件响应 no-store |

`capabilities.web_analysis` 包含 `enabled,reason_code,online:false,timeout_seconds,queue_timeout_seconds`；不返回程序路径。任务详情增加 `analyses[]`，列表增加 `active_analyses`。状态为 `queued,running,completed,failed,not_analyzed,cancelled,interrupted`；公开记录含 ID、状态、时间、原因码和 `report_ready`，不含原报告、命令、日志或宿主路径。原采集结论保持不变，`coverage=partial`。

每个任务同时最多一个活动分析，全局排队最多 10 个，每任务累计最多 10 次；来源不可用、已有活动分析、额度超限返回 409，fxapk 未配置或不可用返回 503。无可分析材料为 `not_analyzed`，不能当成功。排队期限 600 秒，整个子进程（含校验、材料准备）执行期限 360 秒、内存 2 GiB；达到期限或取消终止进程树，不发布迟到报告。

提交不解析 ZIP，只固定已就绪归档的来源路径、大小和 SHA-256。完整校验及报告整理由后台受限进程完成；损坏或摘要不匹配会异步失败，而非在 POST 请求线程展开材料。

报告 ZIP 只含 `analysis.json` 与 `report/input.json`，原件按回执映射从独立数据包回查；不包含 APK/IPA、原始 ZIP 或执行日志，回执中的程序路径和命令不导出。原生报告仍可能包含敏感线索及 `meta.web_evidence.source_dir` 主机材料目录，不在网页中直接渲染；普通状态 JSON 不暴露这些内容。

服务重启将未完成分析置为 `interrupted/service_restarted`，不自动重试。刷新清空取消并隐藏当前会话分析，保留后台原文件，跨会话不可访问。

## 刷新与清空

刷新按钮和整页刷新调用 `DELETE /api/jobs`，重置输入并取消当前会话未完成任务。记录在任务、构建、附件接口不可见，迟到写回不恢复显示；其他会话不受影响，后端原文件保留。演示文件接口已移除。
