# HTTP API v1

后端为唯一采集与构建执行端。前端使用同源 JSON API；图片上传使用 multipart 的 `file` 字段。所有响应默认禁止缓存。未在本文件列出的计划接口尚未提供。

## 会话与请求

`GET /api/session` 返回 `{authenticated, csrf_token, expires}`。`POST /api/login` 接收 `{password}`，成功设置 HttpOnly / SameSite=Strict 会话 Cookie；写请求必须具有与服务地址一致的 Origin。登录后所有写请求另需 `X-CSRF-Token`。`POST /api/logout` 使会话失效。单会话 8 小时，不因重新登录自动获得其他会话的任务。

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

二维码候选保留原始文本、严格解码结果与坐标；`url=null` 表示不可直接提交。多码必须选择。`truncated=true` 时须裁剪重新识别。提交的 `url` 是对所选二维码的编辑值，来源仍保留。原始 itms-services 文本作为 manifest 入口处理，不安装描述文件。

网址输入可直接使用裸域名、`www` 域名和路径：缺少协议时补 `https://`，`//host/path` 补为 HTTPS，`https:/host/path` 补齐斜杠；已有 `http://` 保留。查询参数、转义和片段不因补齐被改写。前端提交前使用同一个离线 preview 规范化规则；preview 不解析 DNS、不访问目标。直接提交 jobs 也应用相同规则，发生补齐时 `input.original_input` 保存原始文本，`input.entry_url` 保存实际入口。`javascript/data/file/ftp/intent` 等显式其他协议不改写成 HTTPS；既有严格 `itms-services` manifest 入口仍单独处理。补齐不代表地址已通过公网连接检查。

## 状态与结果

采集状态为 `queued → running → completed/cancelled`；服务重启会将遗留排队/运行任务置为 `interrupted`，不重放入口。源输入落盘失败也置 `interrupted`，绝不执行未固化的输入。

`outcome` 与运行状态分开：`downloaded`、`not_found`、`blocked`、`failed`；未执行为 null。`not_found` 仅代表本次完整静态范围内无包。脚本、挑战、多个未选候选、超限和错误都不能据此回退 IPA。中间发现事件的 outcome 可为 null。

`result.offline` 返回 `{available,bytes,coverage,reasons}`，仅说明可加入 APK 的局部静态内容。已保存响应的正文、头、宿主文件路径和其他私有材料不通过任务 JSON 公开。

构建状态为 `queued → running → built/failed/disabled/cancelled`，重启为 `interrupted`。构建成功不修改原采集 outcome。`origin=downloaded_original` 为下载原包，`origin=generated_webview` 为生成包。

只有任务结束、没有下载原包、且存在合法网页候选时可构建。客户端提交候选 ID，不提交任意网页、路径、包名、脚本或签名选项。打包交付仅一个 APK；离线资源只在 APK 内，不附带证据清单。

错误有两种兼容格式：`{error:{code,message?}}` 或 `{detail:code}`。未认证 401，Origin/CSRF 403，不属于当前会话的对象 404，幂等/队列冲突 409，过大上传 413，忙碌/登录限流 429，构建能力缺失 503。

前端每个活动任务按 1.5–5 秒自适应轮询，隐藏页面或无活动任务停止；轮询和恢复只读状态，不能重启采集。会话失效后停止请求并重新登录。

### 下载候选继续

任务详情的 `download_candidates` 为 `{id,url,kind,source_url,label,child_job_id}` 列表，仅取自该任务最终未决的 `result.selection_candidates`。候选 ID 绑定父任务和地址，客户端不能用任意 URL 替换。旧记录缺少精确选择集时列表为空，`download_selection_unavailable=true`，需重新提交入口。

`POST /api/jobs/{id}/continue` 需要所属会话、Origin、CSRF 和 Idempotency-Key。父任务须已 completed 且未取得原包。一个候选最多有一个子任务，一个父任务同时最多有一个 queued/running 子任务；其结束后可选其他候选。`continuation_active_child_job_id` 及兼容字段 `continuation_child_job_id` 只指当前活动子任务，各候选自己的 `child_job_id` 保留历史结果。

子任务 `input` 保存 `parent_job_id,parent_entry_url,selected_candidate_id,source_url,selected_candidate_kind,continuation_depth`；`session_continuity=independent_request_session,cookies_inherited=false`。不重新访问父入口、不导入父 Cookie，保留父结论；最多 4 层并拒绝去片段后的祖先循环，查询参数仍保留。每个子任务重新使用普通有界采集预算，全部清空时父子一并隐藏及取消。活动冲突 `continuation_active`、重复选择 `candidate_already_selected`、深度/循环错误均明确拒绝。

`flutter_source_download_limit` 表示明确引用的 Flutter 主脚本超过受控读取上限，`flutter_runtime_required` 表示仍需运行页面；两者均不能触发 IPA 回退。`device_verification_required` 的 outcome 为 blocked。`text_charset_conflict,text_charset_unsupported,text_decode_failed` 为编码覆盖缺口，不以乱码快照代替。

当前 Flutter 启动脚本上限 256 KiB，主脚本 64 MiB；任务累计网页正文 128 MiB，普通 HTML 8 MiB。大脚本保存后以 64 KiB 分块扫描，跨块 URL/UTF-8 保留；EOF 完整性、编码、取消和绝对链路截止时间检查通过后才发布候选。网络保护与本地静态字面量校验分开，无效的无关 URL 常量不使整份脚本解析失败。

`challenge_detected` 根据验证提示与控件或专用挑战页面结构判断，不按全源码关键词命中；脚本依赖但未观察到实际门槛时仍为 `browser_required`。这些原因码均不是站点性质或合法性结论。

Android Chrome 可从当前渲染 DOM 的明确文件锚点继续下载，跳转事件使用 `mechanism=rendered_package_link`、`same_browser_session=true`；仍通过原有连接前守卫，不重放已尝试的文件票据。页面存在验证提示但已下发文件链接时，`challenge_detected` 保留 `verification_passed=false` 与 `continuation=explicit_dom_package_link`。文件最终 `downloaded` 只确认原包取得，不能解释为验证通过；文件地址自身拒绝时仍是 `blocked`。无明确链接时维持原有受阻结果。

验证页面内联脚本中明确的字面量 HTML GET 地址也可作为内容页候选，`kind=http,action=script_content_link`；跳转记录 `mechanism=script_content_link,same_browser_session=true`，验证观察使用 `continuation=explicit_script_content_link`。页面和脚本均不执行额外受保护函数，不求值动态地址，也不复现 POST。多个不同内容地址进入既有候选选择接口；`browser_content_loop` 表示循环已停止，`browser_script_limit` 表示静态提取预算不足，两者都不能解释为没有 APK。

采集优先使用 HTTP；需要动态页面或遇 403/429/502/503 时才尝试一次 Android Chrome。结果 `landing.http_resolution` 保存 HTTP 结果与 `new_browser_session=true,cookies_inherited=false`，HTTP hops 和 bodies 仍保留，两个阶段共享原任务预算。前端通过零目标请求的 `/api/preview` 识别 APK/IPA 输入直链，再提供普通外部下载链接；点击不调用 `/api/jobs`，服务无法确认客户端文件是否完整，因此不会产生 `downloaded` 任务。候选直链按钮也不继承采集会话，不保证跨设备有效。

演示文件接口已移除。右上「刷新」和浏览器整页刷新调用 `DELETE /api/jobs`，同时重置输入和前端待处理状态。已清空记录在列表、任务、构建、附件接口均不可见；工作线程可完成取消写回但不会让记录重新出现。其他会话不受影响，已落盘原始文件保留在后端。

## 服务端网络与离线字体配置

### 任务时限与动态进度

`GET /api/capabilities` 的 `task_limits` 提供 `collection_seconds=600`、`build_seconds=900`、`queue_budget=separate_same_duration`。生产 `execution_limit_method=isolated_process_tree`，并分别提供 `collection_limit_method`、`build_limit_method`；内部注入测试组合标为 `mixed_or_injected`。这些值由服务端决定，网页不能关闭期限。排队各自最多等待 600/900 秒，开始执行后另计相同预算；整项采集共用一个执行期限，不因重定向、APK/IPA 切换或资源解析重置。

生产采集和构建在受限独立进程执行，到期/取消终止整个进程树；结果为 `failed/task_timeout`、构建 `failed/build_timeout`，排队到期 `queue_timeout`。排队超时覆盖为 `not_started`，执行超时为 `partial`，均不表示没有 APK。附件与终态在同一事务发布，已超时或取消的任务不发布迟到成功附件。仅内部测试注入路径标记 `injected_test_callable`，HTTP 不提供该选择。

`GET /api/jobs/{id}` 的任务及 `builds[]` 各自包含 `progress`。保留兼容的最新 `event`，增加 `events`（最多 128 项）、`started_at`、`deadline_at`、`timeout_seconds`、`execution_limit_method`；排队时返回 `queue_deadline_at`、`queue_timeout_seconds`。时间戳为 Unix 秒，执行监督使用单调时钟；客户端倒计时只供估计，必须以后端终态确认停止。每个事件有递增 `seq` 和 `at`，中间采样合并后序号可不连续。

采集事件包括 `request/response_received/redirect/page_received/download_candidate/download_started/download_progress/response_progress/response_complete/file_verifying/file_verified/challenge_detected/browser_required`，终态包含 `task_completed/task_timeout/cancelled/queue_timeout`。跳转携带 `from_url,to_url,mechanism`；传输携带 `received_bytes,total_bytes,complete`，总长度未知时为 null，不显示百分比。`download_started` 只表示实际收到了未校验包格式字节，`complete=true` 只表示该响应传输结束，`file_verified` 才表示现有文件检查通过；所有候选与验证阻挡仍保留其独立结果。

构建阶段包括 `building/build_preparing/build_resources/build_compiling/build_signing/build_verifying/build_saving`，最终按 `built/failed/disabled/build_timeout/cancelled` 展示。UI 每 1.5–5 秒读取现有任务接口，隐藏或结束时停轮询；后台下载进度最多每秒更新一次（另保留起止样本），连续样本合并。接口不会因读取进度而访问目标。

客户端不能覆盖绑定地址、允许网段、DNS、代理或字体文件。服务目录 `server.json` 只接受 `host,port,allowed_networks,proxy_host,proxy_port`，仅允许具体 RFC1918/IPv4 回环绑定和私网/回环子网；HTTP 入口按真实 socket peer 检查，不信任转发头。目标出站 DNS 默认 AliDNS 223.5.5.5，服务/传输失败才回退 DNSPod 119.29.29.29；代理只能由服务端明确指定回环 CONNECT 地址，并仅作为候补：默认直连，仅初始传输失败且未观察到响应/会话推进时尝试一次独立代理，共享采集总时限与预算。访问控制、证书、公网守卫失败及覆盖缺口不会触发切换。`capabilities.network_policy` 声明默认模式和候补是否配置；结果 `network_mode`、`network_attempts` 保存每次完整结果，进度事件 `network_attempt_started/network_fallback/network_attempt_completed` 带模式与独立会话标记，原直连失败不会被成功代理结果删除。

上传图片的实际格式白名单扩展为 PNG/JPEG/WebP/HEIF/BMP/GIF/TIFF/AVIF，拒绝动画和多帧；仍受上传、像素、内存及子进程超时限制。授权下载流程有界发现网页明确引用图片并本机识别二维码，图片扫码状态、候选和覆盖缺口与原包四态分别记录。图片二维码不是可下载包的证明。

可选 `offline-font.json` 固定字段为 `path,license_path,size,sha256,git_blob_sha1,license_sha256`，仅管理员本机配置；加载器校验固定 Noto Sans CJK SC Sans2.004 官方元数据和实际字体/许可内容，拒绝重解析点和非绝对路径。构建结果 `font_applied` 与 `font_reason` 记录是否实际应用、未配置、无正文、预算不足或校验失败；字体应用不改变原采集 outcome。仅同源固定本地字体路径可加载，离线页仍禁止脚本、表单和网络请求。

构建成功结果新增 `offline_content_kind`（`site_snapshot` / `connection_page`）、`offline_content_reason`、`resource_bytes` 和 `resource_files`。资源字节数为 APK 内离线 HTML/CSS/图片/字体及其完整许可的未压缩总量，不含 config/DEX/Manifest/签名；成品体积使用 `size`。资源统一上限 28 MiB，生成 APK 最终上限 30,000,000 字节。无有效网站快照时生成普通离线联网指引页，不将其标记为网站快照；原采集失败状态保持不变。

`capabilities.chrome` 在后台通过只读控制通道核验已配置的 Android worker，每个服务实例最多一个进行中的探测，完成结果缓存 30 秒。API 不等待慢探测：`checking=true` 表示仍在检查，`cached=true` 表示展示已有结果；这些字段和缓存都不是任务放行凭据。前端有限轮询检查状态，隐藏页面或登出即停止，刷新清空记录不依赖探测成功。探测不导航页面、不启动目标任务；实际采集必须再次取得包含独立期限和实时网络约束的任务 lease。`android-worker.json` 为后端私有配置，不接受 HTTP 客户端修改。动态进度新增 `browser_preparing`、`browser_started`、`browser_connection_blocked` 和实际请求计数；所有数据仍按纯文本展示。

当前本机部署按用户最新要求设置 `proxy_host=null`，仅直连；上面的候补字段为兼容协议，不能解释为当前已启用代理。内部 Chrome 连接守卫只将公开目标地址固定后直连，不接上游代理。
