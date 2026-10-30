"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const activeStates = new Set(["queued", "running", "building", "awaiting_human", "awaiting_selection"]);
  const labels = {queued:"排队中",running:"采集中",building:"正在打包",completed:"采集结束",cancelled:"已取消",interrupted:"已中断",awaiting_selection:"等待选择",awaiting_human:"等待本机处理",downloaded:"已取得原包",not_found:"本次范围内未找到包",blocked:"访问受阻",failed:"未完成",built:"APK 已生成",disabled:"暂不可用",partial:"覆盖不完整",complete:"本次范围已完成",not_started:"尚未执行"};
  const messages = {
    dns_configuration_invalid:"后端 DNS 配置无效，请联系主机管理员检查支持的服务商名称。",
    analysis_unavailable:"后端 fxapk 未配置或不可用，请联系主机管理员。",analysis_source_unavailable:"数据包尚未就绪或不可用，不能启动分析。",
    analysis_active:"本任务已有离线分析正在进行，请等待结束。",analysis_queue_full:"离线分析队列已满，请稍后重试。",analysis_limit:"此任务的分析次数已达上限。",
    analysis_timeout:"离线分析达到时间限制，已停止，未交付完整报告。",analysis_queue_timeout:"分析排队超时，尚未执行。",
    fxapk_timeout:"fxapk 分析超时，未交付完整报告。",fxapk_executable_unavailable:"后端 fxapk 程序不可用。",fxapk_analysis_failed:"fxapk 分析失败，后台保留已有材料。",
    no_analyzable_web_material:"数据包没有可供分析的网页正文或请求材料。",service_restarted:"服务已重启，未完成的任务已中断；不会自动重跑。",
    fxapk_report_contract_invalid:"分析报告未通过格式校验，不能下载。",fxapk_report_unavailable:"未取得有效分析报告。",fxapk_report_empty:"分析未产生有效网页报告。",
    invalid_credentials:"密码不正确，请重新输入。",login_rate_limited:"尝试次数较多，请稍后再登录。",
    authentication_required:"会话已过期，请重新登录。",invalid_csrf:"登录状态已变化，请刷新后重新登录。",
    invalid_url:"请检查网址格式，可直接粘贴域名或完整的 HTTP/HTTPS 网址。",unsupported_input:"此入口协议或类型暂不支持，请使用 HTTP/HTTPS 网页或有效的 IPA 描述文件入口。",
    invalid_input:"请添加有效的网址或选择二维码入口。",request_too_large:"上传内容过大，请选择较小的图片。",
    image_too_large:"图片超过 10 MiB，请压缩后再试。",decoder_busy:"图片解码器正在处理其他图片，请稍后重试。",
    image_queue_full:"暂存图片数量已满，请稍后再试。",queue_full:"任务队列已满，请稍后提交。",
    qr_truncated:"图片中二维码过多，请裁剪后重新上传。",invalid_selection:"请选择一个有效的二维码入口。",
    idempotency_conflict:"此操作内容已变化，请刷新任务列表核对后再提交。",not_found:"此任务已不可用，或不属于当前会话。",
    task_timeout:"采集已达到时间限制并停止，结果不完整；已取得的记录保留，不能据此判断没有 APK。",build_timeout:"打包已达到时间限制并停止，未交付完整 APK；原采集结果保留。",queue_timeout:"排队已超时并停止，本次操作未执行。",
    browser_worker_scope_unsupported:"该网页使用了尚未支持的后台脚本，本次采集未完成，不能据此判断没有 APK。",
    build_unavailable:"本机打包工具尚未就绪。",invalid_build_source:"此任务没有可用于打包的网页入口。",
    target_not_public:"目标解析结果或地址未通过公网检查，已停止该目标连接；不能据此判断是否有 APK。",dns_failed:"目标域名解析失败。",
    dns_unsafe_answer:"DNS 返回非公网或特殊地址，未连接该目标；不能据此判断是否有 APK。",
    dns_tls_verification_failed:"DNS 服务的证书校验失败，未取得可信解析结果；未连接该目标。",
    dns_nxdomain:"DNS 服务返回域名不存在；本次无法连接，不能据此判断是否有 APK。",
    dns_no_addresses:"DNS 未返回与查询匹配的地址；本次无法连接，不能据此判断是否有 APK。",
    dns_invalid_response:"DNS 响应格式或完整性检查失败，未使用该响应连接目标。",
    dns_diagnostics_unavailable:"DNS 诊断记录不可用，无法确认解析详情。",
    chain_timeout:"当前下载链路已达到时间限制，本次采集未完成。",
    browser_transport_failed:"浏览器连接或传输未完成；不能据此判断是否有 APK。",
    browser_required:"页面内容依赖脚本，当前静态采集尚未完成；Chrome 动态采集未启用。",
    browser_guard_unavailable:"Chrome 连接前防护尚未验收，浏览器采集暂不可用。",
    browser_worker_unavailable:"Android Chrome 环境未能连接，本次采集已停止。",
    browser_worker_start_timeout:"Android 启动超时，本次尚未访问目标网页。请检查本机运行状态后重新提交。",
    browser_worker_configuration:"后端 Android Chrome 配置无效，请检查本机服务配置。",
    browser_dynamic_incomplete:"已运行页面，但尚未取得可验证的原始应用包；动态流程仍有覆盖缺口。",
    browser_network_error:"Chrome 页面请求失败，尚未取得完整应用包。",
    browser_http_error:"网页或其依赖资源返回 HTTP 错误，尚未取得原始应用包；不能据此判断没有 APK。",
    browser_content_loop:"内容页地址形成循环，已停止重复访问，尚未取得原始应用包。",
    browser_script_limit:"脚本内容超过本次提取限额，采集覆盖不完整。",
    browser_download_not_intercepted:"页面下载未能安全接管，本次已停止；未将不完整文件作为成品。",
    browser_navigation_failed:"Chrome 跳转未完成，已保留当前采集记录。",
    flutter_runtime_required:"已识别 Flutter 网页，仍需运行页面才能确认下载流程；当前没有确认原包地址。",
    flutter_source_download_limit:"已识别 Flutter 网页，但应用脚本超过本次脚本读取预算，尚未确认原包地址。可以使用下方的打包 APK。",
    flutter_source_limit:"Flutter 页面资源超过本次读取上限，尚未确认原包地址。",
    flutter_main_reference_unknown:"Flutter 启动配置没有可确认的主脚本地址，尚未确认原包地址。",
    package_verified:"已取得完整应用包，文件完整性检查通过。",
    archive_invalid:"文件已接收，但应用包结构或完整性校验失败，未计为成功取得原包。",
    archive_unsupported:"文件已接收，但其归档格式无法完成校验，未计为成功取得原包。",
    archive_limit:"文件已接收，但包校验超过检查限额，未计为成功取得原包。",
    archive_ambiguous:"文件已接收，但应用包结构存在歧义，未计为成功取得原包。",
    landing_candidate_discovered:"已从页面下载配置找到真实地址，继续验证应用包。",
    tls_handshake_failed:"下载节点的 TLS 连接中断，本次节点未取得文件。",tls_verification_failed:"目标证书校验失败，已停止访问。",
    tls_policy_continuation_unconfirmed:"证书错误后的继续操作未得到确认，请查看数据包中的缺口记录。",tls_policy_restore_failed:"证书处理设置的清理未得到确认，已保留缺口记录。",browser_subresource_tls_policy_unavailable:"部分页面资源的证书错误未能继续处理，采集覆盖不完整。",
    browser_tls_policy_unavailable:"当前 Chrome 无法完成逐次证书错误处理，已停止本次浏览器访问。",browser_tls_event_invalid:"证书错误事件范围无法确认，已停止访问。",browser_tls_error_unsupported:"证书错误类型不在可处理范围，已停止访问。",browser_tls_unpermitted_error:"证书错误未关联到当前允许的请求，已停止访问。",browser_tls_policy_limit:"证书错误处理达到本次限额，已停止访问。",
    challenge_detected:"观察到实际验证页面或访问控制，尚未取得原包；此状态不能判断网站性质。",
    device_verification_required:"下载页要求真实手机设备验证，当前尚未取得原包。可手动打包联网入口后在手机上访问。",
    candidate_selection_required:"发现多个下载候选，请选择一个地址继续。",
    candidate_already_selected:"此地址已有后续任务，请查看该地址的任务。",continuation_active:"已有后续任务正在执行，请等待结束后选择其他地址。",invalid_continuation:"此任务当前不能继续下载。",continuation_limit:"后续任务次数已达上限，请保留结果。",continuation_cycle:"所选地址会重复已有入口，已停止。",
    text_charset_conflict:"页面编码声明冲突，已停止转换，避免文字乱码。",text_charset_unsupported:"页面声明的文字编码暂不支持，已保留原始内容。",text_decode_failed:"页面文字编码无效，未将乱码内容打包。",
    static_scope_complete:"已完成本次静态采集范围。",network_error:"与本地主机的连接中断，请重试。",
    proxy_failed:"本机代理未能建立连接，本次尝试已停止。",proxy_timeout:"本机代理连接超时，本次尝试已停止。",
    network_failed:"目标连接失败。",network_timeout:"目标连接或读取超时，本次采集未完成。",dns_timeout:"域名解析超时，本次采集未完成。",
    page_qr_incomplete:"页面图片二维码检查未完成，尚不能确定是否有应用包。",
    landing_mirrors_failed:"页面声明的下载镜像均未取得有效应用包。",landing_static_decode_failed:"落地页下载配置解析失败，尚未确定包地址。",
    landing_pattern_ambiguous:"落地页下载配置存在歧义，需要人工选择。",landing_resource_not_same_origin:"落地页依赖超出允许的同源资源范围。",
    transfer_failed:"下载传输中断，文件未通过完整性检查。",length_mismatch:"下载长度不符，文件不完整。",http_status:"目标返回异常HTTP状态，本次采集未完成。",
    http_access_control:"目标返回访问控制响应，内容仍未知。",page_qr_access_control:"页面图片受访问控制限制，二维码内容仍未知。",
    read_timeout:"读取目标超时。",timed_out:"处理超时。",
    cancelled:"操作已取消。",storage_failed:"本机文件写入失败。",internal_error:"处理未完成，请查看后端主机状态。",
    image_invalid:"文件不是受支持的图片，请选择手机截图或常用图片。",invalid_image:"文件不是有效图片或不支持此格式。",lan_access_only:"仅允许已配置的局域网设备访问。",
    limit_exceeded:"图片处理超过资源限制，请缩小或裁剪后重试。",no_code:"未识别到二维码。",
    no_supported_url:"二维码中没有可使用的网址。",candidate_not_package:"候选响应并非所需应用包。",
    scratch_soft_budget_exceeded:"构建超出临时空间预算，已停止。",scratch_insufficient_space:"本机临时空间不足。",
    signing_failed:"APK 签名失败。",signature_verification_failed:"APK 签名验证未通过。",
    build_command_failed:"本机构建工具执行失败。",build_timed_out:"APK 构建超时。"
  };
  const state = {csrf:null, authenticated:false, capabilities:null, jobs:[], current:null, job:null, image:null,
    selectedQR:null, previewURL:null, pendingJob:null, pendingBuilds:new Map(), pendingAnalyses:new Map(), pendingContinuations:new Map(), selectedContinuations:new Map(), continuationTls:new Map(), progressExpanded:new Set(), submitting:false, uploading:false,
    epoch:0, clearing:false, mutations:new Set(), pollTimer:null, pollController:null, polling:false, pollDelay:1500, loading:false, activeBuildJobs:new Set(),
    capabilityTimer:null, capabilityController:null, capabilityGeneration:0, capabilityAttempts:0, capabilityDeadline:0, capabilityStatus:"idle"};

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }
  function friendly(code) { return messages[code] || (code?.startsWith("landing_") ? "落地页下载配置超出当前静态解析范围，尚未确定包地址。" : "处理未完成，请稍后重试或查看本机状态。"); }
  function notice(text, error = false) {
    $("notice").textContent = text;
    $("notice").classList.toggle("error", error);
    $("notice").hidden = !text;
  }
  function rememberJob(id) {
    try { if (id) localStorage.setItem("fxfetch.job-id", id); else localStorage.removeItem("fxfetch.job-id"); } catch { /* Storage may be disabled. */ }
  }
  function stopPolling() {
    clearTimeout(state.pollTimer);
    state.pollTimer = null;
    if (state.pollController) state.pollController.abort();
  }
  function updateTLSChoice() {
    $("tls-policy-summary").textContent = $("tls-policy").value === "strict" ? "证书：严格验证" : "证书：自动处理";
  }
  function signedOut(expired = false) {
    clearDirectLink();
    $("tls-policy").value = "auto";
    $("advanced-settings").open = false;
    state.continuationTls.clear();
    state.authenticated = false;
    state.csrf = null;
    state.jobs = [];
    state.current = null;
    state.job = null;
    state.pendingJob = null;
    state.pendingBuilds.clear(); state.pendingAnalyses.clear(); state.pendingContinuations.clear(); state.selectedContinuations.clear(); state.progressExpanded.clear();
    state.activeBuildJobs.clear();
    stopPolling();
    stopCapabilityPolling();
    state.capabilities = null; state.capabilityStatus = "idle";
    clearImage();
    $("url").value = "";
    $("workspace").hidden = true;
    $("logout").hidden = true;
    $("login-panel").hidden = false;
    if (expired) notice("会话已过期，请重新登录。当前操作不会自动重新提交。", true);
  }
  function api(path, options = {}) {
    const pending = request(path, options);
    if ((options.method || "GET") === "POST" && path !== "/api/login" && path !== "/api/logout") {
      state.mutations.add(pending);
      pending.then(() => state.mutations.delete(pending), () => state.mutations.delete(pending));
    }
    return pending;
  }
  async function request(path, options = {}) {
    const controller = new AbortController();
    const external = options.signal;
    const abort = () => controller.abort();
    if (external) external.addEventListener("abort", abort, {once:true});
    if (external && external.aborted) controller.abort();
    const timeout = setTimeout(abort, options.upload ? 30000 : 15000);
    const headers = new Headers(options.headers || {});
    const method = options.method || "GET";
    if (method !== "GET" && state.csrf) headers.set("X-CSRF-Token", state.csrf);
    let body = options.body;
    if (body && !(body instanceof FormData)) { headers.set("Content-Type", "application/json"); body = JSON.stringify(body); }
    try {
      const response = await fetch(path, {method, headers, body, credentials:"same-origin", signal:controller.signal, cache:"no-store"});
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const code = payload.error?.code || (typeof payload.detail === "string" ? payload.detail : "request_failed");
        if (response.status === 401 && path !== "/api/login") signedOut(true);
        const error = new Error(friendly(code));
        error.code = code;
        error.status = response.status;
        throw error;
      }
      return payload;
    } catch (error) {
      if (error.status) throw error;
      if (external?.aborted) { const aborted = new Error("cancelled"); aborted.code = "aborted"; throw aborted; }
      const network = new Error(messages.network_error); network.code = "network_error"; throw network;
    } finally {
      clearTimeout(timeout);
      if (external) external.removeEventListener("abort", abort);
    }
  }
  function idempotencyKey() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return Array.from(crypto.getRandomValues(new Uint8Array(24)), (value) => value.toString(16).padStart(2,"0")).join("");
  }
  function bytes(value) { if (!Number.isFinite(value)) return ""; return value >= 1048576 ? `${(value/1048576).toFixed(1)} MiB` : `${(value/1024).toFixed(1)} KiB`; }
  function busy(job) { return !!job && (activeStates.has(job.state) || FxfetchDataPackage.isPending(job) || FxfetchAnalysis.isPending(job) || (job.builds || []).some((build) => activeStates.has(build.state))); }
  function hasActive() { return state.jobs.some((job) => activeStates.has(job.state) || job.active_builds > 0 || job.active_analyses > 0) || busy(state.job) || state.activeBuildJobs.size > 0; }
  function schedule() {
    clearTimeout(state.pollTimer);
    if (!state.authenticated || state.clearing || document.hidden || !hasActive()) return;
    state.pollTimer = setTimeout(poll, state.pollDelay);
  }
  async function poll() {
    if (state.polling || !state.authenticated || document.hidden) return;
    state.polling = true;
    state.pollController = new AbortController();
    try {
      await loadJobs(false, state.pollController.signal);
      state.pollDelay = Math.min(5000, state.pollDelay + 500);
    } catch (error) { if (error.code !== "aborted" && state.authenticated) notice(error.message, true); state.pollDelay = 5000; }
    finally { state.polling = false; state.pollController = null; schedule(); }
  }
  function renderCapabilities() {
    const cap = state.capabilities;
    const region = $("capabilities");
    region.replaceChildren();
    const chromeText = state.capabilityStatus === "checking" ? "HTTP 采集可用 · 正在检查 Android Chrome…" : state.capabilityStatus === "pending" ? "HTTP 采集可用 · Android Chrome 就绪检查尚未完成" : state.capabilityStatus === "unavailable" ? "HTTP 采集可用 · Android Chrome 状态暂不可用" : cap?.chrome?.enabled ? "HTTP 下载与 Android Chrome 动态采集已就绪" : "HTTP 采集可用 · Android Chrome 尚未就绪";
    region.append(node("p", "", chromeText));
    region.append(node("p", "", "默认直连"));
    region.append(node("p", "", !cap ? state.capabilityStatus === "checking" ? "正在检查本机 APK 打包能力…" : "本机 APK 打包状态暂不可用。" : cap.web_apk?.enabled ? "本机 APK 打包已就绪" : "本机 APK 打包尚未就绪，请由后端主机配置工具链。"));
    region.append(node("p", "", cap?.web_analysis?.enabled ? "fxapk 离线分析已配置，点击分析才会执行。" : "fxapk 离线分析尚未启用；不影响采集和数据包下载。"));
  }
  function stopCapabilityPolling() {
    clearTimeout(state.capabilityTimer); state.capabilityTimer = null;
    state.capabilityGeneration += 1;
    state.capabilityController?.abort(); state.capabilityController = null;
  }
  async function pollCapabilities() {
    if (!state.authenticated || document.hidden || state.capabilityController || state.capabilityStatus !== "checking") return;
    if (state.capabilityAttempts >= 16 || Date.now() >= state.capabilityDeadline) {
      state.capabilityStatus = state.capabilities?.chrome?.checking ? "pending" : "unavailable";
      renderCapabilities(); return;
    }
    clearTimeout(state.capabilityTimer); state.capabilityTimer = null;
    const generation = state.capabilityGeneration;
    const controller = new AbortController(); state.capabilityController = controller;
    state.capabilityAttempts += 1;
    try {
      const capabilities = await api("/api/capabilities", {signal:controller.signal});
      if (generation !== state.capabilityGeneration || !state.authenticated || document.hidden) return;
      state.capabilities = capabilities;
      state.capabilityStatus = capabilities.chrome?.checking ? "checking" : "ready";
      renderCapabilities();
      if (!state.clearing) renderJob();
    } catch (error) {
      // Readiness failure never cancels or prevents the independent clear action.
      if (generation === state.capabilityGeneration && state.authenticated && error.code !== "aborted") renderCapabilities();
    } finally {
      if (state.capabilityController === controller) state.capabilityController = null;
      if (generation === state.capabilityGeneration && state.authenticated && !document.hidden && state.capabilityStatus === "checking") {
        state.capabilityTimer = setTimeout(pollCapabilities, 4000);
      }
    }
  }
  function startCapabilityPolling() {
    stopCapabilityPolling();
    state.capabilities = null; state.capabilityStatus = "checking";
    state.capabilityAttempts = 0; state.capabilityDeadline = Date.now() + 70000;
    renderCapabilities();
    void pollCapabilities();
  }
  async function authenticated(session) {
    state.csrf = session.csrf_token;
    state.authenticated = true;
    state.pollDelay = 1500;
    $("password").value = "";
    $("login-panel").hidden = true;
    $("workspace").hidden = false;
    $("logout").hidden = false;
    notice("");
    const clearing = clearRecords(false);
    startCapabilityPolling();
    await clearing;
  }
  async function loadJobs(restore = false, signal) {
    const epoch = state.epoch;
    const response = await api("/api/jobs", {signal});
    if (!state.authenticated || epoch !== state.epoch || state.clearing) return;
    state.jobs = response.jobs || [];
    for (const job of state.jobs) if (job.active_builds > 0) state.activeBuildJobs.add(job.id);
    const desired = state.current;
    state.current = state.jobs.some((job) => job.id === desired) ? desired : state.jobs[0]?.id || null;
    const picker = $("job-picker");
    picker.replaceChildren();
    if (!state.jobs.length) picker.append(new Option("还没有任务", ""));
    for (const job of state.jobs) {
      const date = new Date(job.created * 1000).toLocaleString("zh-CN", {month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit"});
      picker.append(new Option(`${date} · ${labels[job.state] || "任务"}`, job.id));
    }
    picker.value = state.current || "";
    rememberJob(state.current);
    if (state.current) await loadCurrent(signal); else { state.job = null; renderJob(); }
    for (const id of [...state.activeBuildJobs]) {
      if (id === state.current) continue;
      const background = await api(`/api/jobs/${encodeURIComponent(id)}`, {signal});
      if (!(background.builds || []).some((build) => activeStates.has(build.state))) state.activeBuildJobs.delete(id);
    }
    schedule();
  }
  async function loadCurrent(signal) {
    const id = state.current;
    const epoch = state.epoch;
    if (!id || state.clearing) return;
    const job = await api(`/api/jobs/${encodeURIComponent(id)}`, {signal});
    if (state.current !== id || !state.authenticated || epoch !== state.epoch || state.clearing) return;
    state.job = job;
    if ((job.builds || []).some((build) => activeStates.has(build.state))) state.activeBuildJobs.add(id);
    else state.activeBuildJobs.delete(id);
    renderJob();
  }
  function badge(text, tone) { return node("span", `badge ${tone || ""}`, text); }
  function downloadFile(job, artifact) {
    const card = node("div", "file-card");
    const info = node("div", "file-info");
    info.append(node("strong", "", artifact.filename || "应用文件"));
    info.append(node("small", "", `${artifact.origin === "generated_webview" || artifact.build_id ? "生成 APK" : "原始文件"} · ${bytes(artifact.size)}`));
    const link = node("a", "file-link", "下载");
    link.href = `/api/jobs/${encodeURIComponent(job.id)}/artifacts/${encodeURIComponent(artifact.id)}`;
    link.setAttribute("download", "");
    card.append(info, link);
    return card;
  }
  const eventLabels = {tls_certificate_error:"证书校验失败，已记录错误",tls_fallback_continued:"按本任务策略继续，服务器身份未经验证",download_action:"点击下载控件",browser_preparing:"准备 Android Chrome",browser_started:"浏览器已启动",browser_connection:"正在连接目标",browser_connection_blocked:"目标连接被拒绝",interaction_started:"操作下载控件",build_preparing:"准备模板",build_resources:"整理离线资源与字体",build_compiling:"编译 APK",build_signing:"签名",build_verifying:"校验签名与应用包",build_saving:"保存文件",task_started:"开始采集",request:"正在请求",response_received:"收到响应",response_progress:"正在接收响应",queue_timeout:"排队超时，未执行",redirect:"发生跳转",page_received:"已取得页面",download_candidate:"发现下载候选，尚未验证",download_started:"开始传输候选文件，尚未验证",download_progress:"正在传输",response_complete:"响应传输结束",file_verifying:"正在核验文件",file_verified:"文件核验通过",challenge_detected:"观察到验证或访问控制",browser_required:"静态采集仍有脚本覆盖缺口",task_completed:"本次采集结束",task_timeout:"采集超时，已停止",cancelled:"已取消",building:"开始打包",built:"APK 已生成",build_timeout:"打包超时，已停止",failed:"处理未完成"};
  function eventText(event) {
    if (["dns_resolution_observed", "dns_resolution_failed", "dns_resolution_success"].includes(event?.event)) {
      const provider = {alidns:"阿里 DNS", dnspod:"DNSPod", cloudflare:"Cloudflare DNS", google:"Google DNS"}[event.provider] || "DNS";
      const query = ["A", "AAAA"].includes(event.query_type) ? ` ${event.query_type}` : "";
      const failure = {dns_nxdomain:"服务返回域名不存在，未连接该目标", dns_no_addresses:"未返回匹配地址，未连接该目标", dns_invalid_response:"响应格式或完整性检查失败", dns_diagnostics_unavailable:"诊断记录不可用", task_timeout:"任务超时，解析已停止", chain_timeout:"链路超时，解析已停止"}[event.reason_code];
      if (failure) return `${provider}${query}：${failure}`;
      const reason = {dns_answer_accepted:"解析结果已通过地址检查", dns_unsafe_answer:"解析含非公网或特殊地址，未连接该目标", target_not_public:"解析地址未通过公网检查，未连接该目标", dns_tls_verification_failed:"解析服务证书校验失败", dns_failed:"解析失败", dns_timeout:"解析超时", cancelled:"解析已取消"}[event.reason_code];
      return `${provider}${query}：${reason || (event.event === "dns_resolution_failed" ? "解析未完成" : event.event === "dns_resolution_success" ? "解析完成" : "已记录解析观察")}`;
    }
    if (event?.event === "browser_connection_failed") return "目标连接未能建立";
    if (event?.event === "browser_transport_failed") return "连接建立后传输中断";
    if (event?.event === "browser_budget_exhausted") return "浏览器采集已达到预算限制";
    if (event?.event === "browser_connection_cancelled") return "浏览器连接已取消";
    if (event?.event === "network_fallback") return "直连初始连接未完成，改用一次本机代理尝试";
    if (event?.event === "network_attempt_started") return event.network_mode === "proxy" ? "开始独立代理尝试" : "开始直连尝试";
    if (event?.event === "network_attempt_completed") return `${event.network_mode === "proxy" ? "代理" : "直连"}尝试结束`;
    return eventLabels[event?.event] || "状态已更新";
  }
  function duration(seconds) {
    const value = Math.max(0, Math.floor(seconds));
    return value >= 60 ? `${Math.floor(value / 60)} 分 ${value % 60} 秒` : `${value} 秒`;
  }
  function renderProgress(item, container, isBuild = false) {
    const progress = item.progress;
    if (!progress || typeof progress !== "object") return;
    const events = Array.isArray(progress.events) ? progress.events.filter((event) => event && typeof event === "object") : [];
    const latest = events.at(-1) || (progress.event ? progress : null);
    const active = activeStates.has(item.state);
    const panel = node("section", `live-progress ${isBuild ? "build-progress" : "collection-progress"} ${active ? "is-active" : "is-finished"}`);
    panel.append(node("h3", "", isBuild ? "打包进度" : "采集进度"));
    const finalReason = item.result?.reason_code || item.reason_code;
    const currentText = !active ? eventLabels[finalReason] || labels[item.outcome] || labels[item.state] || "本次处理结束" : latest ? eventText(latest) : item.state === "queued" ? "等待执行" : "正在处理";
    const summary = node("p", "progress-current", currentText);
    summary.setAttribute("role", "status"); panel.append(summary);
    const mode = latest?.network_mode || [...events].reverse().find((event) => event.network_mode)?.network_mode || item.result?.network_mode;
    if (mode === "direct" || mode === "proxy") panel.append(node("p", "network-mode", `网络出口：${mode === "proxy" ? "本机代理（独立尝试）" : "直连"}`));
    const now = Date.now() / 1000;
    const terminalEvents = new Set(["task_completed","task_timeout","cancelled","built","build_timeout","failed","queue_timeout"]);
    const end = active ? now : Number.isFinite(latest?.at) && terminalEvents.has(latest.event) ? latest.at : Number.isFinite(item.updated) ? item.updated : Number.isFinite(latest?.at) ? latest.at : now;
    const started = progress.started_at;
    const deadline = item.state === "queued" ? progress.queue_deadline_at : progress.deadline_at;
    const timeout = item.state === "queued" ? progress.queue_timeout_seconds : progress.timeout_seconds;
    const timing = [];
    if (Number.isFinite(started)) timing.push(`已耗时 ${duration(end - started)}`);
    if (Number.isFinite(timeout) && timeout > 0) timing.push(`${item.state === "queued" ? "排队" : "执行"}时限 ${duration(timeout)}`);
    if (active && Number.isFinite(deadline)) timing.push(deadline > now ? `预计剩余 ${duration(deadline - now)}` : "已到时限，正在等待停止确认");
    if (timing.length) panel.append(node("p", "progress-timing", timing.join(" · ")));
    // Bytes describe one actual response, never overall task completion.
    const transfer = [...events].reverse().find((event) => ["download_started","download_progress","response_progress"].includes(event.event)) || (["download_started","download_progress","response_progress"].includes(progress.event) ? progress : null);
    if (transfer && Number.isFinite(transfer.received_bytes) && transfer.received_bytes >= 0) {
      const received = transfer.received_bytes, total = transfer.total_bytes;
      const known = Number.isFinite(total) && total > 0 && received <= total;
      const transferLabel = transfer.event === "response_progress" ? "响应传输" : "文件传输";
      const text = known ? `${transferLabel}：${bytes(received)} / ${bytes(total)} · ${Math.floor(received / total * 100)}%` : `${transferLabel}：已接收 ${bytes(received)} · 总量未知`;
      panel.append(node("p", "transfer-bytes", text));
      if (transfer.url) panel.append(node("small", "event-url", String(transfer.url)));
      if (known) {
        const meter = document.createElement("progress"); meter.max = total; meter.value = received;
        meter.setAttribute("aria-label", `${transferLabel}字节进度`); panel.append(meter);
      }
      const verified = events.slice(Math.max(0, events.indexOf(transfer))).some((event) => event.event === "file_verified" && event.url === transfer.url);
      if (!verified) panel.append(node("small", "muted", transfer.event === "response_progress" ? "响应接收进度不代表已取得原包。" : "传输字节不代表应用包已验证成功。"));
    }
    const renderEvent = (event) => {
      const row = node("li", "progress-event");
      const time = Number.isFinite(event.at) ? new Date(event.at * 1000).toLocaleTimeString("zh-CN", {hour12:false}) : "";
      row.append(node("span", "event-time", time), node("strong", "", eventText(event)));
      const url = event.event === "redirect" ? event.to_url || event.url : event.url;
      if (url) row.append(node("span", "event-url", String(url)));
      if (event.event === "redirect" && event.from_url) row.append(node("small", "event-url", `来自 ${event.from_url}`));
      if (event.label) row.append(node("span", "event-label", String(event.label)));
      if (Number.isFinite(event.status)) row.append(node("small", "", `HTTP ${event.status}`));
      return row;
    };
    if (events.length) {
      const significant = new Set(["browser_preparing","browser_started","interaction_started","browser_connection_blocked","browser_connection_failed","browser_transport_failed","browser_budget_exhausted","dns_resolution_failed","dns_resolution_observed","network_fallback","network_attempt_started","redirect","download_candidate","download_started","file_verifying","file_verified","challenge_detected","browser_required","task_timeout","build_timeout"]);
      // Keep important chain changes when frequent byte updates would hide them.
      const picked = new Set(events.slice(-6));
      for (const event of events.filter((event) => significant.has(event.event)).slice(-6)) picked.add(event);
      const shown = events.filter((event) => picked.has(event)).slice(-12);
      const list = node("ol", "progress-timeline");
      for (const event of shown) list.append(renderEvent(event));
      panel.append(list);
      if (events.length > shown.length) {
        const history = node("details", "progress-history");
        history.append(node("summary", "", `查看已记录的 ${events.length} 条链路事件`));
        const all = node("ol", "progress-timeline");
        for (const event of events) all.append(renderEvent(event));
        const historyKey = `${isBuild ? "build" : "job"}:${item.id}`;
        history.open = state.progressExpanded.has(historyKey);
        history.ontoggle = () => { if (history.open) state.progressExpanded.add(historyKey); else state.progressExpanded.delete(historyKey); };
        history.append(all); panel.append(history);
      }
    }
    container.append(panel);
  }
  function renderRejectedFiles(job, content) {
    const files = (job.rejected_files || []).filter((file) => file.validation_status === "failed");
    if (!files.length) return;
    const panel = node("section", "details download-files rejected-files");
    panel.append(node("h3", "", "原文件 · 校验失败"));
    panel.append(node("p", "result-note", "文件已完整接收，但未通过包校验。可下载原始字节；任务仍保留校验失败，不代表有效 APK/IPA。"));
    for (const file of files) {
      const row = node("div", "file-card");
      const info = node("div", "file-info");
      info.append(node("strong", "", file.filename || "原文件"));
      info.append(node("small", "", `校验失败 · ${bytes(file.size)}`));
      const link = node("a", "file-link", "下载原文件（校验失败）");
      link.href = `/api/jobs/${encodeURIComponent(job.id)}/rejected-files/${encodeURIComponent(file.id)}`;
      link.setAttribute("download", "");
      row.append(info, link);
      panel.append(row);
      panel.append(node("p", "muted", friendly(file.reason_code)));
    }
    content.append(panel);
  }
  function renderBuildPanel(job, content, artifacts) {
    const candidates = job.web_candidates || [];
    if (candidates.length && job.outcome !== "downloaded") {
      const panel = node("section", "build-panel");
      panel.append(node("h3", "", "将网页打包为 APK"));
      panel.append(node("p", "", "生成可联网打开网站的应用，加入实际保存的页面与可用资源。原包采集结论保持独立。"));
      const buildRunning = (job.builds || []).some((build) => activeStates.has(build.state));
      for (const candidate of candidates) {
        const row = node("div", "build-action");
        const action = node("button", "primary", state.pendingBuilds.has(`${job.id}:${candidate.id}`) ? "重试打包提交" : "打包 APK");
        action.type = "button";
        action.disabled = !state.capabilities?.web_apk?.enabled || buildRunning;
        action.onclick = () => submitBuild(job, candidate, action);
        row.append(action, node("small", "", candidate.filename || "网页应用.apk"));
        panel.append(row);
      }
      if (!state.capabilities?.web_apk?.enabled) panel.append(node("p", "build-status", "本机打包工具链未就绪，请在后端主机完成配置。"));
      for (const build of job.builds || []) {
        const line = node("div", "build-status");
        line.append(node("span", "", `${build.filename || "APK"} · ${labels[build.state] || "处理完成"}`));
        if (build.state === "built") {
          const detail = build.result || {};
          const size = detail.size ?? artifacts.find((artifact) => artifact.build_id === build.id)?.size;
          if (Number.isFinite(size)) line.append(node("p", "", `成品大小：${bytes(size)}`));
          if (detail.offline_content_kind === "site_snapshot") {
            line.append(node("p", "", "已包含保存的网站离线内容，离线可用范围以实际保存内容为准。"));
          } else if (detail.offline_content_kind === "connection_page") {
            line.append(node("p", "", "仅含离线入口页，未取得网站离线内容；打开网站仍需联网。"));
          }
          if (Number.isInteger(detail.resource_files) && detail.resource_files >= 0) {
            const resourceSize = Number.isFinite(detail.resource_bytes) ? ` · ${bytes(detail.resource_bytes)}（未压缩）` : "";
            line.append(node("p", "", `已打包资源：${detail.resource_files} 项${resourceSize}`));
          }
          if (Number.isFinite(size) && size < 10 * 1024 * 1024) {
            line.append(node("p", "", "当前实际页面与资源较少，成品体积较小；体积随内容变化。"));
          }
        }
        if (build.result?.reason_code) line.append(node("p", "", friendly(build.result.reason_code)));
        if (activeStates.has(build.state)) {
          const cancel = node("button", "text-button", "取消打包");
          cancel.type = "button";
          cancel.onclick = () => cancelBuild(job.id, build.id, cancel);
          line.append(document.createTextNode("　"), cancel);
        }
        renderProgress(build, line, true);
        panel.append(line);
      }
      content.append(panel);
    }
  }
  function renderJob() {
    const job = state.job, content = $("job-content");
    content.replaceChildren();
    content.hidden = !job;
    $("job-empty").hidden = !!job;
    if (!job) return;
    const heading = node("div", "job-heading");
    heading.append(badge(labels[job.state] || "任务", activeStates.has(job.state) ? "busy" : ""));
    if (activeStates.has(job.state)) {
      const cancel = node("button", "text-button", "取消采集");
      cancel.type = "button";
      cancel.onclick = () => cancelJob(job.id, cancel);
      heading.append(cancel);
    }
    content.append(heading, node("p", "job-url", job.input?.entry_url || ""));
    const tlsPolicy = job.tls_policy || job.input?.tls_policy;
    const tlsFallback = job.tls_fallback || job.data_package?.tls_fallback;
    if (tlsFallback?.observed === true) content.append(node("p", "tls-warning", `本次记录了 ${tlsFallback.count} 次证书校验失败后的继续访问。相关 HTTPS 服务器身份未经验证，页面或 APK 可能被冒充、篡改。文件校验通过不代表来源可信；具体错误、证书原件及获取缺口保留在数据包中。${tlsFallback.state === "unavailable" ? "另有未能确认的证书处理记录，请查看数据包缺口。" : ""}`));
    else if (!job.input?.tls_policy && job.input?.ignore_tls_errors === true) content.append(node("p", "tls-warning", "此历史任务曾手动忽略证书错误，HTTPS 服务器身份未经验证。文件校验通过不代表来源可信。"));
    else if (tlsFallback?.state === "unavailable") content.append(node("p", "tls-warning", "证书处理记录不完整，暂时不能确认是否发生了放宽校验。请查看数据包中的错误及获取缺口。"));
    else if (tlsPolicy === "auto") content.append(node("p", "muted", "证书策略：先校验，仅证书校验失败时继续；错误和原件随数据包保留。"));
    else if (tlsPolicy === "strict") content.append(node("p", "muted", "证书策略：严格校验，证书错误时停止。"));
    content.append(node("p", "", `原包结果：${labels[job.outcome] || "尚未取得结论"}`));
    const artifacts = job.artifacts || [];
    if (artifacts.length) {
      const files = node("section", "details download-files");
      files.append(node("h3", "", "应用文件（单独下载）"));
      for (const artifact of artifacts) files.append(downloadFile(job, artifact));
      content.append(files);
    }
    renderRejectedFiles(job, content);
    renderBuildPanel(job, content, artifacts);
    renderProgress(job, content);
    FxfetchDataPackage.render(job, content, {node, bytes, friendly});
    FxfetchAnalysis.render(job, content, {
      node, friendly, capability:state.capabilities?.web_analysis,
      submitting:!!state.pendingAnalyses.get(job.id)?.busy,
      onStart:(button) => submitAnalysis(job, button),
      onCancel:(id, button) => cancelAnalysis(job.id, id, button)
    });
    const result = job.result || {};
    if ((result.network_attempts || []).length) {
      const network = node("section", "details network-attempts");
      network.append(node("h3", "", "网络尝试记录"));
      for (const attempt of result.network_attempts) {
        const detail = attempt.result || {};
        network.append(node("p", "", `${attempt.network_mode === "proxy" ? "本机代理" : "直连"} · ${labels[detail.outcome] || "未完成"}${result.network_attempts.length > 1 ? " · " + friendly(detail.reason_code) : ""}`));
      }
      if (result.network_attempts.length > 1) network.append(node("p", "muted", "代理尝试使用独立访问，直连结果保留，不继承页面登录状态。"));
      content.append(network);
    }
    const reason = result.reason_code || job.reason_code;
    const collectorLabel = {http:"静态 HTTP 采集",android_chrome:"Android Chrome 采集",android_chrome_unavailable:"Android Chrome 未能启动"}[result.collector_mode];
    if (collectorLabel) content.append(node("p", "muted", collectorLabel));
    if (reason) content.append(node("p", "result-note", job.download_selection_unavailable ? "这条旧记录没有保存可继续的候选，请重新提交入口。" : friendly(reason)));
    if (result.coverage) content.append(node("p", "muted", `覆盖范围：${labels[result.coverage] || "存在未完成范围"}`));
    if (job.outcome !== "downloaded") {
      if (result.offline?.available) content.append(node("p", "offline-status", "已有离线页面内容。离线可用范围取决于已保存的内容，不代表网站业务可离线运行。"));
      else if (!activeStates.has(job.state)) content.append(node("p", "offline-status", "未取得网站离线内容。联网入口与原采集结果保留。"));
    }
    if ((result.attempts || []).length) {
      const attempts = node("section", "details");
      attempts.append(node("h3", "", "链路记录"));
      for (const attempt of result.attempts) {
        const line = node("div", "attempt");
        line.append(node("strong", "", attempt.chain === "android" ? "Android" : "iPhone"));
        const discoveryEvent = !attempt.outcome && ["candidate_discovered","landing_candidate_discovered"].includes(attempt.reason_code);
        line.append(node("span", "", `${discoveryEvent ? "已发现下载地址" : labels[attempt.outcome] || "继续处理中"} · ${labels[attempt.coverage] || "范围待确认"}`));
        if (attempt.reason_code && attempt.reason_code !== "candidate_discovered") line.append(node("p", "muted", friendly(attempt.reason_code)));
        attempts.append(line);
      }
      content.append(attempts);
    }
    renderContinuation(job, content);
    if (busy(job)) content.append(node("p", "refresh-note", "正在自动更新 · 离开当前页面后暂停轮询"));
    else content.append(node("p", "refresh-note", "任务已停止更新，刷新会清空当前会话记录。"));
  }
  async function viewRelatedJob(id) {
    if (state.clearing) return;
    state.current = id; rememberJob(id); state.pollDelay = 1500;
    try { await loadJobs(); } catch (error) { if (state.authenticated) notice(error.message, true); }
  }
  function renderContinuation(job, content) {
    if (job.input?.parent_job_id) {
      content.append(node("p", "muted", "本次下载使用独立访问，不保留原页面的登录状态。"));
      const parent = node("button", "text-button", "查看原任务");
      parent.type = "button"; parent.onclick = () => viewRelatedJob(job.input.parent_job_id);
      content.append(parent);
    }
    const candidates = job.download_candidates || [];
    if (!candidates.length && !job.continuation_child_job_id) return;
    const panel = node("section", "details continuation-panel");
    panel.append(node("h3", "", "选择下载地址"));
    panel.append(node("p", "", "选择后只访问该地址；原任务保留。新下载不保留原页面的登录状态。"));
    const pending = state.pendingContinuations.get(job.id);
    const child = job.continuation_active_child_job_id || job.continuation_child_job_id;
    const group = node("fieldset", "continuation-candidates");
    group.append(node("legend", "", "选择一个候选"));
    for (const candidate of candidates) {
      const label = node("label", "candidate");
      const radio = document.createElement("input");
      radio.type = "radio"; radio.name = `download-choice-${job.id}`; radio.value = candidate.id;
      radio.checked = candidate.id === (pending?.body.candidate_id || state.selectedContinuations.get(job.id));
      radio.disabled = !!candidate.child_job_id || !!child || !!pending || state.clearing;
      radio.onchange = () => { state.selectedContinuations.set(job.id, candidate.id); renderJob(); };
      const description = node("span", "");
      description.append(node("strong", "", candidate.label || "下载候选"), node("span", "job-url", candidate.url));
      label.append(radio, description); group.append(label);
      if (["direct_apk", "direct_ipa"].includes(candidate.kind)) {
        try {
          const target = new URL(candidate.url);
          if (["http:", "https:"].includes(target.protocol) && !target.username && !target.password) {
            const direct = node("a", "file-link", "在当前设备直接下载（不继承采集会话）");
            direct.href = candidate.url; direct.target = "_blank"; direct.rel = "noopener noreferrer";
            direct.referrerPolicy = "no-referrer";
            direct.onclick = () => notice("已交给当前设备浏览器下载。此候选尚未验证，服务不会记录为已下载。");
            group.append(direct);
          }
        } catch { /* A malformed candidate stays plain text and cannot navigate. */ }
      }
      if (candidate.child_job_id) {
        const view = node("button", "text-button", "查看此地址的后续任务");
        view.type = "button"; view.onclick = () => viewRelatedJob(candidate.child_job_id);
        group.append(view);
      }
    }
    panel.append(group);
    if (!child) {
      const option = node("div", "tls-option");
      const label = node("label", "", "此次后续任务的证书处理");
      const choice = node("select", "");
      choice.id = `tls-policy-${job.id}`; label.setAttribute("for", choice.id);
      choice.append(new Option("先校验，仅证书错误时继续（默认）", "auto"), new Option("严格校验，证书错误时停止", "strict"));
      choice.value = pending?.body.tls_policy || state.continuationTls.get(job.id) || "auto";
      choice.disabled = !!pending || state.clearing;
      choice.onchange = () => state.continuationTls.set(job.id, choice.value);
      option.append(label, choice, node("p", "", "每个新任务重新从证书校验开始。自动继续后服务器身份未经验证，风险和错误会保留。"));
      panel.append(option);
    }
    const action = node("button", "primary continuation-submit", child ? "查看后续任务" : pending?.busy ? "正在提交…" : pending ? "重试继续下载" : "继续下载所选地址");
    action.type = "button";
    action.disabled = state.clearing || !!pending?.busy || (!child && !pending && !state.selectedContinuations.has(job.id));
    action.onclick = () => child ? viewRelatedJob(child) : submitContinuation(job);
    panel.append(action); content.append(panel);
  }
  async function submitContinuation(job) {
    if (state.clearing || !state.authenticated || job.continuation_child_job_id) return;
    const epoch = state.epoch;
    let pending = state.pendingContinuations.get(job.id);
    if (!pending) {
      const selected = state.selectedContinuations.get(job.id);
      if (!(job.download_candidates || []).some((candidate) => candidate.id === selected)) return;
      pending = {key:idempotencyKey(), body:{candidate_id:selected,tls_policy:state.continuationTls.get(job.id) || "auto"}, busy:false};
      state.pendingContinuations.set(job.id, pending);
    }
    if (pending.busy) return;
    pending.busy = true; renderJob();
    try {
      const child = await api(`/api/jobs/${encodeURIComponent(job.id)}/continue`, {method:"POST",body:pending.body,headers:{"Idempotency-Key":pending.key}});
      if (epoch !== state.epoch || state.clearing || !state.authenticated) return;
      state.pendingContinuations.delete(job.id); state.selectedContinuations.delete(job.id);
      state.continuationTls.delete(job.id);
      state.current = child.id; state.job = child; rememberJob(child.id);
      state.pollDelay = 1500; renderJob(); await loadJobs();
      if (epoch === state.epoch) notice("已提交所选地址。原任务保留，新下载不保留原页面的登录状态。");
    } catch (error) {
      if (epoch !== state.epoch || state.clearing) return;
      if (error.status && error.status < 500) state.pendingContinuations.delete(job.id);
      if (state.authenticated) notice(error.message + (state.pendingContinuations.has(job.id) ? " 可重试同一次提交，不会重复创建任务。" : ""), true);
    } finally {
      pending.busy = false;
      if (epoch === state.epoch && !state.clearing && state.job?.id === job.id) renderJob();
      schedule();
    }
  }
  function updateInput() {
    updateTLSChoice();
    const locked = state.submitting || !!state.pendingJob || state.clearing;
    $("url").disabled = locked;
    $("tls-policy").disabled = locked;
    $("image-file").disabled = locked || state.uploading;
    $("clear-image").disabled = locked || state.uploading;
    $("dropzone").setAttribute("aria-disabled", String(locked || state.uploading));
    for (const radio of $("qr-candidates").querySelectorAll("input")) radio.disabled = locked || state.uploading || radio.dataset.blocked === "true";
    $("download-button").disabled = state.submitting || state.uploading || state.clearing || !!state.image?.truncated;
    $("download-button").textContent = state.submitting ? "正在提交…" : state.pendingJob ? "重试提交（同一次任务）" : "开始采集";
    if (locked || state.uploading || state.image?.truncated || !state.authenticated) clearDirectLink();
    else scheduleDirectLink();
  }
  function clearImage() {
    if (state.previewURL) URL.revokeObjectURL(state.previewURL);
    state.previewURL = null;
    state.image = null;
    state.selectedQR = null;
    $("image-file").value = "";
    $("image-preview").removeAttribute("src");
    $("image-preview").hidden = true;
    $("image-result").hidden = true;
    $("qr-candidates").replaceChildren(node("legend", "", "选择二维码入口"));
    $("qr-candidates").hidden = true;
    updateInput();
  }
  async function uploadImage(file) {
    if (!state.authenticated || state.clearing || state.submitting || state.pendingJob || state.uploading) return;
    const epoch = state.epoch;
    const imageTypes = ["image/png","image/jpeg","image/webp","image/heic","image/heif","image/avif","image/bmp","image/x-ms-bmp","image/gif","image/tiff"];
    if (!file || (!imageTypes.includes(file.type) && !/\.(png|jpe?g|jfif|webp|heic|heif|avif|bmp|gif|tiff?)$/i.test(file.name || ""))) { notice("只允许上传图片：手机截图、PNG、JPEG、HEIC、WebP、AVIF、BMP、静态 GIF 或单页 TIFF。", true); return; }
    if (file.size > 10 * 1024 * 1024) { notice(messages.image_too_large, true); return; }
    clearImage();
    state.uploading = true;
    $("image-result").hidden = false;
    $("qr-status").textContent = "正在本地识别…";
    updateInput();
    const data = new FormData(); data.append("file", file);
    try {
      const result = await api("/api/qr-images", {method:"POST",body:data,upload:true});
      if (epoch !== state.epoch) return;
      state.image = result;
      if (result.thumbnail_url) { $("image-preview").src = result.thumbnail_url; $("image-preview").hidden = false; }
      $("qr-status").textContent = result.truncated ? "二维码过多，请裁剪重传" : result.status === "decoded" ? `识别到 ${result.candidates?.length || 0} 个二维码` : friendly(result.reason_code || result.status);
      const group = $("qr-candidates");
      group.hidden = !(result.candidates || []).length;
      const valid = (result.candidates || []).filter((candidate) => candidate.url);
      for (const candidate of result.candidates || []) {
        const label = node("label", "candidate");
        const radio = document.createElement("input"); radio.type = "radio"; radio.name = "qr-choice"; radio.value = candidate.id;
        radio.disabled = !candidate.url || result.truncated;
        radio.dataset.blocked = String(!candidate.url || !!result.truncated);
        radio.onchange = () => { state.selectedQR = candidate; $("url").value = candidate.kind === "itms_manifest" ? candidate.text : candidate.url; updateHost(); };
        label.append(radio, node("span", "", candidate.text)); group.append(label);
        if (valid.length === 1 && candidate.url && !result.truncated) { radio.checked = true; radio.onchange(); }
      }
      if (result.truncated) notice(messages.qr_truncated, true);
      else notice("图片已离线识别。选择入口后，点击开始采集才会访问目标。");
    } catch (error) { $("qr-status").textContent = "识别未完成"; if (state.authenticated) notice(error.message, true); }
    finally { state.uploading = false; updateInput(); }
  }
  let directTimer = null;
  let directRevision = 0;
  function clearDirectLink() {
    clearTimeout(directTimer); directRevision++;
    $("direct-download").hidden = true;
    $("direct-download-link").removeAttribute("href");
  }
  function scheduleDirectLink() {
    clearDirectLink();
    const revision = directRevision, epoch = state.epoch, original = $("url").value;
    if (!state.authenticated || state.submitting || state.clearing || state.uploading || state.pendingJob || !original.trim() || state.image?.truncated || (state.image && !state.selectedQR)) return;
    directTimer = setTimeout(async () => {
      try {
        const preview = await api("/api/preview", {method:"POST",body:{url:original}});
        if (revision !== directRevision || epoch !== state.epoch || !state.authenticated || state.clearing || $("url").value !== original) return;
        if (!["direct_apk", "direct_ipa"].includes(preview.kind) || !preview.request_url) return;
        const url = new URL(preview.request_url);
        if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return;
        $("direct-download-link").href = preview.request_url;
        $("direct-download").hidden = false;
      } catch { /* Invalid input leaves the optional link hidden; submit shows the error. */ }
    }, 350);
  }
  function updateHost() {
    const text = $("url").value.trim();
    try { const url = new URL(text); $("host-hint").textContent = `${url.protocol}  ${url.hostname || "描述文件入口"} · 保留完整路径与参数`; }
    catch { $("host-hint").textContent = "可直接粘贴域名或完整网址；下载时自动补齐 https://，保留路径与参数。"; }
    scheduleDirectLink();
  }
  async function submitJob(event) {
    event.preventDefault();
    if (state.submitting || state.clearing || !state.authenticated) return;
    const epoch = state.epoch;
    state.submitting = true; updateInput(); notice("");
    try {
      if (!state.pendingJob) {
        const originalInput = $("url").value;
        if (!originalInput.trim()) { notice("请先添加网址。", true); return; }
        if (state.image && !state.selectedQR) { notice("请先从识别结果中选择一个入口，或移除图片后输入网址。", true); return; }
        // Use the backend's offline normalizer so browser and direct API input
        // have identical rules. This preview never contacts the target.
        const preview = await api("/api/preview", {method:"POST",body:{url:originalInput}});
        if (epoch !== state.epoch) return;
        if (!preview.request_url || ["unsupported", "store"].includes(preview.kind)) throw new Error(messages.unsupported_input);
        $("url").value = preview.url; updateHost();
        const body = {url:originalInput,tls_policy:$("tls-policy").value};
        if (state.image && state.selectedQR) {
          body.image_id = state.image.id; body.candidate_id = state.selectedQR.id;
          const original = state.selectedQR.kind === "itms_manifest" ? state.selectedQR.text : state.selectedQR.url;
          if (originalInput === original) delete body.url;
        }
        state.pendingJob = {key:idempotencyKey(), body};
      }
      const pending = state.pendingJob;
      const job = await api("/api/jobs", {method:"POST",body:pending.body,headers:{"Idempotency-Key":pending.key}});
      if (epoch !== state.epoch) return;
      state.pendingJob = null; state.current = job.id; state.job = job; rememberJob(job.id);
      $("tls-policy").value = "auto";
      $("advanced-settings").open = false;
      state.pollDelay = 1500; renderJob(); await loadJobs(); notice("任务已提交。刷新会清空当前会话记录，不会重新采集。");
    } catch (error) {
      if (error.status && error.status < 500) { state.pendingJob = null; $("tls-policy").value = "auto"; }
      if (state.authenticated) notice(error.message + (state.pendingJob ? " 重试将沿用同一次提交，不会重复创建任务。" : ""), true);
    } finally { state.submitting = false; updateInput(); schedule(); }
  }
  async function submitBuild(job, candidate, button) {
    if (state.clearing) return;
    const epoch = state.epoch;
    const mapKey = `${job.id}:${candidate.id}`;
    let pending = state.pendingBuilds.get(mapKey);
    if (!pending) { pending = {key:idempotencyKey(),body:{candidate_id:candidate.id},busy:false}; state.pendingBuilds.set(mapKey,pending); }
    if (pending.busy) return;
    pending.busy = true; button.disabled = true;
    try {
      await api(`/api/jobs/${encodeURIComponent(job.id)}/web-apk-builds`, {method:"POST",body:pending.body,headers:{"Idempotency-Key":pending.key}});
      if (epoch !== state.epoch) return;
      state.pendingBuilds.delete(mapKey); state.pollDelay = 1500;
      await loadCurrent(); notice("APK 构建已提交，原采集结果保持独立。");
    } catch (error) {
      if (error.status && error.status < 500) state.pendingBuilds.delete(mapKey);
      if (state.authenticated) notice(error.message + (state.pendingBuilds.has(mapKey) ? " 可再次点击打包按钮重试同一操作。" : ""),true);
    } finally { pending.busy = false; if (state.job?.id === job.id) renderJob(); schedule(); }
  }
  async function submitAnalysis(job, button) {
    if (state.clearing || !state.authenticated) return;
    const epoch = state.epoch;
    let pending = state.pendingAnalyses.get(job.id);
    if (!pending) { pending = {key:idempotencyKey(),busy:false}; state.pendingAnalyses.set(job.id,pending); }
    if (pending.busy) return;
    pending.busy = true; button.disabled = true;
    let submitted = false;
    try {
      const analysis = await api(`/api/jobs/${encodeURIComponent(job.id)}/analyses`, {method:"POST",body:{},headers:{"Idempotency-Key":pending.key}});
      if (epoch !== state.epoch || !state.authenticated) return;
      // A successful POST is already authoritative. Keep its active state even
      // when the following list/detail read fails, so the normal bounded polling
      // cadence can recover without submitting another analysis.
      job.analyses = [...(job.analyses || []).filter(item => item.id !== analysis.id), analysis];
      if (state.job?.id === job.id) state.job.analyses = job.analyses;
      const summary = state.jobs.find(item => item.id === job.id);
      if (summary) summary.active_analyses = job.analyses.filter(item => activeStates.has(item.state)).length;
      submitted = true;
      state.pendingAnalyses.delete(job.id); state.pollDelay = 1500;
      await loadJobs(); notice("离线分析已提交，原采集结果不变。刷新清空会取消本会话未完成的分析。");
    } catch (error) {
      if (epoch !== state.epoch || !state.authenticated) return;
      if (error.status && error.status < 500) state.pendingAnalyses.delete(job.id);
      notice((submitted ? "离线分析已提交，暂时未能获取进度，将自动重试读取。 " : "") + error.message + (state.pendingAnalyses.has(job.id) ? " 再次点击将重试同一次提交，不会重复创建分析。" : ""),true);
    } finally { pending.busy = false; if (state.job?.id === job.id) renderJob(); schedule(); }
  }
  async function cancelAnalysis(job, id, button) {
    if (state.clearing || !state.authenticated) return;
    const epoch = state.epoch;
    button.disabled = true;
    try {
      await api(`/api/jobs/${encodeURIComponent(job)}/analyses/${encodeURIComponent(id)}/cancel`, {method:"POST"});
      if (epoch === state.epoch && state.authenticated) await loadJobs();
    } catch (error) { if (epoch === state.epoch && state.authenticated) notice(error.message,true); }
    finally { button.disabled = false; schedule(); }
  }
  async function cancelJob(id, button) {
    button.disabled = true;
    try { await api(`/api/jobs/${encodeURIComponent(id)}/cancel`, {method:"POST"}); await loadJobs(); }
    catch (error) { if (state.authenticated) notice(error.message,true); }
    finally { button.disabled = false; }
  }
  async function cancelBuild(job, id, button) {
    button.disabled = true;
    try { await api(`/api/jobs/${encodeURIComponent(job)}/web-apk-builds/${encodeURIComponent(id)}/cancel`, {method:"POST"}); await loadCurrent(); }
    catch (error) { if (state.authenticated) notice(error.message,true); }
    finally { button.disabled = false; schedule(); }
  }
  $("login-form").onsubmit = async (event) => {
    event.preventDefault();
    const button = event.submitter; if (button) button.disabled = true;
    const password = $("password").value;
    $("password").value = "";
    try { await authenticated(await api("/api/login", {method:"POST",body:{password}})); }
    catch (error) { notice(error.message,true); }
    finally { if (button) button.disabled = false; }
  };
  $("logout").onclick = async () => {
    stopCapabilityPolling();
    try { await api("/api/logout", {method:"POST"}); signedOut(); rememberJob(null); notice("已退出当前会话。"); }
    catch (error) { notice(error.message,true); }
    finally { if (state.authenticated) void pollCapabilities(); }
  };
  $("download-form").onsubmit = submitJob;
  $("direct-download-link").onclick = () => notice("已交给当前设备浏览器下载。服务没有取得文件，不能确认下载是否完成。");
  $("url").oninput = updateHost;
  $("image-file").onchange = (event) => uploadImage(event.target.files[0]);
  $("clear-image").onclick = () => { if (!state.pendingJob && !state.uploading) { clearImage(); notice(""); } };
  $("dropzone").onclick = () => { if (!state.uploading && !state.pendingJob) $("image-file").click(); };
  $("dropzone").onkeydown = (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); $("dropzone").click(); } };
  $("dropzone").ondragover = (event) => { event.preventDefault(); $("dropzone").classList.add("dragover"); };
  $("dropzone").ondragleave = () => $("dropzone").classList.remove("dragover");
  $("dropzone").ondrop = (event) => { event.preventDefault(); $("dropzone").classList.remove("dragover"); uploadImage(event.dataTransfer.files[0]); };
  $("download-form").onpaste = (event) => {
    const image = Array.from(event.clipboardData?.items || []).find((item) => item.kind === "file" && item.type.startsWith("image/"));
    if (image) { event.preventDefault(); uploadImage(image.getAsFile()); }
  };
  $("job-picker").onchange = async (event) => {
    stopPolling(); state.current = event.target.value; rememberJob(state.current); state.pollDelay = 1500;
    try { await loadCurrent(); } catch (error) { if (state.authenticated) notice(error.message,true); } finally { schedule(); }
  };
  async function clearRecords(showNotice = true) {
    if (state.clearing || !state.authenticated) return;
    state.clearing = true;
    state.epoch += 1;
    stopPolling();
    $("refresh").disabled = true;
    state.jobs = []; state.current = null; state.job = null;
    state.pendingJob = null; state.pendingBuilds.clear(); state.pendingAnalyses.clear(); state.pendingContinuations.clear(); state.selectedContinuations.clear(); state.progressExpanded.clear(); state.activeBuildJobs.clear();
    state.continuationTls.clear(); $("tls-policy").value = "auto";
    $("advanced-settings").open = false;
    state.submitting = false; state.uploading = false;
    clearImage(); $("url").value = ""; updateHost(); rememberJob(null);
    $("job-picker").replaceChildren(new Option("还没有任务", "")); renderJob(); updateInput();
    try {
      // Requests already submitted must settle before the server archives their
      // records; late responses are ignored by the epoch checks above.
      await Promise.allSettled([...state.mutations]);
      await api("/api/jobs", {method:"DELETE"});
      if (showNotice) notice("当前会话记录已清空。原始文件保留在后端主机。");
    } catch (error) { if (state.authenticated) notice(error.message,true); }
    finally { state.clearing = false; $("refresh").disabled = false; updateInput(); }
  }
  $("refresh").onclick = () => clearRecords();
  $("tls-policy").value = "auto";
  $("advanced-settings").open = false;
  $("tls-policy").onchange = updateTLSChoice;
  updateTLSChoice();
  window.addEventListener("pageshow", () => {
    $("tls-policy").value = state.pendingJob?.body.tls_policy || "auto";
    if (!state.pendingJob) $("advanced-settings").open = false;
    updateTLSChoice();
    state.continuationTls.clear();
    if (state.job) renderJob();
  });
  document.addEventListener("visibilitychange", () => { if (document.hidden) { stopPolling(); stopCapabilityPolling(); } else { schedule(); void pollCapabilities(); } });
  window.addEventListener("beforeunload", () => { stopPolling(); stopCapabilityPolling(); if (state.previewURL) URL.revokeObjectURL(state.previewURL); });
  api("/api/session").then((session) => session.authenticated ? authenticated(session) : signedOut()).catch(() => { signedOut(); notice("暂时无法连接本地主机，请检查服务后刷新。",true); });
})();
