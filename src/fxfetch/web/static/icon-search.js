/* Explicit third-party search. Preview and candidate rendering make no target requests. */
"use strict";
globalThis.FxfetchIconSearch = {
  create({api, key, collected, enabled, capabilities}) {
    const $ = id => document.getElementById(id);
    const labels = {validating:"检查图片", quota:"检查免费搜索额度", recognizing:"识别名称和图标",
      uploading:"提交图标搜图", catalog_search:"查询 Koodous 样本库", searching:"搜索 Android 候选", completed:"搜索结束", finished:"搜索结束"};
    const errors = {icon_search_unconfigured:"后台尚未配置本次任务所需的服务。", icon_search_busy:"已有识别或搜索任务运行，请稍后再试。",
      icon_daily_limit:"识别和检索任务已达 24 小时内 20 次上限。", icon_free_quota_unavailable:"免费额度不足或当前不是免费方案，未继续搜索。",
      icon_provider_auth:"第三方接口拒绝请求，请检查后台密钥和访问状态。", icon_provider_quota:"第三方接口额度不足或限流。",
      icon_provider_forbidden:"第三方接口拒绝访问（HTTP 403），请检查模型或节点权限。",
      icon_provider_timeout:"等待第三方接口响应超时，本次未取得完整结果。",
      icon_provider_tls:"第三方接口的 HTTPS 证书或 TLS 连接校验失败。",
      icon_provider_proxy:"模型代理连接失败，请检查后台代理状态。",
      icon_provider_connection:"无法连接第三方接口，请检查网络或节点状态。",
      icon_provider_response_invalid:"第三方接口返回的内容格式无效。",
      icon_provider_incomplete:"第三方接口响应未完整接收，结果不完整。",
      icon_provider_http:"第三方接口返回异常 HTTP 状态，本次未取得完整结果。",
      icon_provider_failed:"第三方接口请求失败，本次没有确认完整搜索结果。", icon_provider_response_limit:"第三方响应超过读取上限。",
      icon_recognition_invalid:"未取得有效的图标识别结果。", icon_ambiguous:"截图里有多个可能的图标，请只截取要搜索的应用及名称。",
      icon_image_limit:"图片超过限制或包含多帧，请使用单张手机截图。", invalid_image:"文件不是有效图片。",
      icon_timeout:"已达到 3 分钟时限，搜索已停止。", icon_interrupted:"服务重启中断了搜索，没有自动重试。",
      icon_processing_failed:"处理未完成。", name_search_unconfigured:"后台尚未配置名称检索服务。",
      search_name_invalid:"请填写有效的应用显示名称（最多 100 字）。", invalid_recognition:"截图识别记录不可用，请重新识别或直接按名称搜索。",
      name_search_invalid:"请填写有效的应用显示名称（最多 100 字）。",
      recognition_unavailable:"截图识别记录不可用，请重新识别或直接输入名称。",
      icon_name_not_visible:"未读到清晰的应用名称，请裁取名称区域或直接输入名称。",
      cancelled:"搜索已取消。"};
    let file = null, preview = null, pending = null, current = null, timer = null, epoch = 0, busy = false;
    let resultStatus = "", cancelling = false;
    let mode = "image", operation = null, recognitionId = null, recognitionEditVersion = null, editVersion = 0;
    let appliedRecognition = null;
    let timing = null, timingTimer = null, timingReceived = 0, timingRunning = false, timingStage = "";
    let timingJob = null, timingSnapshot = null, timingBaseTotal = 0, timingBaseStage = null;
    let timingTotalNode = null, timingStageNode = null;
    const pendingCollect = new Map();
    const sampleControls = [];
    const text = value => { $("icon-status").textContent = value; };
    const element = (tag, value, className) => {
      const node = document.createElement(tag); node.textContent = value;
      if (className) node.className = className; return node;
    };
    async function copyUrl(value) {
      if (globalThis.isSecureContext && navigator.clipboard?.writeText) {
        try { await navigator.clipboard.writeText(value); return true; }
        catch { /* Permission may be denied; try the local HTTP-compatible path. */ }
      }
      const previous = document.activeElement;
      const input = document.createElement("textarea");
      input.value = value; input.readOnly = true;
      input.style.cssText = "position:fixed;left:-9999px;top:0;opacity:0";
      document.body.append(input);
      try {
        input.focus({preventScroll:true}); input.select();
        return document.execCommand("copy");
      } catch { return false; }
      finally { input.remove(); previous?.focus({preventScroll:true}); }
    }
    const active = result => ["queued", "running"].includes(result.state);
    const capability = kind => {
      if (!capabilities) return enabled();
      const value = capabilities();
      if (!value) return false;
      return enabled() && (value[kind === "recognize" ? "recognition_enabled" : "name_enabled"] ?? value.enabled) === true;
    };
    const nameValue = () => $("name-search-name").value.trim();
    const recognized = result => result.mode === "recognize" && result.state === "completed" &&
      result.result === "recognized" && !result.error;
    const externalLink = (url, title, className = "text-button") => {
      try {
        const parsed = new URL(url);
        if (!["https:", "http:"].includes(parsed.protocol) || parsed.username || parsed.password || /[\s\\\x00-\x1f]/.test(url)) return null;
        const link = element("a", title, className); link.href = url; link.target = "_blank";
        link.rel = "noopener noreferrer"; link.referrerPolicy = "no-referrer"; return link;
      } catch { return null; }
    };
    const strongCandidates = result => (result.candidates || []).filter(v =>
      v.evidence.includes("name_in_title") || v.evidence.includes("provider_exact_match") ||
      (!result.recognition?.name && v.evidence.includes("android_text")));
    const candidateSummary = result => {
      const count = result.candidates?.length || 0;
      return `找到 ${count} 条${strongCandidates(result).length ? "" : "弱相关"}候选`;
    };
    function resultError(result) {
      if (!result.error) return "";
      const requests = Array.isArray(result.timing?.requests) ? result.timing.requests : [];
      const lastRequest = [...requests].reverse().find(row => row?.error_code === result.error);
      const stage = result.error_detail?.stage || lastRequest?.stage;
      const prefix = stage && labels[stage] ? `${labels[stage]}阶段：` : "";
      const http = result.error_detail?.http_status;
      const suffix = result.error === "icon_provider_http" && Number.isInteger(http) && http >= 100 && http <= 599 ? `（上游 HTTP ${http}）` : "";
      return prefix + (errors[result.error] || "搜索发生错误，结果可能不完整。") + suffix;
    }
    const validSeconds = value => Number.isFinite(value) && value >= 0;
    const duration = value => `${Math.floor(value / 60)}:${String(Math.floor(value % 60)).padStart(2, "0")}`;
    const detailedSeconds = value => validSeconds(value) ? `${value.toFixed(1)} 秒` : "未记录";
    function clearTiming() {
      clearInterval(timingTimer); timingTimer = null; timing = null;
      timingTotalNode = timingStageNode = null;
      timingJob = timingSnapshot = null; timingBaseTotal = 0; timingBaseStage = null;
      timingReceived = 0; timingRunning = false; timingStage = "";
    }
    function rememberTiming(result) {
      const incoming = result.timing;
      if (!incoming || !validSeconds(incoming.total_seconds)) { clearTiming(); return; }
      const now = performance.now(), running = active(result), job = result.id || current;
      const sameJob = timing && timingJob === job && timing.started_at === incoming.started_at;
      const sameStage = sameJob && timingStage === result.stage &&
        timing.stage_started_at === incoming.stage_started_at;
      const snapshot = JSON.stringify([result.stage, incoming.total_seconds,
        incoming.stage_elapsed_seconds, incoming.stage_started_at]);
      const additional = timingRunning ? Math.max(0, now - timingReceived) / 1000 : 0;
      const oldTotal = timingBaseTotal + additional;
      const oldStage = validSeconds(timingBaseStage) ? timingBaseStage + additional : null;
      // A slow request publishes no new progress. Polling that same snapshot must
      // keep its monotonic anchor, even though progress() rebuilds the DOM below.
      const identical = sameStage && timingRunning && running && timingSnapshot === snapshot;
      const olderStage = sameJob && validSeconds(incoming.stage_started_at) &&
        validSeconds(timing.stage_started_at) && incoming.stage_started_at < timing.stage_started_at;
      const stale = sameJob && timingRunning && running &&
        (incoming.total_seconds < timing.total_seconds ||
         incoming.total_seconds === timing.total_seconds && olderStage);
      clearInterval(timingTimer); timingTimer = null;
      timingTotalNode = timingStageNode = null;
      if (!stale) {
        if (!identical) {
          // Running values remain local estimates, so a delayed newer snapshot
          // cannot make them jump backwards. A new phase starts from the server's
          // phase duration; terminal results always use exact server durations.
          timingBaseTotal = sameJob && timingRunning && running ? Math.max(incoming.total_seconds, oldTotal) : incoming.total_seconds;
          timingBaseStage = validSeconds(incoming.stage_elapsed_seconds) ?
            sameStage && timingRunning && running && validSeconds(oldStage) ?
              Math.max(incoming.stage_elapsed_seconds, oldStage) : incoming.stage_elapsed_seconds : null;
          timingReceived = now;
        }
        timing = incoming; timingJob = job; timingSnapshot = snapshot;
        timingRunning = running; timingStage = result.stage;
      }
      if (timingRunning) timingTimer = setInterval(updateTiming, 1000);
    }
    function updateTiming() {
      if (!timing || !timingTotalNode?.isConnected) return;
      // Use the server duration plus local monotonic time, never wall-clock dates.
      const additional = timingRunning ? Math.max(0, performance.now() - timingReceived) / 1000 : 0;
      const total = timingBaseTotal + additional;
      timingTotalNode.textContent = `${timingRunning ? "总已耗时（本地估算）" : "总耗时"} ${duration(total)} · 执行上限 3:00` +
        (timingRunning && total >= 180 ? " · 已达估算上限，等待后台确认状态" : "");
      if (timingStageNode) timingStageNode.textContent =
        `${labels[timingStage] || "当前阶段"}已耗时 ${duration(timingBaseStage + additional)}`;
    }
    function appendTiming(panel) {
      if (!timing) return;
      timingTotalNode = element("p", "", "search-timing-total");
      timingTotalNode.setAttribute("aria-live", "off"); panel.append(timingTotalNode);
      timingStageNode = null;
      if (timingRunning && validSeconds(timingBaseStage)) {
        timingStageNode = element("p", "", "search-timing-stage");
        timingStageNode.setAttribute("aria-live", "off"); panel.append(timingStageNode);
      }
      updateTiming();
      if (timingRunning) return;
      const stages = Array.isArray(timing.stages) ? timing.stages.filter(row => row && typeof row === "object") : [];
      const requests = Array.isArray(timing.requests) ? timing.requests.filter(row => row && typeof row === "object") : [];
      if (!stages.length && !requests.length) return;
      const details = document.createElement("details"); details.className = "search-timing-details";
      details.append(element("summary", "各阶段与请求耗时"));
      for (const row of stages) details.append(element("p",
        `${labels[row.stage] || "处理阶段"}：${detailedSeconds(row.elapsed_seconds)}`));
      for (const row of requests) {
        const route = row.route === "direct" ? "直连" : /proxy/.test(String(row.route)) ? "模型代理" : "链路未记录";
        const outcome = row.error_code ? ` · ${errors[row.error_code] || "请求未完成"}` :
          Number.isInteger(row.http_status) ? ` · HTTP ${row.http_status}` : "";
        details.append(element("p", `${labels[row.stage] || "接口请求"} · ${route} · 等待响应 ${detailedSeconds(row.response_wait_seconds)}` +
          ` · 读取响应 ${detailedSeconds(row.body_read_seconds)} · 合计 ${detailedSeconds(row.total_seconds)}${outcome}`));
      }
      details.append(element("p", "等待响应包含网络传输和服务端处理，不能据此计算纯模型推理时间。", "field-hint"));
      panel.append(details);
    }
    function progress(title, note = "", working = false) {
      const panel = $("icon-search-progress");
      panel.hidden = false; panel.classList.toggle("is-busy", working);
      panel.replaceChildren(element("strong", title, "search-progress-title"));
      if (note) panel.append(element("p", note, "search-progress-note"));
      appendTiming(panel);
      $("icon-results").setAttribute("aria-busy", String(working));
      $("icon-result-empty").hidden = true;
    }
    function resultProgress(result) {
      rememberTiming(result);
      const count = result.candidates?.length || 0;
      const error = resultError(result);
      if (active(result)) {
        const recognizing = result.mode === "recognize" || operation === "recognize";
        progress(cancelling ? "正在取消搜索" : result.state === "queued" ? recognizing ? "等待识别" : "等待搜索" : recognizing ? "识别中" : "搜索中",
          cancelling ? "等待后台确认，当前结果会保留。" :
            `${labels[result.stage] || "等待搜索进度"}${count ? ` · 已发现 ${count} 条候选` : ""}`, true);
      } else if (result.error === "cancelled" || result.state === "cancelled") {
        progress("搜索已取消", count ? `已保留 ${count} 条候选，尚未核实或访问。` : "本次没有可展示的候选。");
      } else if (recognized(result)) {
        progress("名称已识别，请确认后搜索", recognitionEditVersion !== editVersion ?
          "保留你已修改的名称。确认左侧名称后点击定向搜索。" :
          "名称已回填到左侧，可以修改。点击定向搜索才会请求搜索服务。");
      } else if (count) {
        progress(candidateSummary(result),
          `${error ? error + " " : result.state !== "completed" ? "搜索尚未完成。" : ""}候选未核实，尚未访问目标网站。`);
      } else if (result.state === "completed" && !result.error) {
        progress("本次未找到候选", "不代表没有 Android 版本。");
      } else {
        progress(result.error === "icon_timeout" ? "搜索超时" : "搜索失败", error || "未取得完整搜索结果。");
      }
    }
    const update = () => {
      $("search-tab-status").textContent = busy ? cancelling ? "取消中" : operation === "recognize" ? "识别中" : "搜索中" : resultStatus;
      $("icon-search-button").disabled = busy || !capability("recognize") || (!file && pending?.kind !== "recognize") || !!pending && pending.kind !== "recognize";
      $("icon-search-button").textContent = pending?.kind === "recognize" && !current ? "重试本次提交" : "识别名称";
      $("name-search-button").disabled = busy || !capability("name") || (!nameValue() && pending?.kind !== "name") || !!pending && pending.kind !== "name";
      $("name-search-button").textContent = pending?.kind === "name" && !current ? "重试本次提交" : "定向搜索";
      $("name-search-name").disabled = !enabled() || operation === "name" && (busy || !!pending);
      $("icon-file").disabled = busy || !!pending;
      $("icon-remove").disabled = busy || !!pending;
      $("icon-cancel").hidden = !current || !busy;
      $("icon-cancel").disabled = cancelling;
      $("search-mode-image").disabled = !enabled() || !!pending;
      $("search-mode-name").disabled = !enabled() || !!pending;
      const value = capabilities?.();
      for (const refresh of sampleControls) refresh();
      $("search-capability-note").textContent = !enabled() || !capabilities ? "" : !value ? "正在读取搜索能力…" :
        !capability("recognize") && capability("name") ? "截图识别未配置，可直接输入名称搜索。" :
        capability("recognize") && !capability("name") ? "名称检索未配置，目前仅可识别名称。" :
        !capability("recognize") && !capability("name") ? "后台尚未配置识别或名称检索服务。" : "";
    };
    function setMode(value) {
      mode = value;
      $("icon-recognition-input").hidden = mode !== "image";
      $("search-mode-image").setAttribute("aria-pressed", String(mode === "image"));
      $("search-mode-name").setAttribute("aria-pressed", String(mode === "name"));
      update();
    }
    function select(value) {
      if (!value || busy || pending) return;
      if (value.size > 10 * 1024 * 1024) { text("图片最大 10 MiB。"); return; }
      reset(); file = value; preview = URL.createObjectURL(value);
      $("icon-preview").src = preview; $("icon-preview").hidden = false;
      setMode("image"); text("已选择截图。点击识别名称后才会提交到模型。"); update();
    }
    function reset() {
      epoch++; clearTimeout(timer); timer = null;
      sampleControls.length = 0;
      clearTiming();
      if (preview) URL.revokeObjectURL(preview);
      preview = file = pending = current = null; busy = false; cancelling = false; resultStatus = ""; pendingCollect.clear();
      recognitionId = appliedRecognition = recognitionEditVersion = operation = null; editVersion++;
      $("name-search-name").value = "";
      $("icon-file").value = ""; $("icon-preview").hidden = true; $("icon-preview").removeAttribute("src");
      $("icon-results").replaceChildren(); text(""); update();
      $("icon-search-progress").replaceChildren(); $("icon-search-progress").hidden = true;
      $("icon-search-progress").classList.remove("is-busy"); $("icon-results").setAttribute("aria-busy", "false");
      $("icon-result-empty").hidden = false; $("icon-results").hidden = true;
      setMode("image");
    }
    function render(result) {
      sampleControls.length = 0;
      const area = $("icon-results"), scrollTop = area.scrollTop;
      const weakOpen = area.querySelector(".icon-weak-candidates")?.open ?? true;
      const modelOpen = area.querySelector(".icon-model-details")?.open || false;
      const focusKey = area.contains(document.activeElement) ? document.activeElement.dataset.focusKey : null;
      const content = document.createDocumentFragment();
      renderContent(result, content, weakOpen, modelOpen);
      if (!active(result) && result.expires_at) content.append(element("p",
        `任务材料和结果保留至 ${new Date(result.expires_at * 1000).toLocaleString()}。`, "field-hint"));
      area.replaceChildren(content);
      $("icon-result-empty").hidden = true; area.hidden = false;
      // Restore only a control the user was using, never take focus from another view.
      if (focusKey && !$("icon-search-panel").hidden) {
        const target = [...area.querySelectorAll("[data-focus-key]")].find(node => node.dataset.focusKey === focusKey);
        if (target && !target.disabled) target.focus({preventScroll:true});
      }
      area.scrollTop = scrollTop;
    }
    function renderContent(result, area, weakOpen, modelOpen) {
      if (result.query_name) area.append(element("p", `本次检索名称：${result.query_name}`));
      const recognition = result.recognition;
      if (recognition) {
        area.append(element("p", `识别名称：${recognition.name || "未读到名称"} · ${recognition.confidence === "high" ? "高" : recognition.confidence === "medium" ? "中" : "低"}置信度`));
        if (result.icon_sha256) {
          const img = document.createElement("img"); img.alt = result.crop_applied ? "本次识别的图标" : "本次识别图片"; img.className = "icon-crop";
          img.src = `/api/icon-searches/${result.id}/image/icon`; area.append(img);
        }
        if (recognition.requested_model !== recognition.returned_model) {
          const details = document.createElement("details"); details.className = "icon-model-details"; details.open = modelOpen;
          const summary = element("summary", "模型返回有差异"); summary.dataset.focusKey = "model-summary";
          details.append(summary, element("p", `请求：${recognition.requested_model || "未提供"}；返回：${recognition.returned_model || "未提供"}`, "field-hint"));
          area.append(details);
        }
      }
      const catalog = result.catalog_status;
      if (catalog && typeof catalog === "object") {
        const box = element("section", "", "catalog-status");
        box.setAttribute("aria-label", "样本库查询状态");
        const amount = value => Number.isInteger(value) && value >= 0 ? value : null;
        if (catalog.status === "hit") {
          const count = amount(catalog.count), returned = amount(catalog.returned), pageReturned = amount(catalog.page_returned);
          const scope = count !== null ? `库返回 ${count} 条记录${returned === null ? "" : `，本次展示 ${returned} 条`}` :
            `${pageReturned === null ? "库内查询已命中" : `本页返回 ${pageReturned} 条`}${returned === null ? "" : `，本次展示 ${returned} 条`}，总数未提供`;
          box.append(element("strong", "Koodous 样本库查询有记录"), element("p",
            `${scope}。Koodous 提供样本元数据。`));
          if (catalog.next_page_available) box.append(element("p", "还有后续结果，本次未翻页。"));
          if (catalog.coverage_complete === false || catalog.truncated === true ||
              count !== null && returned !== null && returned < count ||
              pageReturned !== null && returned !== null && returned < pageReturned)
            box.append(element("p", "本次结果覆盖不完整，不能视为库内全部记录。"));
        } else if (catalog.status === "no_record") {
          box.append(element("strong", "Koodous 本次名称查询无记录"), element("p", "只说明本次检索未返回记录，不代表不存在该应用或 APK。"));
        } else if (catalog.status === "unconfigured") {
          box.append(element("strong", "Koodous 接口未配置"), element("p", "本次使用定向网页线索；也可通过下方官方入口自行查询。"));
        } else if (catalog.status === "failed") {
          const status = catalog.http_status;
          const message = status === 401 ? "库接口未授权（HTTP 401），无法判断是否收录。" :
            status === 403 ? "库接口访问被拒绝（HTTP 403），无法判断是否收录。" :
            status === 429 ? "库接口限流（HTTP 429），本次未取得完整结果。" :
            Number.isInteger(status) && status >= 100 && status <= 599 ? `库接口请求未完成（HTTP ${status}），无法判断是否收录。` :
            "库接口查询未完成，无法判断是否收录。";
          box.append(element("strong", "Koodous 样本库查询未完成"), element("p", message), element("p", "其他渠道的网页候选会分别保留，仍需核实。"));
        }
        if (box.childNodes.length) area.append(box);
      }
      if (result.mode === "name" && (!catalog || catalog.status === "unconfigured") && !result.candidates?.some(item => item.category === "sample_index")) {
        const libraries = element("section", "", "sample-library-links");
        libraries.append(element("h3", "外部样本库入口"), element("p", "可复制名称检索式到库内查询，需相应账号权限。这些入口不表示本服务已取得库内结果。"));
        const queryName = String(result.query_name || "").replace(/["\\]/g, "");
        const defaults = [{provider:"Koodous", url:"https://koodous.com/", query:`app: "${queryName}"`},
          {provider:"VirusTotal", url:"https://www.virustotal.com/gui/home/search", query:`type:apk androguard:"${queryName}"`}];
        const supplied = Array.isArray(result.library_queries) ? result.library_queries.filter(item =>
          defaults.some(value => item?.provider === value.provider && item.url === value.url) &&
          typeof item.query === "string" && item.query.length <= 400) : [];
        for (const {provider:title, url, query} of supplied.length ? supplied : defaults) {
          const row = element("div", "", "sample-library-row"), link = externalLink(url, `打开 ${title} ↗`);
          if (!link) continue;
          const copy = element("button", "复制检索式", "text-button"); copy.type = "button";
          copy.onclick = async () => { copy.textContent = await copyUrl(query) ? "已复制" : "复制受限，请手动复制下方文字"; };
          row.append(link, copy, element("code", query, "sample-library-query")); libraries.append(row);
        }
        area.append(libraries);
      }
      if (!result.candidates?.length) return;
      const strong = strongCandidates(result);
      const weak = document.createElement("details");
      weak.className = "icon-weak-candidates"; weak.open = weakOpen;
      const summary = element("summary", `弱相关候选 · ${result.candidates.length - strong.length} 条`);
      summary.dataset.focusKey = "weak-summary"; weak.append(summary);
      let weakCount = 0;
      for (const candidate of result.candidates) {
        const card = element("div", "", "icon-candidate");
        const categories = {sample_record:"Koodous 样本记录（API 元数据）", sample_index:"样本库网页线索", download_page:"安卓下载页候选", web_candidate:"网页线索"};
        if (categories[candidate.category]) card.append(element("span", categories[candidate.category], "candidate-category"));
        card.append(element("strong", candidate.title || candidate.source));
        if (candidate.category === "sample_record") {
          const metadata = element("div", "", "sample-record-metadata");
          for (const [label, value] of [["库内应用名", candidate.app_name], ["包名", candidate.package_name],
            ["版本", candidate.version ?? candidate.version_name]]) {
            if (typeof value === "string" && value) metadata.append(element("p", `${label}：${value.slice(0, 300)}`));
          }
          if (typeof candidate.sha256 === "string" && /^[a-f0-9]{64}$/i.test(candidate.sha256)) metadata.append(element("p", `SHA-256：${candidate.sha256}`));
          if (metadata.childNodes.length) card.append(metadata);
        }
        const urlRow = element("div", "", "icon-candidate-url-row");
        const urlText = element("span", candidate.url, "icon-candidate-url");
        const copy = element("button", "复制", "text-button icon-copy-button");
        copy.type = "button"; copy.dataset.focusKey = `copy:${candidate.id}`;
        copy.setAttribute("aria-label", "复制候选链接");
        const feedback = element("span", "", "icon-copy-feedback");
        feedback.setAttribute("role", "status");
        let copying = false;
        copy.onclick = async () => {
          if (copying) return;
          copying = true;
          const copied = await copyUrl(candidate.url);
          copying = false;
          if (!copy.isConnected) return;
          copy.textContent = copied ? "已复制" : "复制";
          feedback.textContent = copied ? "链接已复制" : "复制受限，链接已选中，请按 Ctrl+C。";
          if (!copied) {
            const range = document.createRange(); range.selectNodeContents(urlText);
            const selection = window.getSelection(); selection?.removeAllRanges(); selection?.addRange(range);
          }
        };
        urlRow.append(urlText, copy); card.append(urlRow, feedback);
        const reasons = {name_in_title:"标题含检索名称", android_text:"包含 Android / APK 文字", provider_exact_match:"搜图服务标注匹配", name_web_search:"名称网页搜索", sample_index_search:"样本库定向网页检索", targeted_download_search:"安卓下载页定向检索", koodous_api:"Koodous 库名称查询"};
        const explanation = candidate.evidence.map(v => reasons[v]).filter(Boolean).join(" · ") ||
          (candidate.channel === "koodous_api" ? "Koodous 库名称查询" : result.mode === "name" ? "名称检索线索，相关性待核实" : "仅搜图候选，相关性待核实");
        card.append(element("small", explanation));
        if (candidate.category && candidate.category !== "download_page") {
          const link = externalLink(candidate.url, candidate.category === "sample_record" ? "查看样本记录 ↗" : "查看资料 ↗"); if (link) card.append(link);
          if (candidate.category === "sample_record") {
            const refresh = globalThis.FxfetchSampleSources?.attach({card, result, candidate, api, key,
              enabled, capabilities, element});
            if (refresh) sampleControls.push(refresh);
          } else card.append(element("small", "资料页未验证为可下载 APK。"));
          if (strong.includes(candidate)) area.append(card);
          else { weak.append(card); weakCount++; }
          continue;
        }
        if (result.mode === "name" && candidate.category !== "download_page") {
          if (strong.includes(candidate)) area.append(card);
          else { weak.append(card); weakCount++; }
          continue;
        }
        const button = element("button", "追踪下载", "text-button icon-collect-button"); button.type = "button";
        button.dataset.focusKey = `candidate:${candidate.id}`;
        button.disabled = active(result);
        button.onclick = async () => {
          if (!enabled() || busy || pending) return;
          const generation = epoch; button.disabled = true;
          const token = pendingCollect.get(candidate.id) || key(); pendingCollect.set(candidate.id, token);
          try {
            const job = await api(`/api/icon-searches/${result.id}/collect`, {method:"POST",
              headers:{"Idempotency-Key":token}, body:{candidate_id:candidate.id, tls_policy:$("tls-policy").value}});
            if (generation !== epoch) return;
            pendingCollect.delete(candidate.id); await collected(job);
            text("已提交追踪任务，请在任务与文件中查看进度。");
          } catch (error) { if (generation === epoch) text(errors[error.code] || error.message); }
          finally { button.disabled = false; }
        };
        card.append(button);
        if (strong.includes(candidate)) area.append(card);
        else { weak.append(card); weakCount++; }
      }
      if (weakCount) area.append(weak);
    }
    async function poll(generation) {
      if (generation !== epoch || !current) return;
      try {
        const result = await api(`/api/icon-searches/${current}`);
        if (generation !== epoch) return;
        busy = active(result);
        if (!busy) cancelling = false;
        if (recognized(result) && result.id !== appliedRecognition) {
          recognitionId = result.id; appliedRecognition = result.id;
          if (recognitionEditVersion === editVersion && result.recognition?.name) $("name-search-name").value = result.recognition.name;
        }
        resultStatus = result.error === "cancelled" || result.state === "cancelled" ? "已取消" :
          recognized(result) ? "待确认名称" :
          result.candidates?.length ? `${result.candidates.length} 条候选${result.error || result.state !== "completed" ? " · 未完成" : ""}` :
          result.error === "icon_timeout" ? "已超时" : result.error || result.state !== "completed" ? "失败" : "无候选";
        text(result.error ? resultError(result) : labels[result.stage] || "搜索中");
        resultProgress(result); render(result); update();
        if (busy) timer = setTimeout(() => poll(generation), 2000);
      } catch (error) {
        if (generation !== epoch) return;
        text(error.message);
        if (!error.status || error.status >= 500) {
          progress("暂时无法更新进度", "正在重试获取状态，尚不能确认搜索是否结束。", true);
          timer = setTimeout(() => poll(generation), 4000);
        } else {
          busy = false; cancelling = false; resultStatus = "状态不可用";
          progress("无法读取搜索状态", error.message); update();
        }
      }
    }
    $("icon-file").onchange = event => select(event.target.files[0]);
    $("icon-upload").onclick = () => { if (!busy && !pending) $("icon-file").click(); };
    $("icon-remove").onclick = () => {
      const name = $("name-search-name").value;
      reset(); $("name-search-name").value = name; editVersion++; setMode("name");
    };
    $("icon-search-panel").onpaste = event => {
      const item = Array.from(event.clipboardData?.items || []).find(v => v.kind === "file" && v.type.startsWith("image/"));
      if (item) { event.preventDefault(); select(item.getAsFile()); }
    };
    $("icon-search-panel").ondragover = event => event.preventDefault();
    $("icon-search-panel").ondrop = event => { event.preventDefault(); select(event.dataTransfer.files[0]); };
    $("search-mode-image").onclick = () => { if (enabled() && !pending) setMode("image"); };
    $("search-mode-name").onclick = () => { if (enabled() && !pending) { setMode("name"); $("name-search-name").focus(); } };
    $("name-search-name").oninput = () => { editVersion++; update(); };
    $("name-search-name").onkeydown = event => {
      if (event.key === "Enter" && !event.isComposing && event.keyCode !== 229) {
        event.preventDefault(); $("name-search-button").click();
      }
    };
    async function submit(kind) {
      if (busy || !capability(kind) || pending && pending.kind !== kind) return;
      if (!pending) {
        if (kind === "recognize" && !file || kind === "name" && !nameValue()) return;
        pending = {kind, token:key(), file, name:nameValue(), recognition_id:mode === "image" ? recognitionId : null};
        if (kind === "recognize") recognitionEditVersion = editVersion;
      }
      const request = pending, generation = epoch;
      operation = kind; current = null; resultStatus = "";
      busy = true; cancelling = false; update(); text(kind === "recognize" ? "正在提交截图识别名称…" : "正在提交名称检索…");
      clearTiming();
      sampleControls.length = 0;
      $("icon-results").replaceChildren(); $("icon-results").hidden = true;
      progress(kind === "recognize" ? "正在识别名称" : "搜索中", kind === "recognize" ? "正在提交截图…" : "正在提交名称…", true);
      try {
        let result;
        if (kind === "recognize") {
          const form = new FormData(); form.append("file", request.file);
          result = await api("/api/icon-recognitions", {method:"POST", upload:true, body:form, headers:{"Idempotency-Key":request.token}});
        } else {
          const body = {name:request.name};
          if (request.recognition_id) body.recognition_id = request.recognition_id;
          result = await api("/api/name-searches", {method:"POST", body, headers:{"Idempotency-Key":request.token}});
        }
        if (generation !== epoch) return;
        pending = null; current = result.id; await poll(generation);
      } catch (error) {
        if (generation !== epoch) return;
        if (error.status && error.status < 500) pending = null;
        busy = false; resultStatus = pending ? "提交未确认" : "未启动";
        text(errors[error.code] || error.message);
        progress(pending ? "搜索提交未确认" : "搜索未启动", pending ? "可重试本次提交，避免重复创建任务。" : errors[error.code] || error.message);
        update();
      }
    }
    $("icon-search-button").onclick = () => submit("recognize");
    $("name-search-button").onclick = () => submit("name");
    $("icon-cancel").onclick = async () => {
      if (!current || cancelling || !busy) return;
      const generation = epoch; cancelling = true; update();
      progress("正在取消搜索", "等待后台确认，当前结果会保留。", true);
      try {
        await api(`/api/icon-searches/${current}/cancel`, {method:"POST"});
        if (generation !== epoch || !busy) return;
        text("已请求取消，等待后台确认。");
      } catch (error) {
        if (generation !== epoch || !busy) return;
        cancelling = false; text(error.message); update();
        progress("取消请求未确认", "搜索状态仍待确认，可再次取消。", busy);
      }
    };
    update();
    return {reset, update};
  }
};
