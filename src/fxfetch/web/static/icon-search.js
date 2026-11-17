/* Explicit third-party search. Preview and candidate rendering make no target requests. */
"use strict";
globalThis.FxfetchIconSearch = {
  create({api, key, collected, enabled}) {
    const $ = id => document.getElementById(id);
    const labels = {validating:"检查图片", quota:"检查免费搜索额度", recognizing:"识别名称和图标",
      uploading:"提交图标搜图", searching:"搜索 Android 候选", completed:"搜索结束", finished:"搜索结束"};
    const errors = {icon_search_unconfigured:"后台尚未配置识图服务。", icon_search_busy:"已有识图任务运行，请稍后再试。",
      icon_daily_limit:"今日搜索已达 20 次上限。", icon_free_quota_unavailable:"免费额度不足或当前不是免费方案，未继续搜索。",
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
      icon_processing_failed:"图片处理未完成。", cancelled:"搜索已取消。"};
    let file = null, preview = null, pending = null, current = null, timer = null, epoch = 0, busy = false;
    let resultStatus = "", cancelling = false;
    let timing = null, timingTimer = null, timingReceived = 0, timingRunning = false, timingStage = "";
    let timingTotalNode = null, timingStageNode = null;
    const pendingCollect = new Map();
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
    }
    function rememberTiming(result) {
      clearTiming();
      if (!result.timing || !validSeconds(result.timing.total_seconds)) return;
      timing = result.timing; timingReceived = performance.now();
      timingRunning = active(result); timingStage = result.stage;
      if (timingRunning) timingTimer = setInterval(updateTiming, 1000);
    }
    function updateTiming() {
      if (!timing || !timingTotalNode?.isConnected) return;
      // Use the server duration plus local monotonic time, never wall-clock dates.
      const additional = timingRunning ? Math.max(0, performance.now() - timingReceived) / 1000 : 0;
      const total = timing.total_seconds + additional;
      timingTotalNode.textContent = `${timingRunning ? "总已耗时（本地估算）" : "总耗时"} ${duration(total)} · 执行上限 3:00` +
        (timingRunning && total >= 180 ? " · 已达估算上限，等待后台确认状态" : "");
      if (timingStageNode) timingStageNode.textContent =
        `${labels[timingStage] || "当前阶段"}已耗时 ${duration(timing.stage_elapsed_seconds + additional)}`;
    }
    function appendTiming(panel) {
      if (!timing) return;
      timingTotalNode = element("p", "", "search-timing-total");
      timingTotalNode.setAttribute("aria-live", "off"); panel.append(timingTotalNode);
      timingStageNode = null;
      if (timingRunning && validSeconds(timing.stage_elapsed_seconds)) {
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
        progress(cancelling ? "正在取消搜索" : result.state === "queued" ? "等待搜索" : "搜索中",
          cancelling ? "等待后台确认，当前结果会保留。" :
            `${labels[result.stage] || "等待搜索进度"}${count ? ` · 已发现 ${count} 条候选` : ""}`, true);
      } else if (result.error === "cancelled" || result.state === "cancelled") {
        progress("搜索已取消", count ? `已保留 ${count} 条候选，尚未核实或访问。` : "本次没有可展示的候选。");
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
      $("search-tab-status").textContent = busy ? cancelling ? "取消中" : "搜索中" : resultStatus;
      $("icon-search-button").disabled = busy || !file || !enabled();
      $("icon-search-button").textContent = pending && !current ? "重试本次提交" : "一键识图搜索";
      $("icon-file").disabled = busy || !!pending;
      $("icon-remove").disabled = busy || !!pending;
      $("icon-cancel").hidden = !current || !busy;
      $("icon-cancel").disabled = cancelling;
    };
    function select(value) {
      if (!value || busy || pending) return;
      if (value.size > 10 * 1024 * 1024) { text("图片最大 10 MiB。"); return; }
      reset(); file = value; preview = URL.createObjectURL(value);
      $("icon-preview").src = preview; $("icon-preview").hidden = false;
      text("已选择截图。点击一键搜索后才会提交到第三方。"); update();
    }
    function reset() {
      epoch++; clearTimeout(timer); timer = null;
      clearTiming();
      if (preview) URL.revokeObjectURL(preview);
      preview = file = pending = current = null; busy = false; cancelling = false; resultStatus = ""; pendingCollect.clear();
      $("icon-file").value = ""; $("icon-preview").hidden = true; $("icon-preview").removeAttribute("src");
      $("icon-results").replaceChildren(); text(""); update();
      $("icon-search-progress").replaceChildren(); $("icon-search-progress").hidden = true;
      $("icon-search-progress").classList.remove("is-busy"); $("icon-results").setAttribute("aria-busy", "false");
      $("icon-result-empty").hidden = false; $("icon-results").hidden = true;
    }
    function render(result) {
      const area = $("icon-results"), scrollTop = area.scrollTop;
      const weakOpen = area.querySelector(".icon-weak-candidates")?.open ?? true;
      const modelOpen = area.querySelector(".icon-model-details")?.open || false;
      const focusKey = area.contains(document.activeElement) ? document.activeElement.dataset.focusKey : null;
      const content = document.createDocumentFragment();
      renderContent(result, content, weakOpen, modelOpen);
      if (!active(result) && result.expires_at) content.append(element("p",
        `搜索图片和结果保留至 ${new Date(result.expires_at * 1000).toLocaleString()}。`, "field-hint"));
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
      const recognition = result.recognition;
      if (recognition) {
        area.append(element("p", `识别名称：${recognition.name || "未读到名称"} · ${recognition.confidence === "high" ? "高" : recognition.confidence === "medium" ? "中" : "低"}置信度`));
        if (result.icon_sha256) {
          const img = document.createElement("img"); img.alt = "本次用于搜索的图标"; img.className = "icon-crop";
          img.src = `/api/icon-searches/${result.id}/image/icon`; area.append(img);
        }
        if (recognition.requested_model !== recognition.returned_model) {
          const details = document.createElement("details"); details.className = "icon-model-details"; details.open = modelOpen;
          const summary = element("summary", "模型返回有差异"); summary.dataset.focusKey = "model-summary";
          details.append(summary, element("p", `请求：${recognition.requested_model || "未提供"}；返回：${recognition.returned_model || "未提供"}`, "field-hint"));
          area.append(details);
        }
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
        card.append(element("strong", candidate.title || candidate.source));
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
        const reasons = {name_in_title:"标题含识别名称", android_text:"包含 Android / APK 文字", provider_exact_match:"搜图服务标注匹配", name_web_search:"名称网页搜索"};
        card.append(element("small", candidate.evidence.map(v => reasons[v]).filter(Boolean).join(" · ") || "仅搜图候选，相关性待核实"));
        const button = element("button", "追踪下载", "text-button icon-collect-button"); button.type = "button";
        button.dataset.focusKey = `candidate:${candidate.id}`;
        button.disabled = active(result);
        button.onclick = async () => {
          if (!enabled()) return;
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
        resultStatus = result.error === "cancelled" || result.state === "cancelled" ? "已取消" :
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
    $("icon-remove").onclick = reset;
    $("icon-search-panel").onpaste = event => {
      const item = Array.from(event.clipboardData?.items || []).find(v => v.kind === "file" && v.type.startsWith("image/"));
      if (item) { event.preventDefault(); select(item.getAsFile()); }
    };
    $("icon-search-panel").ondragover = event => event.preventDefault();
    $("icon-search-panel").ondrop = event => { event.preventDefault(); select(event.dataTransfer.files[0]); };
    $("icon-search-button").onclick = async () => {
      if (!file || busy || !enabled()) return;
      const generation = epoch; pending ||= key(); current = null; resultStatus = "";
      busy = true; cancelling = false; update(); text("正在提交截图…");
      clearTiming();
      $("icon-results").replaceChildren(); $("icon-results").hidden = true;
      progress("搜索中", "正在提交截图…", true);
      const form = new FormData(); form.append("file", file);
      try {
        const result = await api("/api/icon-searches", {method:"POST", upload:true, body:form, headers:{"Idempotency-Key":pending}});
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
    };
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
