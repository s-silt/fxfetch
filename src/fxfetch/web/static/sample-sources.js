/* Manual exact-hash requests for retained Koodous records. */
"use strict";
globalThis.FxfetchSampleSources = {
  attach({card, result, candidate, api, key, enabled, capabilities, element}) {
    if (result.mode !== "name" || !["completed", "partial"].includes(result.state) ||
        result.catalog_status?.provider !== "Koodous" || result.catalog_status.status !== "hit" ||
        candidate.category !== "sample_record" || candidate.channel !== "koodous_api" ||
        !candidate.evidence?.includes("koodous_api_record") ||
        !/^[a-f0-9]{32}$/.test(result.id) || !/^(?:[1-9]|[1-3][0-9]|40)$/.test(candidate.id) ||
        !/^[a-f0-9]{64}$/.test(candidate.sha256) ||
        candidate.url !== "https://koodous.com/apks/" + candidate.sha256) return;

    const controls = [
      {source:"malshare", provider:"MalShare", prefix:"malshare_"},
      {source:"malwarebazaar", provider:"MalwareBazaar", prefix:"bazaar_"}
    ].map(info => this.attachProvider({card, result, candidate, api, key, enabled, capabilities, element, ...info}));
    return () => controls.forEach(update => update());
  },
  attachProvider({card, result, candidate, api, key, enabled, capabilities, element, source, provider, prefix}) {
    const configured = () => capabilities?.()?.[source + "_enabled"] === true;
    const searchPath = "/api/icon-searches/" + result.id;
    const base = searchPath + "/candidates/" + candidate.id + "/" + source;
    const box = element("div", "", "sample-source " + source + "-record");
    box.setAttribute("role", "group");
    box.setAttribute("aria-label", provider);
    const status = element("p", "", "field-hint");
    status.setAttribute("role", "status");
    const button = element("button", "", "text-button");
    button.type = "button";
    button.dataset.focusKey = source + ":" + candidate.id;
    const file = element("a", `保存 ${provider} 已校验 APK`, "text-button");
    file.download = candidate.sha256 + ".apk";
    file.referrerPolicy = "no-referrer";
    box.append(status, button, file);
    card.append(box);

    const failures = {
      unconfigured:`服务端未配置 ${provider}。`,
      auth:`${provider} 未授权此次请求，请检查密钥及账户状态。`, forbidden:`${provider} 拒绝访问。`,
      quota:`${provider} 额度不足或请求受限。`, daily_limit:"已达本服务的每日操作上限。",
      timeout:`等待 ${provider} 超时。`, connection:`无法连接 ${provider}。`,
      tls:`${provider} 连接的证书或 TLS 校验失败。`, interrupted:"操作已中断。",
      busy:`已有 ${provider} 操作正在执行。`, storage_limit:"已达到样本存储限额。",
      storage:"样本文件保存失败。", hash_mismatch:"文件 SHA-256 与该样本不符。",
      invalid_apk:"文件未通过 APK 结构校验。", incomplete:"文件接收不完整。",
      size_limit:"响应超出大小限制。", no_record:`${provider} 本次取样未返回该文件。`,
      lookup_required:"需要先按 SHA-256 查询该样本。", invalid_hash:"该样本的 SHA-256 无效。",
      http:`${provider} 返回 HTTP 错误。`, response_invalid:`${provider} 返回的数据格式异常。`,
      worker_failed:"处理样本的后台进程失败。", invalid_archive:"下载的压缩包未通过校验。"
    };
    function failure(code) {
      if (typeof code !== "string" || !code.startsWith(prefix)) return "";
      const suffix = code.slice(prefix.length);
      return Object.hasOwn(failures, suffix) ? failures[suffix] : "";
    }
    let receipt = null, action = "lookup", inFlight = "", unconfirmed = false, message = "";
    let pendingToken = null, tokenAction = "";
    function applyReceipt(value) {
      if (value != null && (value.provider !== provider || value.candidate_id !== candidate.id ||
          value.sha256 !== candidate.sha256 ||
          !["running", "hit", "no_record", "failed"].includes(value.lookup?.status) ||
          (value.download != null && !["running", "downloaded", "failed"].includes(value.download.status)) ||
          (value.download?.status === "downloaded" &&
            (value.lookup.status !== "hit" || value.file_url !== base + "/file")))) {
        throw new Error("invalid_receipt");
      }
      receipt = value;
    }
    function update() {
      const lookup = receipt?.lookup, download = receipt?.download;
      const saved = download?.status === "downloaded";
      const running = lookup?.status === "running" || download?.status === "running";
      action = unconfirmed || running ? "refresh" : lookup?.status === "hit" ? "download" : "lookup";
      let note = "";
      if (saved) note = `服务已从 ${provider} 取得 APK，SHA-256 与该样本一致，APK 结构校验通过。`;
      else if (running) note = `服务正在处理 ${provider} 请求，可刷新本地状态。`;
      else if (download?.status === "failed") note = provider + " 下载失败。" + (failure(download.code) || "未取得可验证的 APK。");
      else if (lookup?.status === "no_record") note = `${provider} 本次未查到该 SHA-256。`;
      else if (lookup?.status === "failed") note = provider + " 查询失败。" + (failure(lookup.code) || "无法确认该哈希是否收录。");
      else if (lookup?.status === "hit") note = `${provider} 已收录该 SHA-256，可下载并校验样本。`;
      if (!configured() && !saved && !running && !unconfirmed) note += ` 服务端未配置 ${provider}。`;
      status.textContent = message || (inFlight === "lookup" ? `正在向 ${provider} 查询该 SHA-256…` :
        inFlight === "download" ? `正在从 ${provider} 下载并校验 APK…` : note.trim());
      status.hidden = !status.textContent;
      button.textContent = action === "refresh" ? "刷新本地状态" :
        action === "download" ? `从 ${provider} 下载 APK` : `向 ${provider} 查询 SHA-256`;
      button.hidden = saved;
      button.disabled = !!inFlight || !enabled() || (action !== "refresh" && !configured());
      file.hidden = !saved || !enabled();
      if (!file.hidden) file.setAttribute("href", base + "/file");
      else file.removeAttribute("href");
    }
    button.onclick = async () => {
      if (!box.isConnected || button.disabled || !enabled() || inFlight ||
          (action !== "refresh" && !configured())) return;
      const operation = action;
      inFlight = operation; message = ""; update();
      try {
        if (operation === "refresh") {
          const local = await api(searchPath);
          if (local.id !== result.id) throw new Error("invalid_receipt");
          const previousAttempt = receipt?.[tokenAction]?.requested_at;
          applyReceipt(local[source]?.[candidate.id]);
          if (receipt?.[tokenAction]?.requested_at !== previousAttempt && receipt?.[tokenAction])
            pendingToken = null;
        } else {
          if (!pendingToken || tokenAction !== operation) {
            pendingToken = key(); tokenAction = operation;
          }
          const response = await api(base + "/" + operation, {method:"POST", body:{},
            headers:{"Idempotency-Key":pendingToken}, timeoutMs:195000, cancelOnClear:true});
          if (!response) throw new Error("invalid_receipt");
          applyReceipt(response);
          pendingToken = null;
        }
        unconfirmed = false;
      } catch (error) {
        if (!error.status || (error.status >= 500 && !failure(error.code)) || operation === "refresh") {
          unconfirmed = true;
          message = `暂未确认 ${provider} 操作结果，可刷新本地状态。`;
        } else {
          pendingToken = null;
          message = failure(error.code) || `${provider} 本次操作未完成。`;
        }
      } finally {
        inFlight = "";
        if (box.isConnected) update();
      }
    };
    try { applyReceipt(result[source]?.[candidate.id]); }
    catch { unconfirmed = true; message = `无法核对 ${provider} 的这条样本记录，可刷新本地状态。`; }
    update();
    return update;
  }
};
