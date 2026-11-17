/* Model discovery is explicit; opening this panel only reads local settings. */
"use strict";
globalThis.FxfetchModelSettings = {
  create({api, enabled, changed}) {
    const $ = id => document.getElementById(id);
    const panel = $("model-settings");
    const errors = {
      model_list_busy:"正在获取模型列表，请稍后再试。",
      model_list_cooldown:"请求过于频繁，请稍后再次点击获取。",
      model_list_invalid:"供应商未返回有效的模型列表。",
      model_list_limit:"模型列表超过读取上限，未使用不完整列表。",
      model_list_expired:"模型列表已过期，请重新获取后选择。",
      model_not_available:"该模型不在本次获取的列表中，请重新获取后选择。",
      model_settings_changed:"后台模型配置已变化，请重新获取列表。",
      model_settings_unavailable:"模型设置暂不可用，请检查后台配置。",
      icon_search_unconfigured:"后台尚未配置模型服务。",
      icon_provider_auth:"供应商拒绝请求，请检查后台密钥或访问权限。",
      icon_provider_forbidden:"供应商拒绝访问（HTTP 403），请检查模型或节点权限。",
      icon_provider_timeout:"等待供应商响应超时，请稍后手动重试。",
      icon_provider_tls:"供应商的 HTTPS 证书或 TLS 连接校验失败。",
      icon_provider_proxy:"模型代理连接失败，请检查后台代理状态。",
      icon_provider_connection:"无法连接模型供应商，请检查网络或节点状态。",
      icon_provider_response_invalid:"供应商返回的内容格式无效。",
      icon_provider_incomplete:"供应商响应未完整接收。",
      icon_provider_http:"供应商返回异常 HTTP 状态。",
      icon_provider_quota:"供应商接口额度不足或限流。",
      icon_provider_failed:"获取模型列表失败，请稍后手动重试。",
      icon_provider_response_limit:"供应商响应超过读取上限。"
    };
    let epoch = 0, current = "", models = [], listToken = "", pending = "", controller = null, uncertainModel = "";
    const recheck = document.createElement("button");
    recheck.id = "model-recheck"; recheck.type = "button"; recheck.className = "secondary";
    recheck.textContent = "重新核对保存结果"; recheck.hidden = true;
    $("model-settings-status").after(recheck);
    const status = value => { $("model-settings-status").textContent = value; };
    const message = error => {
      const text = errors[error.code] || error.message || "操作未完成，请稍后再试。";
      return error.code === "icon_provider_http" && Number.isInteger(error.httpStatus) && error.httpStatus >= 100 && error.httpStatus <= 599 ? `${text}（上游 HTTP ${error.httpStatus}）` : text;
    };
    function update() {
      const locked = !enabled() || !!pending || !!uncertainModel;
      $("model-current").textContent = uncertainModel ? `${current || "尚未读取"}（保存结果待核对）` : current || "尚未读取";
      $("model-refresh").disabled = locked;
      $("model-refresh").textContent = pending === "refresh" ? "正在获取…" : "获取模型列表";
      $("model-choice").disabled = locked || !listToken;
      $("model-save").disabled = locked || !listToken || !$("model-choice").value || $("model-choice").value === current;
      $("model-save").textContent = pending === "save" ? "正在保存…" : "保存选择";
      $("model-settings-content").setAttribute("aria-busy", String(!!pending));
      recheck.hidden = !uncertainModel;
      recheck.disabled = !enabled() || !!pending;
      recheck.textContent = pending === "reconcile" ? "正在核对…" : "重新核对保存结果";
    }
    function clearList() {
      models = []; listToken = "";
      $("model-choice").replaceChildren(new Option("先获取模型列表，再选择", ""));
      $("model-list-count").textContent = "";
    }
    function reset() {
      epoch++; controller?.abort(); controller = null; pending = ""; current = ""; uncertainModel = "";
      panel.open = false; clearList(); status(""); update();
    }
    function reconcileResult(result) {
      if (typeof result.current_model !== "string") throw new Error("当前模型读取结果无效。");
      const intended = uncertainModel;
      current = result.current_model; uncertainModel = "";
      if (current === intended) {
        clearList(); status("已核对并确认保存成功，之后的图标识别和 AI 辅助选择将使用此模型。");
      } else {
        status(`核对完成：当前实际模型为 ${current}，所选的 ${intended} 未生效；选择仍保留，可确认后手动保存。`);
      }
      changed?.(current);
    }
    async function perform(kind, path, options, accept) {
      if (!enabled() || pending) return;
      const generation = epoch, requestController = new AbortController();
      controller = requestController; pending = kind; update();
      try {
        const result = await api(path, {...options, signal:requestController.signal});
        if (generation !== epoch || !enabled()) return;
        accept(result);
      } catch (error) {
        if (generation !== epoch || !enabled() || error.code === "aborted") return;
        if (kind === "save" && (!error.status || error.status >= 500)) {
          uncertainModel = options.body.model; pending = "reconcile"; update();
          status("保存结果未确认，正在读取本地设置核对；不会重新提交保存请求。");
          try {
            const result = await api("/api/model-settings", {signal:requestController.signal});
            if (generation !== epoch || !enabled()) return;
            reconcileResult(result);
          } catch (readError) {
            if (generation !== epoch || !enabled() || readError.code === "aborted") return;
            status("保存结果未确认，暂时无法读取当前模型。请点击「重新核对保存结果」，核对前不会再次保存。");
          }
          return;
        }
        if (kind === "reconcile") {
          status("保存结果未确认，暂时无法读取当前模型。可再次点击「重新核对保存结果」。");
          return;
        }
        if (["model_list_expired", "model_not_available", "model_settings_changed"].includes(error.code)) clearList();
        status(message(error));
      } finally {
        if (generation === epoch && controller === requestController) {
          controller = null; pending = ""; update();
        }
      }
    }
    function loadCurrent() {
      if (uncertainModel) return perform("reconcile", "/api/model-settings", {}, reconcileResult);
      return perform("read", "/api/model-settings", {}, result => {
        if (typeof result.current_model !== "string") throw new Error("未能读取当前模型。请关闭设置后重试。");
        if (current && current !== result.current_model) clearList();
        current = result.current_model;
      });
    }
    recheck.onclick = () => {
      if (!uncertainModel || !enabled() || pending) return;
      status("正在核对本地保存结果…");
      void perform("reconcile", "/api/model-settings", {}, reconcileResult);
    };
    panel.ontoggle = () => {
      if (panel.open && enabled()) {
        $("service-status").open = false;
        void loadCurrent();
      }
    };
    $("service-status").addEventListener("toggle", () => {
      if ($("service-status").open) panel.open = false;
    });
    $("model-settings-close").onclick = () => { panel.open = false; panel.querySelector("summary").focus(); };
    panel.addEventListener("keydown", event => {
      if (event.key === "Escape") { event.preventDefault(); panel.open = false; panel.querySelector("summary").focus(); }
    });
    $("model-refresh").onclick = () => {
      if (!enabled() || pending) return;
      clearList(); status("正在向已配置的供应商获取模型列表…");
      void perform("refresh", "/api/model-settings/refresh", {method:"POST", body:{}, timeoutMs:35000}, result => {
        if (typeof result.current_model !== "string" || !Array.isArray(result.models) || !result.models.length ||
            result.models.some(value => typeof value !== "string") || typeof result.list_token !== "string" || !result.list_token) {
          throw new Error("供应商未返回有效的模型列表。");
        }
        current = result.current_model; models = [...new Set(result.models)]; listToken = result.list_token;
        const options = [new Option("请选择模型", "")];
        for (const model of models) options.push(new Option(model, model));
        $("model-choice").replaceChildren(...options);
        $("model-list-count").textContent = `已获取 ${models.length} 个模型。`;
        status("列表已就绪。选择模型后，点击「保存选择」生效。");
      });
    };
    $("model-choice").onchange = () => {
      status($("model-choice").value === current ? "该模型已是当前设置。" : "选择尚未保存。");
      update();
    };
    $("model-save").onclick = () => {
      const model = $("model-choice").value;
      if (!enabled() || pending || !listToken || !models.includes(model) || model === current) return;
      status("正在保存模型选择…");
      void perform("save", "/api/model-settings", {method:"POST", body:{model, list_token:listToken}}, result => {
        if (result.current_model !== model) throw new Error("未能确认保存结果，请关闭设置后重新查看当前模型。");
        current = result.current_model; clearList();
        status("已保存，之后的图标识别和 AI 辅助选择将使用此模型。供应商列出模型不代表已验证调用成功。");
        changed?.(current);
      });
    };
    reset();
    return {reset, update};
  }
};
