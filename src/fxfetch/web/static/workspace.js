/* Input modules and keyboard-mode barcode readers. No target access occurs here. */
"use strict";
globalThis.FxfetchWorkspace = {
  create({api, canEdit, onScan, onMode}) {
    const $ = id => document.getElementById(id);
    const modes = ["url", "qr", "scanner"];
    let mode = "url", revision = 0, applying = false;
    let view = "collect";
    const viewScroll = {collect:0, search:0};
    function showView(next, focus = false) {
      if (!["collect", "search"].includes(next)) return;
      const changed = next !== view;
      if (changed) {
        viewScroll[view] = $(view === "collect" ? "job-content" : "icon-results").scrollTop;
        view = next;
      }
      $("collect-workspace").hidden = view !== "collect";
      $("icon-search-panel").hidden = view !== "search";
      for (const item of ["collect", "search"]) {
        $("view-" + item).setAttribute("aria-selected", String(item === view));
        $("view-" + item).tabIndex = item === view ? 0 : -1;
      }
      if (changed) $(view === "collect" ? "job-content" : "icon-results").scrollTop = viewScroll[view];
      if (focus) $("view-" + view).focus();
    }
    function select(next, focus = false) {
      if (!modes.includes(next) || !canEdit()) return;
      if (next !== mode) { revision++; applying = false; }
      mode = next;
      onMode?.(mode);
      for (const item of modes) $("mode-" + item).setAttribute("aria-pressed", String(item === mode));
      $("qr-input-panel").hidden = mode !== "qr";
      $("scanner-input-panel").hidden = mode !== "scanner";
      if (focus) $(mode === "scanner" ? "scanner-input" : mode === "qr" ? "dropzone" : "url").focus();
      update();
    }
    function update() {
      const locked = !canEdit();
      for (const item of modes) $("mode-" + item).disabled = locked;
      $("scanner-input").disabled = locked || applying;
      $("scanner-apply").disabled = locked || applying;
    }
    function reset() {
      revision++; applying = false;
      $("scanner-input").value = "";
      $("scanner-status").textContent = "仅接收文字，不会自动访问网址。";
      mode = "url";
      for (const item of modes) $("mode-" + item).setAttribute("aria-pressed", String(item === mode));
      $("qr-input-panel").hidden = $("scanner-input-panel").hidden = true;
      showView("collect");
      viewScroll.collect = viewScroll.search = 0;
      $("job-content").scrollTop = $("icon-results").scrollTop = 0;
      update();
    }
    async function apply() {
      if (!canEdit() || applying) return;
      const value = $("scanner-input").value.trim(), current = ++revision;
      if (!value || value.length > 8192 || /[\x00-\x20\x7f]/.test(value) ||
          !/^(?:(?:https?:\/|\/\/|itms-services:\/\/)|[^/?#]+\.[^/?#]+)/i.test(value)) {
        $("scanner-status").textContent = "请扫描单个完整网址；不支持普通商品条码或多行文字。";
        return;
      }
      applying = true; update();
      $("scanner-status").textContent = "正在检查网址格式…";
      try {
        const result = await api("/api/preview", {method:"POST", body:{url:value}});
        if (current !== revision || !canEdit()) return;
        if (!result.url || !result.request_url || ["unsupported", "store"].includes(result.kind))
          throw new Error("扫码内容不是受支持的下载网址。");
        onScan(result.url);
        $("scanner-status").textContent = "网址已回填。点击「开始采集」才会访问目标。";
        $("scanner-input").value = "";
      } catch (error) {
        if (current === revision) $("scanner-status").textContent = error.message;
      } finally {
        if (current === revision) {
          applying = false; update();
          if (view === "collect" && mode === "scanner") $("scanner-input").focus();
        }
      }
    }
    for (const item of modes) $("mode-" + item).onclick = () => select(item, true);
    $("scanner-input").onkeydown = event => {
      if (event.key === "Enter") {
        // A reader's Enter suffix must never trigger the surrounding download form.
        event.preventDefault(); event.stopPropagation();
        if (!event.isComposing) void apply();
      }
    };
    $("scanner-apply").onclick = apply;
    for (const item of ["collect", "search"]) {
      $("view-" + item).onclick = () => showView(item);
      $("view-" + item).onkeydown = event => {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        showView(event.key === "Home" ? "collect" : event.key === "End" ? "search" :
          view === "collect" ? "search" : "collect", true);
      };
    }
    $("show-tasks").onclick = () => { showView("collect"); $("job-picker").focus(); };
    return {select, update, reset, showView};
  }
};
