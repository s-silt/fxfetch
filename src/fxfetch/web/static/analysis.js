"use strict";

(() => {
  const active = new Set(["queued", "running"]);
  const labels = {queued:"等待离线分析", running:"正在离线分析", completed:"分析完成", failed:"分析未完成", not_analyzed:"未执行分析", cancelled:"分析已取消", interrupted:"分析已中断"};

  function isPending(job) {
    return (job?.analyses || []).some((item) => active.has(item.state));
  }

  function render(job, container, {node, friendly, capability, submitting, onStart, onCancel}) {
    const panel = node("section", "details analysis-panel");
    panel.append(node("h3", "", "网页材料离线分析"));
    panel.append(node("p", "muted", "使用 fxapk 解析后台已保存的数据包，不重新访问目标。分析结果不改变原采集结论，也不代表材料真实、归属已核实或整站覆盖。"));
    const ready = job.data_package?.state === "ready";
    const analyses = job.analyses || [];
    const action = node("button", "primary", submitting ? "正在提交…" : analyses.length ? "重新离线分析" : "离线分析数据包");
    action.type = "button";
    action.disabled = !ready || !capability?.enabled || isPending(job) || submitting;
    action.onclick = () => onStart(action);
    panel.append(action);
    if (!capability?.enabled) {
      panel.append(node("p", "muted", capability
        ? "离线分析未启用：请由后端主机配置已安装的 fxapk。页面不能指定程序或材料路径。"
        : "正在确认后端离线分析能力，尚未启动分析。"));
    } else if (!ready) {
      panel.append(node("p", "muted", "需要本次任务的数据包就绪后才能分析；不会为分析重新采集。"));
    }
    if (analyses.length) panel.append(node("p", "muted", "报告与原始数据包分别下载；报告可能包含敏感网址、线索和主机材料路径，请妥善保管。"));
    for (const item of analyses) {
      const card = node("div", "analysis-result");
      const heading = node("div", "analysis-heading");
      heading.append(node("strong", "", labels[item.state] || "分析状态未知"));
      if (Number.isFinite(item.created)) {
        heading.append(node("small", "muted", new Date(item.created * 1000).toLocaleString("zh-CN")));
      }
      card.append(heading);
      if (item.state === "queued") card.append(node("p", "muted", "独立分析队列，不占用采集或 APK 打包队列。"));
      if (item.state === "running") card.append(node("p", "muted", "正在校验材料、离线解析及整理报告；达到后端时限会停止。"));
      if (item.reason_code) card.append(node("p", "", friendly(item.reason_code)));
      if (item.state === "completed" && item.report_ready) {
        const link = node("a", "file-link", "下载分析报告 ZIP");
        link.href = `/api/jobs/${encodeURIComponent(job.id)}/analyses/${encodeURIComponent(item.id)}/report.zip`;
        link.setAttribute("download", "");
        card.append(link, node("p", "muted", "包含原生 JSON 报告和来源回执，不包含 APK/IPA 或原始数据包；回查原件需同时保留数据包。"));
      }
      if (active.has(item.state)) {
        const cancel = node("button", "text-button", "取消分析");
        cancel.type = "button";
        cancel.onclick = () => onCancel(item.id, cancel);
        card.append(cancel);
      }
      panel.append(card);
    }
    container.append(panel);
  }

  globalThis.FxfetchAnalysis = Object.freeze({isPending, render});
})();
