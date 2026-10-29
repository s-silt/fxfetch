"use strict";

(() => {
  function isPending(job) {
    return ["pending", "building"].includes(job?.data_package?.state);
  }

  function render(job, container, {node, bytes, friendly}) {
    const bundle = job.data_package;
    if (!bundle) return;
    const panel = node("section", "details data-package");
    panel.append(node("h3", "", "网页材料与数据包"));
    const materials = bundle.web_materials;
    if (materials && Number.isInteger(materials.count) && materials.count >= 0) {
      panel.append(node("p", "", materials.count > 0
        ? `已保存 ${materials.count} 项网页材料，仅覆盖本次访问；可能包含受阻页面。`
        : "未取得网页材料；数据包只能保留本次访问记录及原包引用（如有）。"));
    }
    if (bundle.state === "ready") {
      const card = node("div", "file-card");
      const info = node("div", "file-info");
      info.append(node("strong", "", bundle.filename || "数据包.zip"));
      info.append(node("small", "", `后台已保存 · ZIP · ${bytes(bundle.size)}`));
      const link = node("a", "file-link", "下载数据包");
      link.href = `/api/jobs/${encodeURIComponent(job.id)}/data-package`;
      link.setAttribute("download", "");
      card.append(info, link);
      panel.append(card, node("p", "muted", "APK / IPA 单独下载，不重复放入 ZIP；原包哈希及来源保留在包内。数据包可能包含敏感网址与正文，请妥善保管。"));
    } else if (isPending(job)) {
      panel.append(node("p", "muted", bundle.state === "building"
        ? "正在后台整理数据包，不会重新访问目标。"
        : "数据包将在本次采集结束后由后台保存。"));
    } else if (bundle.state === "failed") {
      panel.append(node("p", "result-note", "数据包未能完成后台归档，原包下载结果不受影响。"));
      if (bundle.reason_code) panel.append(node("p", "muted", friendly(bundle.reason_code)));
    } else {
      panel.append(node("p", "muted", "此记录没有可下载的后台数据包。"));
    }
    if (materials?.gaps?.length) {
      panel.append(node("p", "muted", "材料存在缺口，具体限制以数据包内记录为准；保存记录不代表访问成功或采全网站。"));
    }
    container.append(panel);
  }

  globalThis.FxfetchDataPackage = Object.freeze({isPending, render});
})();
