"use strict";

(() => {
  const tlsReasons = {
    tls_fallback_handshake_failed:"证书错误后的重握手仍然失败，未取得连接证书原件",
    tls_policy_continuation_unconfirmed:"证书错误后的继续操作未得到确认",
    tls_policy_restore_failed:"证书处理设置的清理未得到确认",
    browser_tls_observation_unbound:"缺少可靠的响应关联",
    browser_tls_origin_limit:"站点数量达到证书采集上限",
    browser_tls_capture_budget:"任务已取消或证书采集预算已耗尽",
    browser_tls_query_timeout:"Chrome 读取证书超时",
    browser_tls_query_unavailable:"Chrome 证书接口不可用或调用失败",
    browser_tls_chain_invalid:"Chrome 返回的证书链格式异常",
    browser_tls_chain_limit:"证书链长度超过保存上限",
    browser_tls_certificate_invalid:"证书内容无效或超过单证大小限制",
    browser_tls_certificate_limit:"证书总大小达到保存上限",
    browser_tls_certificate_storage_failed:"证书保存失败或剩余空间不足",
    browser_tls_certificate_empty:"Chrome 未返回证书原件",
    browser_tls_trace_budget:"Chrome 网络证书采集预算已耗尽或任务已取消",
    browser_tls_trace_unavailable:"Chrome 网络证书接口不可用或调用失败",
    browser_tls_trace_stream_missing:"Chrome 未返回网络证书记录流",
    browser_tls_trace_size_limit:"Chrome 网络记录超过读取上限",
    browser_tls_trace_invalid:"Chrome 网络证书记录格式异常",
    browser_tls_trace_close_failed:"Chrome 网络证书记录流关闭失败",
    browser_tls_trace_data_loss:"Chrome 网络记录缓冲区存在丢失",
    browser_tls_trace_event_invalid:"Chrome 网络证书事件格式异常",
    browser_tls_trace_event_limit:"Chrome 网络证书事件达到读取上限",
    browser_tls_trace_certificate_empty:"Chrome 网络记录未包含可保存的证书原件",
    tls_certificate_original_missing:"记录中未保存相应证书原件",
    tls_certificate_chain_partial:"证书链仅保存了部分成员",
  };
  function isPending(job) {
    return ["pending", "building"].includes(job?.data_package?.state);
  }

  function renderTls(summary, panel, node) {
    if (!summary) return;
    if (summary.state === "not_applicable") {
      panel.append(node("p", "muted", "TLS 证书：本次没有可导出证书的 HTTPS 观察记录。"));
      return;
    }
    const saved = (summary.http_certificates || 0) + (summary.chrome_certificates || 0);
    const message = summary.state === "not_captured"
      ? "TLS 证书原件未取得；数据包保留未取得原因，不用指纹代替原件。"
      : `TLS 证书原件已保存 ${saved} 份：HTTP ${summary.http_certificates} 份，Chrome ${summary.chrome_certificates} 份。${summary.state === "partial" ? "部分证书或链成员未取得。" : ""}`;
    panel.append(node("p", summary.state === "not_captured" ? "result-note" : "muted", message));
    if (summary.association_limited) {
      panel.append(node("p", "muted", "Chrome 原件的采集来源、链序号及关联范围已记入清单；仅能关联到站点快照或浏览器网络事件时，不能据此确认属于某一次具体连接。"));
    }
    if (summary.reasons?.length) {
      const reasons = [...new Set(summary.reasons.map(reason => Object.hasOwn(tlsReasons, reason) ? tlsReasons[reason] : null).filter(Boolean))].slice(0, 4);
      panel.append(node("p", "muted", reasons.length
        ? `证书获取限制：${reasons.join("；")}。完整原因及来源见数据包清单。`
        : "证书获取存在缺口，具体原因及来源见数据包清单。"));
    }
  }

  function render(job, container, {node, bytes, friendly}) {
    const bundle = job.data_package;
    if (!bundle) return;
    const panel = node("section", "details data-package");
    panel.append(node("h3", "", "原文件、网页材料与数据包"));
    const materials = bundle.web_materials;
    if (materials && Number.isInteger(materials.count) && materials.count >= 0) {
      panel.append(node("p", "", materials.count > 0
        ? `已保存 ${materials.count} 项网页材料，仅覆盖本次访问；可能包含受阻页面。`
        : "未取得网页材料；数据包保留本次访问记录及实际保存的原文件（如有）。"));
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
      panel.append(card);
      const attachments = bundle.attachments;
      if (attachments && Number.isInteger(attachments.packages) && Number.isInteger(attachments.certificates)) {
        panel.append(node("p", "muted", `包内原文件：APK / IPA ${attachments.packages} 个，TLS 证书 ${attachments.certificates} 份。校验失败的原文件仍标为失败；仅有指纹的证书无法还原原件。`));
      } else {
        panel.append(node("p", "muted", "此旧版数据包可能仅含原包引用；具体原件及缺口以清单为准。"));
      }
      renderTls(bundle.tls_certificates, panel, node);
      panel.append(node("p", "muted", "原文件也可单独下载。ZIP 保存原始字节与来源，归档成功不代表 APK 校验通过。数据包可能包含敏感网址与正文，请妥善保管。"));
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
