// Pure Node regression of the real client functions; no browser or network.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../src/fxfetch/web/static/app.js"), "utf8")
  .replace(/^\s*api\("\/api\/session"\).*$/m, "")
  .replace(/\}\)\(\);\s*$/, "globalThis.test = {state, authenticated, pollCapabilities, signedOut, busy, hasActive, submitAnalysis, cancelAnalysis, submitJob, submitContinuation, clearRecords, renderJob, eventText};})();");

function harness(capability, responder = () => ({})) {
  const elements = new Map(), events = new Map(), timers = new Map(), calls = [];
  let timerId = 0, now = 0;
  class Element {
    constructor() { this.value = ""; this.children = []; this.classList = {toggle() {}, add() {}, remove() {}}; }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    setAttribute() {}
    removeAttribute() {}
    querySelectorAll() { return []; }
  }
  const document = {
    hidden:false,
    getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
    createElement() { return new Element(); },
    addEventListener(name, callback) { events.set(name, callback); },
  };
  const context = vm.createContext({
    document, window:{addEventListener() {}}, localStorage:{removeItem() {}, setItem() {}},
    Headers, FormData, AbortController, URL, console, crypto:require("node:crypto").webcrypto,
    Date:class extends Date { static now() { return now; } },
    Option:class extends Element {},
    setTimeout(fn, milliseconds) { const id = ++timerId; timers.set(id, {fn, milliseconds}); return id; },
    clearTimeout(id) { timers.delete(id); },
    async fetch(url, options) {
      calls.push([url, options.method]);
      const data = url === "/api/capabilities" ? await capability(options) : await responder(url, options);
      return {ok:true, status:200, async json() { return data; }};
    },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../src/fxfetch/web/static/data-package.js"), "utf8"), context, {filename:"data-package.js"});
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../src/fxfetch/web/static/analysis.js"), "utf8"), context, {filename:"analysis.js"});
  vm.runInContext(source, context, {filename:"app.js"});
  const settle = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };
  return {
    test:context.test, bundle:context.FxfetchDataPackage, analysis:context.FxfetchAnalysis, document, calls, events, timers, settle,
    async tick() {
      const item = [...timers.entries()].find(([, value]) => value.milliseconds === 4000);
      assert.ok(item, "Expected one bounded readiness retry");
      timers.delete(item[0]); now += 4000;
      await item[1].fn(); await settle();
    },
  };
}

async function main() {
  {
    const ui = harness(() => ({}));
    const text = ui.test.eventText({event:"dns_resolution_observed", provider:"dnspod", query_type:"AAAA", reason_code:"dns_unsafe_answer", dns_record:{answers:["private diagnostic"]}});
    assert.match(text, /DNSPod AAAA/);
    assert.match(text, /非公网或特殊地址，未连接该目标/);
    assert.doesNotMatch(text, /private diagnostic|无 APK|没有 APK/);
    for (const reason_code of ["dns_nxdomain", "dns_no_addresses", "dns_invalid_response", "dns_diagnostics_unavailable", "task_timeout", "chain_timeout"]) {
      const failure = ui.test.eventText({event:"dns_resolution_failed", reason_code});
      assert.notEqual(failure, "DNS：解析未完成");
      assert.doesNotMatch(failure, /无 APK|没有 APK|解析完成/);
    }
    for (const event of ["browser_connection_failed", "browser_transport_failed", "browser_connection_cancelled", "browser_budget_exhausted"]) {
      assert.doesNotMatch(ui.test.eventText({event}), /公网|被拒绝/);
      assert.notEqual(ui.test.eventText({event}), "状态已更新");
    }
    assert.match(ui.test.eventText({event:"browser_connection_blocked"}), /被拒绝/);
  }
  {
    const submissions = [], jobs = new Map();
    let loseReply = false;
    const ui = harness(() => ({}), (url, options) => {
      if (url === "/api/preview") return {request_url:"https://synthetic.test/", url:"https://synthetic.test/", kind:"web"};
      if (options.method === "POST" && (url === "/api/jobs" || url.endsWith("/continue"))) {
        const body = JSON.parse(options.body); submissions.push(body);
        if (loseReply) { loseReply = false; throw new Error("synthetic connection lost"); }
        const job = {id:`job-${submissions.length}`, state:"completed", outcome:"failed", input:{entry_url:"https://synthetic.test/", tls_policy:body.tls_policy}};
        jobs.set(job.id, job); return job;
      }
      if (url === "/api/jobs") return {jobs:options.method === "DELETE" ? [] : [...jobs.values()]};
      return jobs.get(url.split("/").at(-1)) || {};
    });
    const policy = ui.document.getElementById("tls-policy");
    const entry = ui.document.getElementById("url");
    const event = {preventDefault() {}};
    ui.test.state.authenticated = true;
    assert.equal(policy.value, "auto", "Web task starts strict with conditional fallback enabled");
    assert.equal(ui.document.getElementById("advanced-settings").open, false);
    assert.equal(ui.document.getElementById("tls-policy-summary").textContent, "证书：自动处理");
    entry.value = "https://synthetic.test/"; policy.value = "strict";
    policy.onchange();
    assert.equal(ui.document.getElementById("tls-policy-summary").textContent, "证书：严格验证");
    await ui.test.submitJob(event);
    assert.equal(submissions.at(-1).tls_policy, "strict");
    assert.equal(policy.value, "auto", "Acknowledged submission resets next task policy");
    assert.equal(ui.document.getElementById("tls-policy-summary").textContent, "证书：自动处理");
    await ui.test.submitJob(event);
    assert.equal(submissions.at(-1).tls_policy, "auto");
    policy.value = "strict"; loseReply = true;
    await ui.test.submitJob(event);
    assert.equal(ui.test.state.pendingJob.body.tls_policy, "strict");
    assert.equal(policy.disabled, true, "Ambiguous retry cannot change frozen task options");
    policy.value = "auto";
    await ui.test.submitJob(event);
    assert.equal(submissions.at(-1).tls_policy, "strict");
    assert.equal(policy.value, "auto");
    const parent = {id:"parent", input:{tls_policy:"strict"}, download_candidates:[{id:"choice"}]};
    ui.test.state.selectedContinuations.set(parent.id, "choice");
    await ui.test.submitContinuation(parent);
    assert.equal(submissions.at(-1).tls_policy, "auto", "Child starts with its own default policy");
    const second = {...parent,id:"second"};
    ui.test.state.selectedContinuations.set(second.id, "choice");
    ui.test.state.continuationTls.set(second.id, "strict");
    await ui.test.submitContinuation(second);
    assert.equal(submissions.at(-1).tls_policy, "strict");
    assert.equal(ui.test.state.continuationTls.has(second.id), false);
    policy.value = "strict"; ui.test.state.continuationTls.set("draft", "strict");
    await ui.test.clearRecords();
    assert.equal(policy.value, "auto"); assert.equal(ui.test.state.continuationTls.size, 0);
    policy.value = "strict"; ui.test.signedOut(); assert.equal(policy.value, "auto");

  }
  {
    const ui = harness(() => ({}));
    const flatten = element => [element, ...element.children.flatMap(flatten)];
    const job = {id:"tls", state:"completed", outcome:"downloaded", input:{tls_policy:"auto"}, tls_policy:"auto",
      tls_fallback:{state:"recorded", count:0, observed:false, reasons:[]}};
    const warnings = () => flatten(ui.document.getElementById("job-content")).filter(e => e.className === "tls-warning");
    ui.test.state.job = job; ui.test.renderJob();
    assert.equal(warnings().length, 0, "Auto policy alone is not evidence of ignored certificates");
    job.tls_fallback = {state:"recorded", count:1, observed:true, reasons:["self_signed_certificate"]};
    ui.test.renderJob(); assert.match(warnings()[0].textContent, /服务器身份未经验证/);
    job.tls_fallback.state = "unavailable";
    ui.test.renderJob(); assert.match(warnings()[0].textContent, /另有未能确认/);
    job.tls_fallback = {state:"unavailable", count:0, observed:false, reasons:[]};
    ui.test.renderJob(); assert.match(warnings()[0].textContent, /不能确认/);
    delete job.tls_policy; delete job.tls_fallback; job.input = {ignore_tls_errors:true};
    ui.test.renderJob(); assert.match(warnings()[0].textContent, /历史任务/);
  }
  {
    for (const background of [false, true]) {
      const job = {id:"job", state:"completed", outcome:"blocked", data_package:{state:"ready"}, analyses:[]};
      const other = {id:"other", state:"completed", analyses:[]};
      let reads = 0;
      const ui = harness(() => ({}), (url, options) => {
        if (url === "/api/jobs/job/analyses" && options.method === "POST") return {id:"analysis", state:"queued", report_ready:false};
        if (url === "/api/jobs") {
          reads++;
          if (reads <= 2) throw new Error("synthetic list read failure");
          return {jobs:[{id:"job", state:"completed", active_analyses:0}, {id:"other", state:"completed", active_analyses:0}]};
        }
        if (url === "/api/jobs/job") return {...job, analyses:[{id:"analysis", state:"completed", report_ready:true}]};
        if (url === "/api/jobs/other") return other;
        return {};
      });
      ui.test.state.authenticated = true;
      ui.test.state.current = background ? "other" : "job";
      ui.test.state.job = background ? other : job;
      ui.test.state.jobs = [{id:"job", state:"completed", active_analyses:0}, {id:"other", state:"completed", active_analyses:0}];
      await ui.test.submitAnalysis(job, {disabled:false});
      assert.equal(job.analyses[0].state, "queued", "POST result must survive a failed list refresh");
      assert.equal(ui.test.state.pendingAnalyses.size, 0, "Successful POST must not be retried");
      assert.equal(ui.test.hasActive(), true, "Acknowledged analysis must keep polling even in the background");
      async function tickPoll(milliseconds) {
        const timer = [...ui.timers.entries()].find(([, item]) => item.milliseconds === milliseconds);
        assert.ok(timer, "Expected a scheduled analysis progress read");
        ui.timers.delete(timer[0]);
        await timer[1].fn(); await ui.settle();
      }
      await tickPoll(1500);
      assert.equal(ui.test.hasActive(), true);
      await tickPoll(5000);
      assert.equal(ui.test.hasActive(), false, "Terminal server state must stop polling");
      if (!background) assert.equal(ui.test.state.job.analyses[0].report_ready, true);
      assert.equal(ui.calls.filter(([url, method]) => url.endsWith("/analyses") && method === "POST").length, 1);
      assert.equal(reads, 3, "Read failures should recover using GET requests only");
      assert.ok(![...ui.timers.values()].some(item => item.milliseconds === 5000));
    }
  }
  {
    const ui = harness(() => ({}));
    const node = (tag, className, text) => {
      const element = ui.document.createElement(tag);
      Object.assign(element, {tagName:tag, className, textContent:text});
      return element;
    };
    const flatten = element => [element, ...element.children.flatMap(flatten)];
    let started = 0, cancelled = 0;
    const helpers = {node, friendly:code => code, capability:{enabled:true}, submitting:false,
      onStart:() => started++, onCancel:() => cancelled++};
    const job = {id:"job", state:"completed", outcome:"blocked", data_package:{state:"ready"}, analyses:[]};
    const render = () => { const box = node("div", "", ""); ui.analysis.render(job, box, helpers); return flatten(box); };
    let nodes = render();
    assert.equal(nodes.find(item => item.tagName === "button").disabled, false);
    assert.equal(started, 0, "Rendering must not create analysis");
    nodes.find(item => item.tagName === "button").onclick();
    assert.equal(started, 1);
    for (const state of ["queued", "running", "completed", "failed", "cancelled", "interrupted", "not_analyzed"]) {
      job.analyses = [{id:"analysis", state, report_ready:true}];
      nodes = render();
      const active = ["queued", "running"].includes(state);
      assert.equal(ui.test.busy(job), active);
      assert.equal(nodes.find(item => item.tagName === "button").disabled, active);
      const links = nodes.filter(item => item.tagName === "a");
      assert.equal(links.length, state === "completed" ? 1 : 0);
      if (links.length) assert.equal(links[0].href, "/api/jobs/job/analyses/analysis/report.zip");
      const cancel = nodes.find(item => item.textContent === "取消分析");
      assert.equal(!!cancel, active);
      if (cancel) cancel.onclick();
      assert.equal(job.outcome, "blocked");
    }
    assert.equal(cancelled, 2);
    job.analyses = [{id:"analysis", state:"completed", report_ready:false}];
    assert.equal(render().filter(item => item.tagName === "a").length, 0);
    helpers.capability.enabled = false;
    assert.equal(render().find(item => item.tagName === "button").disabled, true);
    helpers.capability.enabled = true; job.data_package.state = "building";
    assert.equal(render().find(item => item.tagName === "button").disabled, true);
    ui.test.state.jobs = [{state:"completed", active_analyses:1}];
    assert.equal(ui.test.hasActive(), true, "Nonselected analysis must keep polling alive");
    assert.equal(ui.calls.length, 0);
  }
  {
    const submissions = [];
    const ui = harness(() => ({}), (url, options) => {
      if (url.endsWith("/analyses")) {
        submissions.push(options.headers.get("Idempotency-Key"));
        if (submissions.length === 1) throw new Error("synthetic lost response");
      }
      return {};
    });
    ui.test.state.authenticated = true;
    const button = {disabled:false};
    await ui.test.submitAnalysis({id:"job"}, button);
    assert.equal(ui.test.state.pendingAnalyses.size, 1);
    await ui.test.submitAnalysis({id:"job"}, button);
    assert.equal(submissions.length, 2);
    assert.equal(submissions[0], submissions[1], "Lost response retry must reuse idempotency key");
    assert.equal(ui.test.state.pendingAnalyses.size, 0);
    await ui.test.cancelAnalysis("job", "analysis", button);
    assert.ok(ui.calls.some(([url, method]) => url === "/api/jobs/job/analyses/analysis/cancel" && method === "POST"));
    ui.test.state.pendingAnalyses.set("job", {busy:false});
    ui.test.signedOut();
    assert.equal(ui.test.state.pendingAnalyses.size, 0);
  }
  {
    const ui = harness(() => ({}));
    const node = (tag, className, text) => {
      const element = ui.document.createElement(tag);
      element.tagName = tag; element.className = className; element.textContent = text;
      return element;
    };
    const flatten = element => [element, ...element.children.flatMap(flatten)];
    const helpers = {node, bytes:value => `${value} bytes`, friendly:code => code};
    const job = {id:"synthetic-job", state:"completed", outcome:"failed", data_package:{
      state:"ready", filename:"abcde.test.zip", size:123,
      web_materials:{state:"saved", count:2, coverage:"partial", gaps:["js_not_executed"]},
    }};
    const container = node("div", "", "");
    ui.bundle.render(job, container, helpers);
    const nodes = flatten(container), links = nodes.filter(element => element.tagName === "a");
    assert.equal(links.length, 1);
    assert.equal(links[0].href, "/api/jobs/synthetic-job/data-package");
    assert.equal(links[0].textContent, "下载数据包");
    assert.ok(nodes.some(element => element.textContent?.includes("此旧版数据包")));
    job.data_package.attachments = {packages:1, certificates:2, bytes:789};
    const upgraded = node("div", "", "");
    ui.bundle.render(job, upgraded, helpers);
    assert.ok(flatten(upgraded).some(element => element.textContent?.includes("APK / IPA 1 个，TLS 证书 2 份")));
    assert.ok(flatten(upgraded).some(element => element.textContent?.includes("归档成功不代表 APK 校验通过")));
    job.data_package.tls_certificates = {state:"saved", http_certificates:0, chrome_certificates:2,
      association_limited:true, reasons:[]};
    const tlsPanel = node("div", "", "");
    ui.bundle.render(job, tlsPanel, helpers);
    assert.ok(flatten(tlsPanel).some(element => element.textContent?.includes("HTTP 0 份，Chrome 2 份")));
    assert.ok(flatten(tlsPanel).some(element => element.textContent?.includes("不能据此确认属于某一次具体连接")));
    job.data_package.tls_certificates = {state:"not_captured", http_certificates:0, chrome_certificates:0,
      association_limited:false, reasons:["browser_tls_query_timeout"]};
    const tlsGap = node("div", "", "");
    ui.bundle.render(job, tlsGap, helpers);
    assert.ok(flatten(tlsGap).some(element => element.textContent?.includes("TLS 证书原件未取得")));
    assert.ok(flatten(tlsGap).some(element => element.textContent?.includes("Chrome 读取证书超时")));
    job.data_package.tls_certificates = {state:"partial", http_certificates:0, chrome_certificates:1,
      association_limited:true, reasons:["browser_tls_trace_data_loss"]};
    const tlsPartial = node("div", "", "");
    ui.bundle.render(job, tlsPartial, helpers);
    assert.ok(flatten(tlsPartial).some(element => element.textContent?.includes("部分证书或链成员未取得")));
    assert.ok(flatten(tlsPartial).some(element => element.textContent?.includes("缓冲区存在丢失")));
    job.data_package.tls_certificates = {state:"not_applicable", http_certificates:0, chrome_certificates:0,
      association_limited:false, reasons:[]};
    const noTls = node("div", "", "");
    ui.bundle.render(job, noTls, helpers);
    assert.ok(flatten(noTls).some(element => element.textContent?.includes("本次没有可导出证书的 HTTPS 观察记录")));
    assert.ok(nodes.some(element => element.textContent?.includes("已保存 2 项")));
    assert.equal(ui.test.busy(job), false);
    for (const state of ["pending", "building", "failed", "unavailable"]) {
      job.data_package.state = state;
      const panel = node("div", "", "");
      ui.bundle.render(job, panel, helpers);
      assert.equal(flatten(panel).filter(element => element.tagName === "a").length, 0);
      assert.equal(ui.test.busy(job), ["pending", "building"].includes(state));
    }
    assert.equal(ui.calls.length, 0, "Rendering and polling decisions must not perform network requests");
  }
  {
    let resolve;
    const pending = new Promise(done => { resolve = done; });
    const ui = harness(() => pending);
    await ui.test.authenticated({csrf_token:"synthetic"});
    assert.ok(ui.calls.some(([url, method]) => url === "/api/jobs" && method === "DELETE"));
    assert.equal(ui.test.state.clearing, false);
    await ui.test.pollCapabilities();
    assert.equal(ui.calls.filter(([url]) => url === "/api/capabilities").length, 1);
    ui.test.signedOut();
    resolve({chrome:{enabled:true, checking:false}, web_apk:{enabled:true}});
    await ui.settle();
    assert.equal(ui.test.state.authenticated, false);
    assert.equal(ui.test.state.capabilities, null);
    assert.equal(ui.timers.size, 0);
  }
  {
    const ui = harness(() => { throw new Error("synthetic capability unavailable"); });
    await ui.test.authenticated({csrf_token:"synthetic"}); await ui.settle();
    assert.ok(ui.calls.some(([url, method]) => url === "/api/jobs" && method === "DELETE"));
    for (let i = 0; i < 16; i++) await ui.tick();
    assert.equal(ui.calls.filter(([url]) => url === "/api/capabilities").length, 16);
    assert.equal(ui.test.state.capabilityStatus, "unavailable");
    assert.equal(ui.timers.size, 0);
  }
  {
    let checks = 0;
    const ui = harness(() => ({chrome:{enabled:++checks > 1, checking:checks === 1}, web_apk:{enabled:true}}));
    await ui.test.authenticated({csrf_token:"synthetic"}); await ui.settle();
    assert.equal(ui.test.state.capabilityStatus, "checking");
    ui.document.hidden = true; ui.events.get("visibilitychange")();
    assert.equal(ui.timers.size, 0);
    await ui.test.pollCapabilities();
    assert.equal(checks, 1);
    ui.document.hidden = false; ui.events.get("visibilitychange")(); await ui.settle();
    assert.equal(checks, 2);
    assert.equal(ui.test.state.capabilityStatus, "ready");
    assert.equal(ui.timers.size, 0);
  }
  console.log(JSON.stringify({passed:true, cases:7, analysisRecoveryScenarios:2, browser:false, network:false}));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
