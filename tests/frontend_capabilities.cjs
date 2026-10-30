// Pure Node regression of the real client functions; no browser or network.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../src/fxfetch/web/static/app.js"), "utf8")
  .replace(/^\s*api\("\/api\/session"\).*$/m, "")
  .replace(/\}\)\(\);\s*$/, "globalThis.test = {state, authenticated, pollCapabilities, signedOut, busy, hasActive, submitAnalysis, cancelAnalysis};})();");

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
    assert.ok(nodes.some(element => element.textContent?.includes("APK / IPA 单独下载")));
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
  console.log(JSON.stringify({passed:true, cases:6, browser:false, network:false}));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
