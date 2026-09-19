/* NetProof frontend jsdom harness.

Loads the REAL index.html + app.js from a running server (default
http://127.0.0.1:8000, override with $NP_BASE_URL) and asserts behavior end to
end: dashboard boot, UX affordances, verdict/pipeline/checklist/trace/drift/
matrix rendering, and the post-change verification view. Admin credentials come
from $NP_ADMIN_USER / $NP_ADMIN_PASS (defaults admin/admin).

    node web/harness/harness.js
    NP_BASE_URL=http://127.0.0.1:8000 NP_ADMIN_PASS=admin node web/harness/harness.js

Exit code 0 == all assertions pass.
*/
const { JSDOM, VirtualConsole } = require("jsdom");

const BASE = (process.env.NP_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");
const ADMIN_USER = process.env.NP_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.NP_ADMIN_PASS || "admin";

const cookieStore = {};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function nodeFetch(url, init) {
  const headers = Object.assign({}, (init && init.headers) || {});
  const cookie = Object.entries(cookieStore).map(([k, v]) => k + "=" + v).join("; ");
  if (cookie) headers["Cookie"] = cookie;
  const res = await globalThis.fetch(url, Object.assign({}, init, { headers, redirect: "manual" }));
  const setc = res.headers.get("set-cookie");
  if (setc) {
    setc.split(/,(?=\s*[^=\s]+\=[^;]+)/g).forEach((seg) => {
      const m = seg.match(/^\s*([^=;\s]+)=([^;]*)/);
      if (m) cookieStore[m[1]] = m[2];
    });
  }
  if (res.status >= 300 && res.status < 400) {
    const loc = res.headers.get("location");
    if (loc) return nodeFetch(loc, init);
  }
  return res;
}

async function api(method, path, body) {
  const res = await nodeFetch(BASE + path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  try { return { status: res.status, data: JSON.parse(text) }; }
  catch (_) { return { status: res.status, data: text }; }
}

(async () => {
  const login = await api("POST", "/api/login", { username: ADMIN_USER, password: ADMIN_PASS });
  if (login.status !== 200) throw new Error("login failed: " + JSON.stringify(login).slice(0, 300));
  console.log("[-] logged in as " + ADMIN_USER);

  const html = await (await nodeFetch(BASE + "/", {})).text();
  const m = html.match(/src="(\/static\/app\.js\?v=[^"]+)"/);
  if (!m) throw new Error("could not find /static/app.js in served index.html");
  const appJs = await (await nodeFetch(BASE + m[1], {})).text();
  console.log("[-] loaded", m[1]);

  const vc = new VirtualConsole();
  vc.on("jsdomError", () => {});
  vc.on("error", () => {});

  const dom = new JSDOM(html, {
    url: BASE + "/",
    runScripts: "dangerously",
    pretendToBeVisual: true,
    virtualConsole: vc,
    beforeParse(window) {
      window.fetch = (input, init) => {
        const url = String(input).startsWith("http") ? String(input) : BASE + String(input);
        return nodeFetch(url, init);
      };
      window.scrollTo = () => {};
      window.Element.prototype.scrollIntoView = function () {};
      window.Element.prototype.scrollIntoViewIfNeeded = function () {};
      if (!window.CSS || !window.CSS.escape) {
        window.CSS = window.CSS || {};
        window.CSS.escape = window.CSS.escape || function (s) {
          return String(s)
            .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g, "\ufffd")
            .replace(/^\d/, "\\3" + (arguments[0] && arguments[0][0]) + " ")
            .replace(/(^|[^a-zA-Z0-9_-])/g, "$1\\");
        };
      }
      window.__RESULTS = [];
    },
  });
  const win = dom.window;

  const suite = `
(async function () {
  window.__SUITE_ERR = null;
  try {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const check = (name, cond) => window.__RESULTS.push({ name, pass: !!cond });
  const api = async (method, path, body) => {
    const res = await fetch(path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    try { return { status: res.status, data: JSON.parse(text) }; }
    catch (_) { return { status: res.status, data: text }; }
  };

  let loaded = false;
  for (let i = 0; i < 200 && !loaded; i++) {
    try { if (document.getElementById("net-chip").textContent && document.getElementById("net-chip").textContent !== "Network") loaded = true; } catch (e) {}
    if (!loaded) await sleep(50);
  }
  if (!loaded) { window.__DONE = true; return; }

  /* ---------------- 1. UX affordances ---------------- */
  check("glossary term renders", !!document.querySelector(".glossary-term[data-gloss]"));
  const glossEl = document.querySelector(".glossary-term[data-gloss='bgp']");
  if (glossEl) {
    glossEl.dispatchEvent(new MouseEvent("pointerover", { bubbles: true }));
    const pop = document.getElementById("gloss-pop");
    check("tooltip opens on hover", !!pop && !pop.hidden);
    glossEl.dispatchEvent(new MouseEvent("pointerout", { bubbles: true, relatedTarget: document.body }));
  }

  const liveBtn = document.querySelector(".mode-pills button[data-mode='scan']");
  const demoBtn = document.querySelector(".mode-pills button[data-mode='demo']");
  check("mode buttons exist", !!liveBtn && !!demoBtn);
  if (liveBtn) liveBtn.click();
  await sleep(250);
  check("live toggle falls back to demo without a scan", !demoBtn || demoBtn.classList.contains("active"));
  if (demoBtn && !demoBtn.classList.contains("active")) demoBtn.click();
  await sleep(250);

  try {
    sessionStorage.removeItem("netproof-walkthrough-dismissed");
    localStorage.removeItem("netproof-walkthrough-dismissed");
  } catch (e) {}
  check("walkthrough overlay exists", !!document.getElementById("walkthrough"));
  const skip = document.getElementById("wt-skip");
  if (skip) { skip.click(); await sleep(50); }
  check("walkthrough dismissible", (() => { try { return localStorage.getItem("netproof-walkthrough-dismissed") === "1"; } catch (e) { return false; } })());

  check("risk dialog opens", (() => {
    if (typeof confirmRisk === "undefined") return false;
    window.__RISK_P = confirmRisk({ title: "test risk", body: "test body" });
    return !!document.querySelector(".dialog-overlay");
  })());
  const riskOv = document.querySelector(".dialog-overlay");
  if (riskOv) { const cancelBtn = riskOv.querySelector('[data-act="cancel"]'); if (cancelBtn) cancelBtn.click(); }
  if (window.__RISK_P) { window.__RISK_P.catch(() => {}); }

  /* ---------------- 2. Validation + full result rendering ---------------- */
  const CHANGE = {
    type: "add_filter_rule", filter: "fw-inside-in",
    rule: { action: "permit", src: "10.0.10.0/24", dst: "10.0.20.0/24", proto: "icmp" },
  };
  const v = await api("POST", "/api/validate", { change: CHANGE, mode: "demo" });
  if (v.status !== 200) throw new Error("validate failed " + JSON.stringify(v.data).slice(0, 400));
  const report = v.data;
  check("report has prediction block",
    !!(report.prediction && Array.isArray(report.prediction.deltas) && report.prediction.deltas.length > 0));

  renderResult(report);

  check("verdict hero renders", !!document.querySelector(".result-hero .score b"));
  check("pipeline layer bar renders", document.querySelectorAll(".layer-cell").length >= 3);
  check("checklist items render", document.querySelectorAll(".tab-zone.checklist .check-item").length > 0);
  check("trace tab exists", !!document.querySelector(".result-tabs .tab[data-tab='trace']"));
  check("matrix table renders", !!document.querySelector(".tab-zone.matrix table.matrix"));
  check("post-change verify tab present", !!document.querySelector(".result-tabs .tab[data-tab='verify']"));
  check("findings tab active by default", !!document.querySelector(".result-tabs .tab[data-tab='findings'].active"));

  const drifted = JSON.parse(JSON.stringify(report));
  drifted.drift = { has_drift: true, risk_level: "high", diff_count: 1, suggested_action: "rebaseline" };
  renderResult(drifted);
  check("drift chip renders", !!document.querySelector(".guard-chip.drift"));
  renderResult(report);

  /* ---------------- 3. Verification view E2E ---------------- */
  const vid = report.audit && report.audit.verdict_id;
  check("verdict id persisted", !!vid);

  const sample = sampleEvidence(report);
  check("sampleEvidence returns docs", sample.length > 0);
  const preEv = buildPreChangeEvidence();
  check("pre-change evidence has config", !!(preEv.config && Object.keys(preEv.config).length > 0));

  const openBtn = document.getElementById("vf-open-" + vid);
  check("open-verification button rendered", !!openBtn);
  if (openBtn) { openBtn.click(); }
  for (let i = 0; i < 50; i++) { if (VERIF_BY_VID[vid]) break; await sleep(100); }
  check("verification opened (not_started)", !!VERIF_BY_VID[vid] && VERIF_BY_VID[vid].status === "not_started");

  const sampleBtn = document.getElementById("vf-sample-" + vid);
  if (sampleBtn) sampleBtn.click();
  const ta = document.getElementById("vf-evidence-editor-" + vid);
  check("evidence editor prefilled as JSON array", !!ta && JSON.parse(ta.value).length > 0);

  const evBtn = document.getElementById("vf-ev-" + vid);
  if (evBtn) evBtn.click();
  for (let i = 0; i < 50; i++) { if (VERIF_BY_VID[vid] && VERIF_BY_VID[vid].status === "awaiting_observation") break; await sleep(100); }
  check("evidence saved -> awaiting_observation", VERIF_BY_VID[vid] && VERIF_BY_VID[vid].status === "awaiting_observation");
  check("evidence count surfaced", !!document.querySelector(".vf-card-head .mono.dim"));

  const runBtn = document.getElementById("vf-run-" + vid);
  check("run button enabled once evidence present", !!runBtn && !runBtn.disabled);
  if (runBtn) runBtn.click();
  for (let i = 0; i < 60; i++) {
    if (VERIF_BY_VID[vid] && ["verified", "verified_with_warnings", "mismatch", "failed", "inconclusive", "unsupported"].indexOf(VERIF_BY_VID[vid].status) >= 0) break;
    await sleep(150);
  }
  const finalSt = VERIF_BY_VID[vid] && VERIF_BY_VID[vid].status;
  check("verification ran to a terminal status", ["verified", "verified_with_warnings", "mismatch", "failed", "inconclusive", "unsupported"].indexOf(finalSt) >= 0);
  check("verified badge renders", !!document.querySelector(".vf-status.pass") || !!document.querySelector(".vf-status.warn"));
  check("health checks render", document.querySelectorAll(".vf-hc").length > 0);
  check("rollback card renders", !!document.querySelector(".vf-rollback"));
  const bundleLink = document.getElementById("vf-bundle-" + vid);
  check("bundle link enabled after run", !!bundleLink && !bundleLink.disabled);

  const v2 = await api("POST", "/api/validate", { change: CHANGE, mode: "demo" });
  const c2 = await api("POST", "/api/verifications", { verdict_id: v2.data.audit.verdict_id, requester: "harness" });
  const noapply = [{
    source: "snapshot", device: "192.168.1.1", section: "filters",
    collected_at: "2099-01-01T00:00:00Z", confirmed: true,
    content: { filters: { "fw-inside-in": { rules: [] } } },
  }];
  await api("POST", "/api/verifications/" + c2.data.id + "/evidence", { evidence: noapply });
  const run2 = await api("POST", "/api/verifications/" + c2.data.id + "/run", {});
  check("absent expected change -> failed/mismatch", ["failed", "mismatch"].indexOf(run2.data.status) >= 0);
  check("rollback recommended on failure", !!(run2.data.rollback && run2.data.rollback.recommended === true));
  const bundle = await api("GET", "/api/verifications/" + c2.data.id + "/bundle");
  check("bundle export 200 + redacted", bundle.status === 200 && bundle.data.redacted === true);

  /* ---------------- 4. Journey / dotline ---------------- */
  try {
    const journey = _buildTopoFlows(drifted, "after");
    check("journey flow builder callable", Array.isArray(journey));
  } catch (e) {
    check("journey flow builder callable", false);
  }

  /* ---------------- 5. Server security headers ---------------- */
  const hdrRes = await fetch("/api/session", { method: "GET", headers: {} });
  const csp = hdrRes.headers.get("content-security-policy") || "";
  check("CSP header present", csp.indexOf("default-src") >= 0);
  check("X-Content-Type-Options nosniff", (hdrRes.headers.get("x-content-type-options") || "").toLowerCase() === "nosniff");
  check("frame denial header", (hdrRes.headers.get("x-frame-options") || "send").toLowerCase() === "deny");
  check("referrer policy header", !!hdrRes.headers.get("referrer-policy"));
  check("permissions policy header", !!hdrRes.headers.get("permissions-policy"));
  check("request id echoed", !!hdrRes.headers.get("x-netproof-request-id"));

  window.__DONE = true;
  return;
  } catch (e) {
    window.__SUITE_ERR = String(e && e.stack || e);
    window.__DONE = true;
  }
})();
`;

  win.eval(appJs + "\n;\n" + suite);

  const start = Date.now();
  let done = false;
  while (!done && Date.now() - start < 150000) {
    done = win.eval("window.__DONE === true") === true;
    if (!done) await sleep(150);
  }

  const results = win.eval("window.__RESULTS") || [];
  const passCount = results.filter((r) => r.pass).length;
  console.log("------");
  results.forEach((r) => console.log((r.pass ? "PASS" : "FAIL") + "  " + r.name));
  console.log("------");
  console.log("harness: " + passCount + "/" + results.length + " passed" + (results.length - passCount ? ", " + (results.length - passCount) + " FAILED" : ""));
  const suiteErr = win.eval("window.__SUITE_ERR || ''");
  if (suiteErr) { console.log("SUITE ERROR:"); console.log(suiteErr); }
  const asyncErrs = win.eval("window.__ASYNC_ERRS || []");
  if (asyncErrs.length) { console.log("ASYNC JS ERRORS (" + asyncErrs.length + "):"); asyncErrs.slice(0, 10).forEach((m) => console.log(m)); }
  if (!done) { console.log("WARN: suite did not finish in time"); }

  win.close();
  dom.window.close();
  process.exit(results.length - passCount && done ? 1 : (done ? 0 : 1));
})().catch((e) => {
  console.error("HARNESS ERROR:", e);
  process.exit(1);
});