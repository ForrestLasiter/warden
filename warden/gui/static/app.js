"use strict";

/* The session token arrives in a <meta> tag (not an inline script) so the page
   can run under a strict Content-Security-Policy with no inline code. */
const TOKEN = (document.querySelector('meta[name="warden-token"]') || {}).content || "";
const SEV = ["Clean", "Info", "Low", "Medium", "High", "Critical"];
const SEV_CLASS = ["clean", "info", "low", "medium", "high", "critical"];
const TITLES = { overview: "Overview", scan: "Scan", sweep: "System sweep", history: "History", quarantine: "Quarantine" };

const ICON = {
  engines: '<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
  scan: '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
  threat: '<svg viewBox="0 0 24 24"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  quarantine: '<svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  history: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 16 14"/></svg>',
  empty: '<svg viewBox="0 0 24 24"><path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>',
};

/* ---------- helpers ---------- */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;      // only ever a constant from ICON
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const kid of kids) if (kid != null) n.append(kid);
  return n;
};

class ApiError extends Error {
  constructor(message, status, data) { super(message); this.status = status; this.data = data || {}; }
}
async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { "X-Warden-Token": TOKEN, "Content-Type": "application/json", ...(opts.headers || {}) } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(data.error || `HTTP ${res.status}`, res.status, data);
  return data;
}

let toastTimer = null;
function toast(msg, kind = "") {
  const t = $("#toast");
  t.textContent = msg; t.className = "toast" + (kind ? " " + kind : ""); t.hidden = false;
  // Errors stay up longer - and are ALSO shown inline next to the form, where
  // they persist, so nothing important lives only in a message that vanishes.
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, kind === "error" ? 12000 : 6000);
}
/* A persistent error tied to a form (SC 3.3.1 / 4.1.3). Pass null to clear. */
function formError(box, message, input) {
  box.textContent = "";
  box.hidden = !message;
  if (input) {
    if (message) { input.setAttribute("aria-invalid", "true"); input.setAttribute("aria-errormessage", box.id); }
    else { input.removeAttribute("aria-invalid"); input.removeAttribute("aria-errormessage"); }
  }
  if (message) box.append(el("strong", { text: "Problem: " }), message);
}
/* Screen-reader progress, at most one announcement every few seconds. */
let srLast = 0;
function srAnnounce(message, force) {
  const now = Date.now();
  if (!force && now - srLast < 6000) return;
  srLast = now;
  $("#srStatus").textContent = message;
}
/* A table that may be wider than a narrow screen scrolls inside its own
   focusable region, so keyboard users can reach the hidden columns. */
function tableRegion(table, label) {
  return el("div", { class: "table-wrap", role: "region", "aria-label": label, tabindex: "0" }, table);
}
const badge = (i) => el("span", { class: "badge badge-" + SEV_CLASS[i] }, SEV[i]);
/* Outcome of a whole scan, for lists of past scans. A scan with no threats is
   only "Clean" if it also covered everything; a severity word is not used here
   because a past report's summary records how many threats, not how severe. */
const outcomeBadge = (e) => e.threats ? pill("high", e.threats === 1 ? "1 threat" : `${e.threats} threats`)
  : e.complete === false ? pill("medium", "Incomplete") : pill("clean", "Clean");
const pill = (cls, text) => el("span", { class: "badge badge-" + cls }, text);
const fmtTime = (s) => (s || "").replace("T", " ").slice(0, 16);

/* ---------- theme ---------- */
function applyTheme(choice) {
  document.documentElement.setAttribute("data-theme", choice);
  $$(".theme-btn").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.themeChoice === choice)));
  try { localStorage.setItem("warden-theme", choice); } catch (_) {}
}
$$(".theme-btn").forEach((b) => b.addEventListener("click", () => applyTheme(b.dataset.themeChoice)));
(function () { let s = "system"; try { s = localStorage.getItem("warden-theme") || "system"; } catch (_) {} applyTheme(s); })();

/* ---------- nav (vertical ARIA tablist) ---------- */
const tabs = $$('[role="tab"]');
function selectTab(tab, focusInput) {
  tabs.forEach((t) => {
    const on = t === tab;
    t.setAttribute("aria-selected", String(on));
    t.tabIndex = on ? 0 : -1;
    $("#" + t.getAttribute("aria-controls")).hidden = !on;
  });
  const key = tab.id.replace("tab-", "");
  $("#pageTitle").textContent = TITLES[key] || "Warden";
  document.title = `${TITLES[key] || "Warden"} — Warden`;
  if (key === "overview") loadOverview();
  if (key === "history") loadHistory();
  if (key === "quarantine") loadQuarantine();
  if (focusInput && key === "scan") $("#scanPath").focus();
  else tab.focus();
}
tabs.forEach((tab, i) => {
  tab.addEventListener("click", () => selectTab(tab));
  tab.addEventListener("keydown", (e) => {
    let idx = null;
    if (e.key === "ArrowDown" || e.key === "ArrowRight") idx = (i + 1) % tabs.length;
    else if (e.key === "ArrowUp" || e.key === "ArrowLeft") idx = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") idx = 0;
    else if (e.key === "End") idx = tabs.length - 1;
    if (idx !== null) { e.preventDefault(); selectTab(tabs[idx]); }
  });
});
$$("[data-goto]").forEach((t) => t.addEventListener("click", () => selectTab($("#tab-" + t.dataset.goto), true)));

/* ---------- engine status + overview ---------- */
let statusCache = null;
async function loadStatus() {
  try {
    statusCache = await api("/api/status");
    const active = statusCache.active.length ? statusCache.active.join(", ") : "none";
    const line = $("#engineStatus");
    line.textContent = "";
    line.append(el("span", { class: "dot", "aria-hidden": "true" }), `Engines active: ${active}`);
    if (statusCache.version) $("#footerVersion").textContent = `Warden v${statusCache.version}`;
    if (statusCache.address) $("#localAddress").textContent = statusCache.address;
    renderNotices(statusCache);
    // Offline mode is a hard switch on the server: reflect it instead of
    // offering a checkbox that can't do anything.
    $$("#scanOnline, #sweepOnline").forEach((box) => {
      box.disabled = Boolean(statusCache.offline);
      if (statusCache.offline) box.checked = false;
    });
    $$(".offline-note").forEach((n) => { n.hidden = !statusCache.offline; });
  } catch (e) { $("#engineStatus").textContent = "Could not load engine status"; }
  return statusCache;
}

function renderNotices(status) {
  const box = $("#notices");
  box.textContent = "";
  (status.warnings || []).forEach((w) => box.append(
    el("p", { class: "notice notice-warn" }, el("strong", { text: "Reduced coverage: " }), w)));
  (status.advisories || []).forEach((a) => box.append(
    el("p", { class: "notice" }, el("strong", { text: "Note: " }), a)));
  box.hidden = !box.childElementCount;
}

function statCard(icon, num, sub, label, tone) {
  const number = el("div", { class: "stat-num" }, String(num));
  if (sub) number.append(" ", el("small", { text: sub }));
  return el("div", { class: "stat" },
    el("div", { class: "stat-ico " + (tone || ""), html: ICON[icon], "aria-hidden": "true" }),
    el("div", {}, number, el("div", { class: "stat-label", text: label })));
}

async function loadOverview() {
  const box = $("#overviewStats");
  const recent = $("#overviewRecent");
  try {
    const [status, hist, quar] = await Promise.all([
      statusCache ? Promise.resolve(statusCache) : loadStatus(),
      api("/api/history"), api("/api/quarantine"),
    ]);
    const entries = hist.entries || [];
    const last = entries[0];
    const quarActive = (quar.entries || []).filter((e) => !e.restored).length;
    const activeCount = status ? status.active.length : 0;
    const engineTotal = status ? Object.keys(status.engines || {}).length : 0;
    const hasHistory = entries.length > 0;

    // Empty state vs populated overview
    $("#overviewEmpty").hidden = hasHistory;
    $("#overviewMain").hidden = !hasHistory;

    box.textContent = "";
    box.append(
      statCard("engines", activeCount, engineTotal ? `/ ${engineTotal}` : "", "Detection engines active"),
      statCard("scan", entries.length, "", "Scans in history"),
      statCard("threat", last ? last.threats : 0, "", "Threats — most recent scan", last && last.threats ? "danger" : "success"),
      statCard("quarantine", quarActive, "", "Files in quarantine", quarActive ? "warn" : ""),
    );

    recent.textContent = "";
    if (!entries.length) {
      recent.append(el("p", { class: "empty", html: ICON.empty }, "No scans yet. Run one to see it here."));
    } else {
      entries.slice(0, 6).forEach((e) => {
        recent.append(el("div", { class: "recent-item" },
          outcomeBadge(e),
          el("div", { class: "ri-main" },
            el("div", { text: `${e.kind === "sweep" ? "System sweep" : "Scan"} — ${e.files_scanned} files` }),
            el("div", { class: "ri-target", text: e.root })),
          el("span", { class: "recent-time", text: fmtTime(e.when) })));
      });
    }
  } catch (e) {
    box.textContent = ""; box.append(el("p", { class: "empty", text: "Could not load overview." }));
  }
}

/* ---------- report rendering ---------- */
/* Three outcomes, never two: a scan that could not cover everything is
   "incomplete", not "clean" - and it says why. */
function reportState(report) {
  if (report.threats > 0) return "threats";
  const cov = report.coverage || {};
  if (cov.complete === false) return "incomplete";
  return "clean";
}

function coverageNotes(report) {
  const cov = report.coverage || {};
  const notes = [];
  if (report.stopped) notes.push(`Stopped early: ${report.stopped}.`);
  if (cov.unreadable_paths) notes.push(`${cov.unreadable_paths} path(s) could not be read.`);
  if (cov.read_or_stat_errors) notes.push(`${cov.read_or_stat_errors} file(s) could not be opened.`);
  if (cov.engine_errors) notes.push(`${cov.engine_errors} file(s) hit an engine error (verdict unknown).`);
  (cov.inactive_or_failed_engines || []).forEach((w) => notes.push(`Engine unavailable: ${w}`));
  if (cov.archive_members_skipped) notes.push(`${cov.archive_members_skipped} archive member(s) were not inspected (encrypted or over a safety limit).`);
  if (report.results_truncated) notes.push("Only the most severe results are listed; the full report is in History.");
  (report.advisories || []).forEach((a) => notes.push(a));
  return notes;
}

function renderSummary(report) {
  const state = reportState(report);
  // The badge shows the WORST verdict actually found, not a fixed "Critical".
  const worst = Math.max(3, ...report.results.map((r) => r.verdict || 0));
  const head = state === "threats" ? [badge(Math.min(worst, 5)), `${report.threats} threat(s) found`]
    : state === "incomplete" ? [pill("medium", "Incomplete"), "Scan incomplete — not everything could be checked"]
    : [badge(0), "No threats found"];
  const cov = report.coverage || {};
  // tabindex -1: focus is moved here when a scan finishes, so keyboard and
  // screen-reader users land on the outcome instead of hunting for it.
  const card = el("div", { class: "summary-card " + state, tabindex: "-1", role: "group", "aria-label": "Scan result" },
    el("div", { class: "sc-head" }, head[0], el("span", { text: head[1] })),
    el("div", { class: "summary-grid" },
      el("span", {}, el("strong", { text: String(report.files_scanned) }), " scanned"),
      el("span", {}, el("strong", { text: String(report.files_skipped) }), " skipped"),
      cov.archives_opened ? el("span", {}, el("strong", { text: String(cov.archive_members_scanned) }), " inside archives") : null,
      el("span", {}, el("strong", { text: String(report.errors) }), " errors"),
      el("span", {}, el("strong", { text: (report.duration_seconds || 0).toFixed(1) + "s" }), " elapsed")));
  const notes = coverageNotes(report);
  if (!notes.length) return card;
  const list = el("ul", { class: "coverage-notes" });
  notes.forEach((n) => list.append(el("li", { text: n })));
  return el("div", { class: "summary-wrap" }, card, list);
}

const SIG_TEXT = {
  valid: "valid signature", unsigned: "not signed",
  invalid: "INVALID signature (file altered or signature broken)",
  untrusted: "signed, but the certificate is not trusted",
  adhoc: "ad-hoc signed (no publisher identity)",
  unsupported: "no platform signature scheme", unknown: "signature status could not be determined",
};
function contextLines(r) {
  const meta = r.meta || {};
  const lines = [];
  if (meta.binary) {
    const b = meta.binary;
    lines.push(["File type", [String(b.format || "?").toUpperCase(), b.arch || "", b.type || ""].join(" ").trim()]);
  }
  if (meta.signature) {
    const s = meta.signature;
    lines.push(["Signature", (SIG_TEXT[s.status] || s.status || "unknown") + (s.publisher ? ` — ${s.publisher}` : "")]);
  }
  if (meta.archive) {
    const a = meta.archive;
    lines.push(["Archive", `${a.members_scanned} member(s) inspected` + (a.members_skipped ? `, ${a.members_skipped} not inspected` : "")]);
  }
  if (r.sha256) lines.push(["SHA-256", r.sha256]);
  return lines;
}

function renderResultItem(r, jobId, index) {
  const item = el("div", { class: "result-item" });
  const box = el("div", { class: "result-findings" });
  const id = "res-" + Math.random().toString(36).slice(2);
  const chev = el("span", { class: "result-chev", html: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>' });
  const head = el("button", {
    class: "result-head", type: "button", "aria-expanded": "false", "aria-controls": id,
    onclick: () => { const o = item.classList.toggle("open"); head.setAttribute("aria-expanded", String(o)); },
  }, chev, badge(r.verdict), el("span", { class: "result-path", text: r.path }));
  box.id = id;
  for (const f of r.findings) {
    box.append(el("div", { class: "finding" },
      el("div", { class: "finding-row" }, badge(f.severity), el("span", { class: "finding-name", text: f.name }),
        el("span", { class: "finding-engine", text: `· ${f.engine}` })),
      el("div", { text: f.description })));
  }
  const ctx = contextLines(r);
  if (ctx.length) {
    const dl = el("dl", { class: "context" });
    ctx.forEach(([k, v]) => dl.append(el("dt", { text: k }), el("dd", { text: v })));
    box.append(el("div", { class: "finding" }, dl));
  }
  if (r.verdict >= 3 && jobId != null && index != null) {
    box.append(el("div", { class: "finding" },
      el("button", { class: "btn btn-danger btn-small", type: "button", "aria-label": `Quarantine this file: ${r.path}`,
        onclick: (e) => { e.stopPropagation(); quarantineResult(jobId, index, e.currentTarget); } }, "Quarantine this file")));
  }
  item.append(head, box);
  return item;
}

const SEV_INDEX = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };

function renderResults(container, report, jobId, minVerdict) {
  const threshold = minVerdict || 3;   // default: medium and up
  container.textContent = "";
  container.append(renderSummary(report));
  // Keep each result's original index so the server can look it up by handle.
  const flagged = report.results
    .map((r, i) => ({ r, i }))
    .filter((x) => x.r.verdict >= threshold)
    .sort((a, b) => b.r.verdict - a.r.verdict);
  if (!flagged.length) return;
  container.append(el("h2", { class: "results-heading", text: "Flagged files" }));
  flagged.forEach((x) => container.append(renderResultItem(x.r, jobId, x.i)));
}

function announce(report, noun) {
  const state = reportState(report);
  if (state === "threats") toast(`${report.threats} threat(s) found`, "error");
  else if (state === "incomplete") toast(`${noun} incomplete — see the notes for what was not checked`, "error");
  else toast(`${noun} complete — clean`, "success");
}

/* ---------- jobs ---------- */
function progressBlock(wrap, label) {
  wrap.hidden = false; wrap.textContent = "";
  const cancel = el("button", { class: "btn btn-small", type: "button", disabled: "" }, "Cancel scan");
  // The visible counter is NOT a live region; srAnnounce() speaks a throttled copy.
  wrap.append(el("div", { class: "progress-line" },
    el("div", { class: "spinner", "aria-hidden": "true" }),
    el("span", { class: "progress-text", text: label })), cancel);
  srAnnounce(label, true);
  return { text: $(".progress-text", wrap), cancel };
}
function armCancel(button, jobId, text) {
  button.disabled = false;
  button.addEventListener("click", async () => {
    button.disabled = true;
    text.textContent = "Stopping after the current file…";
    srAnnounce("Stopping the scan after the current file.", true);
    try { await api(`/api/job/${jobId}/cancel`, { method: "POST" }); }
    catch (_) { /* already finished - the next poll will show the result */ }
  });
}
async function pollJob(jobId, onProgress) {
  return new Promise((resolve, reject) => {
    const tick = async () => {
      try {
        const j = await api("/api/job/" + jobId);
        if (j.status === "running") onProgress(j);
        if (j.status === "done" || j.status === "cancelled") return resolve(j);
        if (j.status === "error") return reject(new Error(j.error || "job failed"));
        setTimeout(tick, 400);
      } catch (e) { reject(e); }
    };
    tick();
  });
}

const ERROR_HINTS = {
  "path not found": "Check that the file or folder exists and that the path is typed in full, for example C:\\Users\\you\\Downloads or /home/you/Downloads.",
  "too many concurrent scans": "Wait for a running scan to finish, or cancel it, then try again.",
  "invalid min_severity": "Choose a report level from the list.",
};

async function runJob({ button, progress, startLabel, endpoint, payload, onDone, noun, errorBox, input, results }) {
  button.disabled = true;
  formError(errorBox, null, input);
  const ui = progressBlock(progress, startLabel);
  let stopping = false;
  ui.cancel.addEventListener("click", () => { stopping = true; });
  try {
    const { job } = await api(endpoint, { method: "POST", body: JSON.stringify(payload) });
    armCancel(ui.cancel, job, ui.text);
    const done = await pollJob(job, (j) => {
      if (stopping) return;
      const line = `Scanning… ${j.count} files, ${j.threats} flagged`;
      ui.text.textContent = line;
      srAnnounce(line);
    });
    progress.hidden = true;
    onDone(done, job);
    statusCache = null;
    announce(done.report, noun);
    const summary = $(".summary-card", results);
    if (summary) summary.focus();
  } catch (err) {
    progress.hidden = true;
    // Say what went wrong AND what to do about it (SC 3.3.3).
    const hint = ERROR_HINTS[err.message] || "";
    const message = `${noun} could not run: ${err.message}.${hint ? " " + hint : ""}`;
    formError(errorBox, message, err.status === 400 ? input : null);
    toast(message, "error");
    (input || button).focus();
  }
  finally { button.disabled = false; }
}

$("#scanForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const path = $("#scanPath").value.trim(); if (!path) return;
  $("#scanResults").textContent = "";
  const level = $("#scanSeverity").value;
  runJob({
    button: $("#scanBtn"), progress: $("#scanProgress"), startLabel: "Starting scan…", noun: "Scan",
    errorBox: $("#scanError"), input: $("#scanPath"), results: $("#scanResults"),
    endpoint: "/api/scan",
    payload: { path, min_severity: level, save: true, online: $("#scanOnline").checked },
    onDone: (done, job) => renderResults($("#scanResults"), done.report, job, SEV_INDEX[level] || 3),
  });
});

$("#sweepForm").addEventListener("submit", (e) => {
  e.preventDefault();
  $("#sweepResults").textContent = ""; $("#sweepCategories").textContent = "";
  runJob({
    button: $("#sweepBtn"), progress: $("#sweepProgress"), startLabel: "Gathering targets…", noun: "Sweep",
    errorBox: $("#sweepError"), input: null, results: $("#sweepResults"),
    endpoint: "/api/sweep",
    payload: { quick: $("#sweepQuick").checked, save: true, online: $("#sweepOnline").checked },
    onDone: (done, job) => {
      if (done.categories) {
        const box = $("#sweepCategories");
        done.categories.forEach((c) => box.append(el("div", { class: "stat" },
          el("div", { class: "stat-ico", html: ICON.scan, "aria-hidden": "true" }),
          el("div", {}, el("div", { class: "stat-num", text: String(c.files) }),
            el("div", { class: "stat-label", text: c.name }),
            el("div", { class: "stat-desc", text: c.description })))));
      }
      renderResults($("#sweepResults"), done.report, job);
    },
  });
});

async function quarantineResult(jobId, index, button) {
  try {
    await api("/api/quarantine/add", { method: "POST", body: JSON.stringify({ job: jobId, index }) });
    if (button) { button.disabled = true; button.textContent = "Quarantined"; button.setAttribute("aria-label", "Quarantined"); }
    toast("File quarantined and isolated", "success");
  } catch (err) { toast("Quarantine failed: " + err.message, "error"); }
}

/* ---------- history ---------- */
async function loadHistory() {
  const box = $("#historyList"); box.textContent = "Loading…";
  try {
    const { entries } = await api("/api/history");
    box.textContent = "";
    if (!entries.length) { box.append(el("p", { class: "empty", html: ICON.empty }, "No saved scans yet.")); return; }
    const table = el("table", {},
      el("caption", { text: "Past scans and sweeps, most recent first." }),
      el("thead", {}, el("tr", {}, el("th", { scope: "col", text: "When (UTC)" }), el("th", { scope: "col", text: "Kind" }), el("th", { scope: "col", text: "Target" }), el("th", { scope: "col", text: "Files" }), el("th", { scope: "col", text: "Result" }))));
    const tb = el("tbody");
    entries.forEach((e) => tb.append(el("tr", {},
      el("td", { text: fmtTime(e.when).replace(" ", " · ") }),
      el("td", { text: e.kind }),
      el("td", { text: e.root }),
      el("td", { text: String(e.files_scanned) }),
      el("td", {}, outcomeBadge(e)))));
    table.append(tb); box.append(tableRegion(table, "Scan history table"));
  } catch (err) { box.textContent = ""; box.append(el("p", { class: "empty", role: "alert", text: "Could not load history." })); }
}

/* ---------- quarantine ---------- */
async function loadQuarantine() {
  const box = $("#quarantineList"); box.textContent = "Loading…";
  try {
    const { entries } = await api("/api/quarantine");
    const active = entries.filter((e) => !e.restored);
    box.textContent = "";
    if (!active.length) { box.append(el("p", { class: "empty", html: ICON.quarantine }, "Quarantine is empty.")); return; }
    const table = el("table", {},
      el("caption", { text: "Isolated files. Restore re-checks a file first, then returns it; delete is permanent." }),
      el("thead", {}, el("tr", {}, el("th", { scope: "col", text: "When" }), el("th", { scope: "col", text: "Verdict" }), el("th", { scope: "col", text: "Original path" }), el("th", { scope: "col", text: "Actions" }))));
    const tb = el("tbody");
    active.forEach((e) => {
      const si = SEV.indexOf(e.verdict);
      tb.append(el("tr", {},
        el("td", { text: (e.quarantined_at || "").slice(0, 10) }),
        el("td", {}, badge(si < 0 ? 4 : si)),
        el("td", { text: e.original_path }),
        el("td", {}, el("div", { class: "row-actions" },
          // Each row's buttons name the file they act on (SC 2.4.6 / 4.1.2).
          el("button", { class: "btn btn-small", type: "button", "aria-label": `Restore ${e.original_path}`, onclick: () => restoreEntry(e.id, e.original_path) }, "Restore"),
          el("button", { class: "btn btn-danger btn-small", type: "button", "aria-label": `Delete ${e.original_path} permanently`, onclick: () => confirmDelete(e.id, e.original_path) }, "Delete")))));
    });
    table.append(tb); box.append(tableRegion(table, "Quarantined files table"));
  } catch (err) { box.textContent = ""; box.append(el("p", { class: "empty", role: "alert", text: "Could not load quarantine." })); }
}

/* Restore re-scans first. If the file is still detected, the server answers 409
   and we ask - restoring live malware should never be a single mis-click. */
async function restoreEntry(id, path, confirmed) {
  try {
    const r = await api("/api/quarantine/restore", { method: "POST", body: JSON.stringify({ id, confirm: Boolean(confirmed) }) });
    toast("Restored to " + r.path, "success"); loadQuarantine();
  } catch (err) {
    if (err.status === 409 && err.data.needs_confirm && !confirmed) {
      const why = err.data.still_threat
        ? `"${path}" is STILL detected as a threat (${err.data.verdict}) by the current rules.`
        : `"${path}" could not be fully re-checked before restoring.`;
      openConfirm({
        title: "Restore anyway?", body: `${why} Restoring puts the file back where it was, where it can run.`,
        okLabel: "Restore anyway", onOk: () => restoreEntry(id, path, true),
      });
      return;
    }
    toast("Restore failed: " + err.message, "error");
  }
}

/* ---------- confirm modal ---------- */
let modalOpener = null, pendingOk = null;
const backdrop = $("#confirmBackdrop"), modal = $("#confirmModal");
function openConfirm({ title, body, okLabel, onOk }) {
  $("#confirmTitle").textContent = title;
  $("#confirmBody").textContent = body;
  $("#confirmOk").textContent = okLabel;
  pendingOk = onOk;
  modalOpener = document.activeElement;
  backdrop.hidden = false;
  // Take the page behind the dialog out of the tab order and the
  // accessibility tree while it is open.
  $(".app").inert = true;
  $(".skip-link").inert = true;
  $("#confirmCancel").focus();
  document.addEventListener("keydown", modalKeydown);
}
function closeModal() {
  backdrop.hidden = true; document.removeEventListener("keydown", modalKeydown);
  $(".app").inert = false;
  $(".skip-link").inert = false;
  if (modalOpener && modalOpener.focus) modalOpener.focus();
  pendingOk = null;
}
function modalKeydown(e) {
  if (e.key === "Escape") { e.preventDefault(); closeModal(); return; }
  if (e.key === "Tab") {
    const f = $$('button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])', modal).filter((n) => !n.disabled && n.offsetParent !== null);
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
}
function confirmDelete(id, path) {
  openConfirm({
    title: "Delete permanently?", okLabel: "Delete",
    body: `Permanently delete the quarantined copy of "${path}"? This cannot be undone.`,
    onOk: async () => {
      try { await api("/api/quarantine/delete", { method: "POST", body: JSON.stringify({ id }) }); toast("Deleted permanently", "success"); loadQuarantine(); }
      catch (err) { toast("Delete failed: " + err.message, "error"); }
    },
  });
}
$("#confirmCancel").addEventListener("click", closeModal);
backdrop.addEventListener("click", (e) => { if (e.target === backdrop) closeModal(); });
$("#confirmOk").addEventListener("click", () => { const fn = pendingOk; closeModal(); if (fn) fn(); });

/* ---------- quit ---------- */
$("#quitBtn").addEventListener("click", () => {
  openConfirm({
    title: "Quit Warden?", okLabel: "Quit Warden",
    body: "This stops Warden on this computer. Any scan that is running will be stopped. You can start Warden again from its shortcut.",
    onOk: async () => {
      try { await api("/api/shutdown", { method: "POST" }); } catch (_) { /* the server is going away */ }
      $(".app").hidden = true;
      $(".skip-link").hidden = true;
      const stopped = $("#stoppedScreen");
      stopped.hidden = false;
      $("#stoppedTitle").focus();
      document.title = "Warden has stopped";
    },
  });
});

/* ---------- boot ---------- */
(async function () { await loadStatus(); loadOverview(); })();
