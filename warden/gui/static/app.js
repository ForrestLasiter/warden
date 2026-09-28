"use strict";

const TOKEN = window.WARDEN_TOKEN;
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
    else if (k === "html") n.innerHTML = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const kid of kids) if (kid != null) n.append(kid);
  return n;
};

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { "X-Warden-Token": TOKEN, "Content-Type": "application/json", ...(opts.headers || {}) } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

let toastTimer = null;
function toast(msg, kind = "") {
  const t = $("#toast");
  t.textContent = msg; t.className = "toast" + (kind ? " " + kind : ""); t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 4000);
}
const badge = (i) => el("span", { class: "badge badge-" + SEV_CLASS[i] }, SEV[i]);
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
    $("#engineStatus").innerHTML = `<span class="dot"></span>Engines active: ${active}`;
    if (statusCache.version) $("#footerVersion").textContent = `Warden v${statusCache.version}`;
  } catch (e) { $("#engineStatus").textContent = "Could not load engine status"; }
  return statusCache;
}

function statCard(icon, num, sub, label, tone) {
  return el("div", { class: "stat" },
    el("div", { class: "stat-ico " + (tone || ""), html: ICON[icon] }),
    el("div", {},
      el("div", { class: "stat-num", html: num + (sub ? ` <small>${sub}</small>` : "") }),
      el("div", { class: "stat-label", text: label })));
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
    const hasHistory = entries.length > 0;

    // Empty state vs populated overview
    $("#overviewEmpty").hidden = hasHistory;
    $("#overviewMain").hidden = !hasHistory;

    box.innerHTML = "";
    box.append(
      statCard("engines", String(activeCount), "/ 4", "Detection engines active"),
      statCard("scan", String(entries.length), "", "Scans in history"),
      statCard("threat", last ? String(last.threats) : "0", "", "Threats — most recent scan", last && last.threats ? "danger" : "success"),
      statCard("quarantine", String(quarActive), "", "Files in quarantine", quarActive ? "warn" : ""),
    );

    recent.innerHTML = "";
    if (!entries.length) {
      recent.append(el("p", { class: "empty", html: ICON.empty + "No scans yet. Run one to see it here." }));
    } else {
      entries.slice(0, 6).forEach((e) => {
        recent.append(el("div", { class: "recent-item" },
          badge(e.threats ? 5 : 0),
          el("div", { class: "ri-main" },
            el("div", { text: `${e.kind === "sweep" ? "System sweep" : "Scan"} — ${e.files_scanned} files` }),
            el("div", { class: "ri-target", text: e.root })),
          el("span", { class: "recent-time", text: fmtTime(e.when) })));
      });
    }
  } catch (e) {
    box.innerHTML = ""; box.append(el("p", { class: "empty", text: "Could not load overview." }));
  }
}

/* ---------- report rendering ---------- */
function renderSummary(report) {
  const t = report.threats > 0;
  return el("div", { class: "summary-card " + (t ? "threats" : "clean") },
    el("div", { class: "sc-head" }, badge(t ? 5 : 0), el("span", { text: t ? `${report.threats} threat(s) found` : "No threats found" })),
    el("div", { class: "summary-grid" },
      el("span", {}, el("strong", { text: String(report.files_scanned) }), " scanned"),
      el("span", {}, el("strong", { text: String(report.files_skipped) }), " skipped"),
      el("span", {}, el("strong", { text: String(report.errors) }), " errors"),
      el("span", {}, el("strong", { text: (report.duration_seconds || 0).toFixed(1) + "s" }), " elapsed")));
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
  if (r.verdict >= 3 && jobId != null && index != null) {
    box.append(el("div", { class: "finding" },
      el("button", { class: "btn btn-danger btn-small", type: "button",
        onclick: (e) => { e.stopPropagation(); quarantineResult(jobId, index); } }, "Quarantine this file")));
  }
  item.append(head, box);
  return item;
}

function renderResults(container, report, jobId) {
  container.innerHTML = "";
  container.append(renderSummary(report));
  // Keep each result's original index so the server can look it up by handle.
  const threats = report.results
    .map((r, i) => ({ r, i }))
    .filter((x) => x.r.verdict >= 3)
    .sort((a, b) => b.r.verdict - a.r.verdict);
  if (!threats.length) return;
  container.append(el("h2", { text: "Flagged files", style: "font-size:1.05rem;margin:6px 2px 0" }));
  threats.forEach((x) => container.append(renderResultItem(x.r, jobId, x.i)));
}

/* ---------- jobs ---------- */
function progressBlock(wrap, label) {
  wrap.hidden = false; wrap.innerHTML = "";
  wrap.append(el("div", { class: "progress-line", role: "status", "aria-live": "polite" },
    el("div", { class: "spinner", "aria-hidden": "true" }), el("span", { class: "progress-text", text: label })));
  return $(".progress-text", wrap);
}
async function pollJob(jobId, onProgress) {
  return new Promise((resolve, reject) => {
    const tick = async () => {
      try {
        const j = await api("/api/job/" + jobId);
        onProgress(j);
        if (j.status === "done") return resolve(j);
        if (j.status === "error") return reject(new Error(j.error || "job failed"));
        setTimeout(tick, 400);
      } catch (e) { reject(e); }
    };
    tick();
  });
}

$("#scanForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const path = $("#scanPath").value.trim(); if (!path) return;
  const btn = $("#scanBtn"); btn.disabled = true;
  const text = progressBlock($("#scanProgress"), "Starting scan…");
  $("#scanResults").innerHTML = "";
  try {
    const { job } = await api("/api/scan", { method: "POST", body: JSON.stringify({ path, min_severity: $("#scanSeverity").value, save: true, online: $("#scanOnline").checked }) });
    const done = await pollJob(job, (j) => { text.textContent = `Scanning… ${j.count} files, ${j.threats} flagged`; });
    $("#scanProgress").hidden = true;
    renderResults($("#scanResults"), done.report, job);
    statusCache = null;
    toast(done.report.threats ? `${done.report.threats} threat(s) found` : "Scan complete — clean", done.report.threats ? "error" : "success");
  } catch (err) { $("#scanProgress").hidden = true; toast("Scan failed: " + err.message, "error"); }
  finally { btn.disabled = false; }
});

$("#sweepForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#sweepBtn"); btn.disabled = true;
  const text = progressBlock($("#sweepProgress"), "Gathering targets…");
  $("#sweepResults").innerHTML = ""; $("#sweepCategories").innerHTML = "";
  try {
    const { job } = await api("/api/sweep", { method: "POST", body: JSON.stringify({ quick: $("#sweepQuick").checked, save: true, online: $("#sweepOnline").checked }) });
    const done = await pollJob(job, (j) => { text.textContent = `Scanning… ${j.count} files, ${j.threats} flagged`; });
    $("#sweepProgress").hidden = true;
    if (done.categories) {
      const box = $("#sweepCategories");
      done.categories.forEach((c) => box.append(el("div", { class: "stat", title: c.description },
        el("div", { class: "stat-ico", html: ICON.scan }),
        el("div", {}, el("div", { class: "stat-num", text: String(c.files) }), el("div", { class: "stat-label", text: c.name })))));
    }
    renderResults($("#sweepResults"), done.report, job);
    statusCache = null;
    toast(done.report.threats ? `${done.report.threats} threat(s) found` : "Sweep complete — clean", done.report.threats ? "error" : "success");
  } catch (err) { $("#sweepProgress").hidden = true; toast("Sweep failed: " + err.message, "error"); }
  finally { btn.disabled = false; }
});

async function quarantineResult(jobId, index) {
  try { await api("/api/quarantine/add", { method: "POST", body: JSON.stringify({ job: jobId, index }) }); toast("File quarantined and isolated", "success"); }
  catch (err) { toast("Quarantine failed: " + err.message, "error"); }
}

/* ---------- history ---------- */
async function loadHistory() {
  const box = $("#historyList"); box.innerHTML = "Loading…";
  try {
    const { entries } = await api("/api/history");
    if (!entries.length) { box.innerHTML = ""; box.append(el("p", { class: "empty", html: ICON.empty + "No saved scans yet." })); return; }
    const table = el("table", {},
      el("caption", { text: "Past scans and sweeps, most recent first." }),
      el("thead", {}, el("tr", {}, el("th", { scope: "col", text: "When (UTC)" }), el("th", { scope: "col", text: "Kind" }), el("th", { scope: "col", text: "Target" }), el("th", { scope: "col", text: "Files" }), el("th", { scope: "col", text: "Threats" }))));
    const tb = el("tbody");
    entries.forEach((e) => tb.append(el("tr", {},
      el("td", { text: fmtTime(e.when).replace(" ", " · ") }),
      el("td", { text: e.kind }),
      el("td", { text: e.root }),
      el("td", { text: String(e.files_scanned) }),
      el("td", {}, e.threats ? badge(5) : el("span", { text: "0" })))));
    table.append(tb); box.innerHTML = ""; box.append(table);
  } catch (err) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: "Could not load history." })); }
}

/* ---------- quarantine ---------- */
async function loadQuarantine() {
  const box = $("#quarantineList"); box.innerHTML = "Loading…";
  try {
    const { entries } = await api("/api/quarantine");
    const active = entries.filter((e) => !e.restored);
    if (!active.length) { box.innerHTML = ""; box.append(el("p", { class: "empty", html: ICON.quarantine + "Quarantine is empty." })); return; }
    const table = el("table", {},
      el("caption", { text: "Isolated files. Restore returns a file; delete is permanent." }),
      el("thead", {}, el("tr", {}, el("th", { scope: "col", text: "When" }), el("th", { scope: "col", text: "Verdict" }), el("th", { scope: "col", text: "Original path" }), el("th", { scope: "col", text: "Actions" }))));
    const tb = el("tbody");
    active.forEach((e) => {
      const si = SEV.indexOf(e.verdict);
      tb.append(el("tr", {},
        el("td", { text: (e.quarantined_at || "").slice(0, 10) }),
        el("td", {}, badge(si < 0 ? 4 : si)),
        el("td", { text: e.original_path }),
        el("td", {}, el("div", { class: "row-actions" },
          el("button", { class: "btn btn-small", type: "button", onclick: () => restoreEntry(e.id) }, "Restore"),
          el("button", { class: "btn btn-danger btn-small", type: "button", onclick: () => confirmDelete(e.id, e.original_path) }, "Delete")))));
    });
    table.append(tb); box.innerHTML = ""; box.append(table);
  } catch (err) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: "Could not load quarantine." })); }
}
async function restoreEntry(id) {
  try { const r = await api("/api/quarantine/restore", { method: "POST", body: JSON.stringify({ id }) }); toast("Restored to " + r.path, "success"); loadQuarantine(); }
  catch (err) { toast("Restore failed: " + err.message, "error"); }
}

/* ---------- confirm modal ---------- */
let modalOpener = null, pendingDeleteId = null;
const backdrop = $("#confirmBackdrop"), modal = $("#confirmModal");
function openModal(bodyText) { $("#confirmBody").textContent = bodyText; modalOpener = document.activeElement; backdrop.hidden = false; $("#confirmCancel").focus(); document.addEventListener("keydown", modalKeydown); }
function closeModal() { backdrop.hidden = true; document.removeEventListener("keydown", modalKeydown); if (modalOpener && modalOpener.focus) modalOpener.focus(); pendingDeleteId = null; }
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
function confirmDelete(id, path) { pendingDeleteId = id; openModal(`Permanently delete the quarantined copy of "${path}"? This cannot be undone.`); }
$("#confirmCancel").addEventListener("click", closeModal);
backdrop.addEventListener("click", (e) => { if (e.target === backdrop) closeModal(); });
$("#confirmOk").addEventListener("click", async () => {
  const id = pendingDeleteId; closeModal(); if (!id) return;
  try { await api("/api/quarantine/delete", { method: "POST", body: JSON.stringify({ id }) }); toast("Deleted permanently", "success"); loadQuarantine(); }
  catch (err) { toast("Delete failed: " + err.message, "error"); }
});

/* ---------- boot ---------- */
(async function () { await loadStatus(); loadOverview(); })();
