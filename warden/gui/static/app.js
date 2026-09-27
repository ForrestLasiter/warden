"use strict";

const TOKEN = window.WARDEN_TOKEN;
const SEV = ["Clean", "Info", "Low", "Medium", "High", "Critical"];
const SEV_CLASS = ["clean", "info", "low", "medium", "high", "critical"];

/* ---------- tiny helpers ---------- */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const kid of kids) if (kid !== null && kid !== undefined) n.append(kid);
  return n;
};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { "X-Warden-Token": TOKEN, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

let toastTimer = null;
function toast(msg, kind = "") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (kind ? " " + kind : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 4000);
}

function badge(sevIndex) {
  return el("span", { class: "badge badge-" + SEV_CLASS[sevIndex] }, SEV[sevIndex]);
}

/* ---------- theme ---------- */
function applyTheme(choice) {
  document.documentElement.setAttribute("data-theme", choice);
  $$(".theme-btn").forEach((b) =>
    b.setAttribute("aria-pressed", String(b.dataset.themeChoice === choice)));
  try { localStorage.setItem("warden-theme", choice); } catch (_) {}
}
$$(".theme-btn").forEach((b) =>
  b.addEventListener("click", () => applyTheme(b.dataset.themeChoice)));
(function initTheme() {
  let saved = "system";
  try { saved = localStorage.getItem("warden-theme") || "system"; } catch (_) {}
  applyTheme(saved);
})();

/* ---------- tabs (ARIA, arrow keys, roving tabindex) ---------- */
const tabs = $$('[role="tab"]');
function selectTab(tab) {
  tabs.forEach((t) => {
    const selected = t === tab;
    t.setAttribute("aria-selected", String(selected));
    t.tabIndex = selected ? 0 : -1;
    $("#" + t.getAttribute("aria-controls")).hidden = !selected;
  });
  tab.focus();
  const panel = tab.id.replace("tab-", "");
  if (panel === "history") loadHistory();
  if (panel === "quarantine") loadQuarantine();
}
tabs.forEach((tab, i) => {
  tab.addEventListener("click", () => selectTab(tab));
  tab.addEventListener("keydown", (e) => {
    let idx = null;
    if (e.key === "ArrowRight") idx = (i + 1) % tabs.length;
    else if (e.key === "ArrowLeft") idx = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") idx = 0;
    else if (e.key === "End") idx = tabs.length - 1;
    if (idx !== null) { e.preventDefault(); selectTab(tabs[idx]); }
  });
});

/* ---------- engine status ---------- */
async function loadStatus() {
  try {
    const s = await api("/api/status");
    const active = s.active.length ? s.active.join(", ") : "none";
    $("#engineStatus").textContent = `Engines active: ${active}`;
    if (s.version) $("#footerVersion").textContent = `Warden v${s.version}`;
  } catch (e) {
    $("#engineStatus").textContent = "Could not load engine status";
  }
}

/* ---------- rendering reports ---------- */
function renderSummary(report) {
  const hasThreats = report.threats > 0;
  return el("div", { class: "summary-card " + (hasThreats ? "threats" : "clean") },
    el("div", { style: "display:flex;align-items:center;gap:10px" },
      badge(hasThreats ? 5 : 0),
      el("strong", { text: hasThreats ? `${report.threats} threat(s) found` : "No threats found" })),
    el("div", { class: "summary-grid" },
      el("span", {}, el("strong", { text: String(report.files_scanned) }), " files scanned"),
      el("span", {}, el("strong", { text: String(report.files_skipped) }), " skipped"),
      el("span", {}, el("strong", { text: String(report.errors) }), " errors"),
      el("span", {}, el("strong", { text: (report.duration_seconds || 0).toFixed(1) + "s" }), " elapsed")));
}

function renderResultItem(r) {
  const item = el("div", { class: "result-item" });
  const findingsBox = el("div", { class: "result-findings" });
  const btnId = "res-" + Math.random().toString(36).slice(2);
  const head = el("button", {
    class: "result-head", type: "button", "aria-expanded": "false", "aria-controls": btnId,
    onclick: () => {
      const open = item.classList.toggle("open");
      head.setAttribute("aria-expanded", String(open));
    },
  }, badge(r.verdict), el("span", { class: "result-path", text: r.path }));

  findingsBox.id = btnId;
  for (const f of r.findings) {
    findingsBox.append(el("div", { class: "finding" },
      el("div", {}, badge(f.severity), " ", el("span", { class: "finding-name", text: f.name })),
      el("div", { class: "finding-engine", text: `engine: ${f.engine}` }),
      el("div", { text: f.description })));
  }
  if (r.verdict >= 3) {
    findingsBox.append(el("div", { class: "finding" },
      el("button", {
        class: "btn btn-danger btn-small", type: "button",
        onclick: (e) => { e.stopPropagation(); quarantineResult(r); },
      }, "Quarantine this file")));
  }
  item.append(head, findingsBox);
  return item;
}

function renderResults(container, report) {
  container.innerHTML = "";
  container.append(renderSummary(report));
  const threats = report.results.filter((r) => r.verdict >= 3);
  const shown = threats.length ? threats : [];
  if (!shown.length) {
    container.append(el("p", { class: "empty", text: "Nothing flagged at Medium or above." }));
    return;
  }
  const list = el("div", { class: "results" });
  shown.sort((a, b) => b.verdict - a.verdict).forEach((r) => list.append(renderResultItem(r)));
  container.append(el("h2", { text: "Flagged files", style: "font-size:1.1rem;margin:20px 0 4px" }), list);
}

/* ---------- scan / sweep jobs ---------- */
function progressBlock(wrap, label) {
  wrap.hidden = false;
  wrap.innerHTML = "";
  const line = el("div", { class: "progress-line", role: "status", "aria-live": "polite" },
    el("div", { class: "spinner", "aria-hidden": "true" }),
    el("span", { class: "progress-text", text: label }));
  wrap.append(line);
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
  const path = $("#scanPath").value.trim();
  if (!path) return;
  const btn = $("#scanBtn");
  btn.disabled = true;
  const text = progressBlock($("#scanProgress"), "Starting scan…");
  $("#scanResults").innerHTML = "";
  try {
    const { job } = await api("/api/scan", {
      method: "POST",
      body: JSON.stringify({ path, min_severity: $("#scanSeverity").value, save: true }),
    });
    const done = await pollJob(job, (j) =>
      { text.textContent = `Scanning… ${j.count} files, ${j.threats} flagged`; });
    $("#scanProgress").hidden = true;
    renderResults($("#scanResults"), done.report);
    toast(done.report.threats ? `${done.report.threats} threat(s) found` : "Scan complete — clean",
      done.report.threats ? "error" : "success");
  } catch (err) {
    $("#scanProgress").hidden = true;
    toast("Scan failed: " + err.message, "error");
  } finally {
    btn.disabled = false;
  }
});

$("#sweepForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#sweepBtn");
  btn.disabled = true;
  const text = progressBlock($("#sweepProgress"), "Gathering targets…");
  $("#sweepResults").innerHTML = "";
  $("#sweepCategories").innerHTML = "";
  try {
    const { job } = await api("/api/sweep", {
      method: "POST",
      body: JSON.stringify({ quick: $("#sweepQuick").checked, save: true }),
    });
    const done = await pollJob(job, (j) =>
      { text.textContent = `Scanning… ${j.count} files, ${j.threats} flagged`; });
    $("#sweepProgress").hidden = true;
    if (done.categories) {
      const box = $("#sweepCategories");
      done.categories.forEach((c) =>
        box.append(el("div", { class: "cat-chip", title: c.description },
          el("strong", { text: String(c.files) }), c.name)));
    }
    renderResults($("#sweepResults"), done.report);
    toast(done.report.threats ? `${done.report.threats} threat(s) found` : "Sweep complete — clean",
      done.report.threats ? "error" : "success");
  } catch (err) {
    $("#sweepProgress").hidden = true;
    toast("Sweep failed: " + err.message, "error");
  } finally {
    btn.disabled = false;
  }
});

/* ---------- quarantine action from a result ---------- */
async function quarantineResult(r) {
  try {
    await api("/api/quarantine/add", { method: "POST", body: JSON.stringify({ result: r }) });
    toast("File quarantined and isolated", "success");
  } catch (err) {
    toast("Quarantine failed: " + err.message, "error");
  }
}

/* ---------- history ---------- */
async function loadHistory() {
  const box = $("#historyList");
  box.innerHTML = "Loading…";
  try {
    const { entries } = await api("/api/history");
    if (!entries.length) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: "No saved scans yet." })); return; }
    const table = el("table", {},
      el("caption", { text: "Past scans and sweeps (most recent first)." }),
      el("thead", {}, el("tr", {},
        el("th", { scope: "col", text: "When (UTC)" }),
        el("th", { scope: "col", text: "Kind" }),
        el("th", { scope: "col", text: "Target" }),
        el("th", { scope: "col", text: "Files" }),
        el("th", { scope: "col", text: "Threats" }))));
    const tbody = el("tbody");
    entries.forEach((e) => {
      tbody.append(el("tr", {},
        el("td", { text: (e.when || "").replace("T", " ").slice(0, 19) }),
        el("td", { text: e.kind }),
        el("td", { text: e.root }),
        el("td", { text: String(e.files_scanned) }),
        el("td", {}, e.threats ? badge(5) : el("span", { text: "0" }))));
    });
    table.append(tbody);
    box.innerHTML = ""; box.append(table);
  } catch (err) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: "Could not load history." })); }
}

/* ---------- quarantine list ---------- */
async function loadQuarantine() {
  const box = $("#quarantineList");
  box.innerHTML = "Loading…";
  try {
    const { entries } = await api("/api/quarantine");
    const active = entries.filter((e) => !e.restored);
    if (!active.length) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: "Quarantine is empty." })); return; }
    const table = el("table", {},
      el("caption", { text: "Isolated files. Restore returns a file; delete is permanent." }),
      el("thead", {}, el("tr", {},
        el("th", { scope: "col", text: "When" }),
        el("th", { scope: "col", text: "Verdict" }),
        el("th", { scope: "col", text: "Original path" }),
        el("th", { scope: "col", text: "Actions" }))));
    const tbody = el("tbody");
    active.forEach((e) => {
      const sevIdx = Math.max(0, SEV.indexOf(e.verdict));
      tbody.append(el("tr", {},
        el("td", { text: (e.quarantined_at || "").slice(0, 10) }),
        el("td", {}, badge(sevIdx < 0 ? 4 : sevIdx)),
        el("td", { text: e.original_path }),
        el("td", {}, el("div", { class: "row-actions" },
          el("button", { class: "btn btn-small", type: "button",
            onclick: () => restoreEntry(e.id) }, "Restore"),
          el("button", { class: "btn btn-danger btn-small", type: "button",
            onclick: () => confirmDelete(e.id, e.original_path) }, "Delete")))));
    });
    table.append(tbody);
    box.innerHTML = ""; box.append(table);
  } catch (err) { box.innerHTML = ""; box.append(el("p", { class: "empty", text: "Could not load quarantine." })); }
}

async function restoreEntry(id) {
  try {
    const r = await api("/api/quarantine/restore", { method: "POST", body: JSON.stringify({ id }) });
    toast("Restored to " + r.path, "success");
    loadQuarantine();
  } catch (err) { toast("Restore failed: " + err.message, "error"); }
}

/* ---------- accessible confirm modal (focus trap) ---------- */
let modalOpener = null;
let pendingDeleteId = null;
const backdrop = $("#confirmBackdrop");
const modal = $("#confirmModal");

function openModal(bodyText) {
  $("#confirmBody").textContent = bodyText;
  modalOpener = document.activeElement;
  backdrop.hidden = false;
  $("#confirmCancel").focus();
  document.addEventListener("keydown", modalKeydown);
}
function closeModal() {
  backdrop.hidden = true;
  document.removeEventListener("keydown", modalKeydown);
  if (modalOpener && modalOpener.focus) modalOpener.focus();
  pendingDeleteId = null;
}
function modalKeydown(e) {
  if (e.key === "Escape") { e.preventDefault(); closeModal(); return; }
  if (e.key === "Tab") {
    const f = $$('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])', modal)
      .filter((n) => !n.disabled && n.offsetParent !== null);
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
}
function confirmDelete(id, path) {
  pendingDeleteId = id;
  openModal(`Permanently delete the quarantined copy of "${path}"? This cannot be undone.`);
}
$("#confirmCancel").addEventListener("click", closeModal);
backdrop.addEventListener("click", (e) => { if (e.target === backdrop) closeModal(); });
$("#confirmOk").addEventListener("click", async () => {
  const id = pendingDeleteId;
  closeModal();
  if (!id) return;
  try {
    await api("/api/quarantine/delete", { method: "POST", body: JSON.stringify({ id }) });
    toast("Deleted permanently", "success");
    loadQuarantine();
  } catch (err) { toast("Delete failed: " + err.message, "error"); }
});

/* ---------- boot ---------- */
loadStatus();
