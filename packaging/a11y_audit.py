"""Accessibility audit of the Warden dashboard (dev-only helper).

Runs axe-core in a real (headless) browser against every view and state of the
dashboard, in both themes and at desktop and phone widths, then runs scripted
checks axe cannot do: keyboard order and focus visibility, dialog focus
management, reflow at 320 CSS px, target size, text-spacing overrides and
non-text contrast of control boundaries.

It starts its own dashboard on a throwaway data folder, so it never touches
your real ~/.warden.

Setup (once):
    pip install playwright && playwright install chromium
    npm pack axe-core && tar -xzf axe-core-*.tgz        # gives ./package/axe.min.js

Run:
    python packaging/a11y_audit.py <path to axe.min.js> [work dir]

Exit code 1 if axe reports a violation or a scripted check fails. Results are
also written to <work dir>/a11y_results.json. See docs/ACCESSIBILITY.md.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile  # noqa: E402
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parent.parent
if len(sys.argv) < 2:
    sys.exit(__doc__)
AXE = Path(sys.argv[1]).read_text(encoding="utf-8")
SCRATCH = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(tempfile.mkdtemp(prefix="warden-a11y-"))
SCRATCH.mkdir(parents=True, exist_ok=True)
PORT = 8792
URL = f"http://127.0.0.1:{PORT}/"
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]

home = SCRATCH / "a11y-home"
samples = SCRATCH / "a11y-samples"
for d in (home, samples):
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
sys.path.insert(0, str(REPO / "tests"))
from _builders import make_elf64, make_zip  # noqa: E402

(samples / "notes.txt").write_text("hello")
(samples / "invoice.pdf.exe").write_bytes(b"not really an exe")
(samples / "report.pdf.exe").write_bytes(b"also harmless")
(samples / "bundle.zip").write_bytes(make_zip({"docs/readme.pdf.exe": b"x", "a.txt": b"y"}))
(samples / "tool").write_bytes(make_elf64(rwx=True))

env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
server = subprocess.Popen(
    [sys.executable, "-c",
     f"import sys; sys.path.insert(0, r'{REPO}'); from warden.gui import serve; serve(port={PORT}, open_browser=False)"],
    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(60):
    try:
        urllib.request.urlopen(URL, timeout=1)
        break
    except Exception:
        time.sleep(0.25)

FAKE_INCOMPLETE = {
    "threats": 0, "files_scanned": 12, "files_skipped": 1, "errors": 2, "duration_seconds": 3.2,
    "stopped": "cancelled", "results": [], "advisories": ["ClamAV signatures are 30 days old - run freshclam to update"],
    "coverage": {"complete": False, "unreadable_paths": 2, "read_or_stat_errors": 2, "engine_errors": 1,
                 "inactive_or_failed_engines": ["yara: compile failed"], "archive_members_skipped": 3,
                 "archives_opened": 1, "archive_members_scanned": 4},
}

results: list[dict] = []
checks: list[dict] = []


def axe(page, label):
    page.evaluate(AXE)
    out = page.evaluate("async (tags) => await axe.run(document, {runOnly: {type: 'tag', values: tags}})", TAGS)
    for kind in ("violations", "incomplete"):
        for v in out[kind]:
            results.append({
                "state": label, "kind": kind, "id": v["id"], "impact": v.get("impact"),
                "help": v["help"], "tags": [t for t in v["tags"] if t.startswith("wcag")],
                "nodes": [{"target": n["target"], "html": n["html"][:160],
                           "summary": (n.get("failureSummary") or "")[:300]} for n in v["nodes"][:6]],
            })
    return len(out["violations"]), len(out["incomplete"]), len(out["passes"])


def check(name, ok, detail=""):
    checks.append({"check": name, "ok": bool(ok), "detail": detail})


with sync_playwright() as p:
    browser = p.chromium.launch()
    summary = []
    for theme in ("light", "dark"):
        for vp_name, vp in (("desktop", {"width": 1280, "height": 800}), ("mobile", {"width": 375, "height": 800})):
            ctx = browser.new_context(viewport=vp, bypass_csp=True)
            page = ctx.new_page()
            page.goto(URL)
            page.wait_for_selector("#overviewStats .stat")
            page.evaluate("t => applyTheme(t)", theme)
            tag = f"{theme}/{vp_name}"

            def run(label, page=page, tag=tag):
                v, i, ps = axe(page, f"{tag}: {label}")
                summary.append((f"{tag}: {label}", v, i, ps))

            run("overview")
            page.evaluate("renderNotices({warnings: ['rule pack corp v3 not loaded: file was modified'], advisories: ['ClamAV signatures are 30 days old']})")
            run("overview + notices")

            page.click("#tab-scan")
            run("scan form (empty)")
            page.fill("#scanPath", str(samples))
            page.select_option("#scanSeverity", "info")
            page.click("#scanBtn")
            page.wait_for_selector(".summary-card", timeout=60000)
            page.evaluate("document.querySelectorAll('.result-head').forEach(b => b.click())")
            run("scan results (expanded)")
            page.evaluate("r => renderResults(document.querySelector('#scanResults'), r, null, 1)", FAKE_INCOMPLETE)
            run("scan results (incomplete)")
            page.evaluate("const ui = progressBlock(document.querySelector('#scanProgress'), 'Scanning… 120 files, 2 flagged'); ui.cancel.disabled = false")
            run("scan in progress")
            page.evaluate("document.querySelector('#scanProgress').hidden = true")
            # an error state: path that does not exist
            page.fill("#scanPath", str(samples / "nope"))
            page.click("#scanBtn")
            page.wait_for_selector("#scanError:not([hidden])")
            run("scan error")
            if theme == "light" and vp_name == "desktop":
                check("error: shown inline and persistent", page.evaluate("!document.querySelector('#scanError').hidden && document.querySelector('#scanError').textContent.length > 10"))
                check("error: input marked invalid and tied to the message",
                      page.evaluate("document.querySelector('#scanPath').getAttribute('aria-invalid') === 'true' && document.querySelector('#scanPath').getAttribute('aria-errormessage') === 'scanError'"))
                check("error: focus returned to the field", page.evaluate("document.activeElement.id") == "scanPath")
            # non-text contrast of form-control boundaries (SC 1.4.11)
            nt = page.evaluate(r"""() => {
                const lum = c => { const m = c.match(/[\d.]+/g).slice(0, 3).map(Number).map(v => v / 255).map(v => v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4)); return 0.2126 * m[0] + 0.7152 * m[1] + 0.0722 * m[2]; };
                const cr = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
                const bgOf = e => { while (e) { const c = getComputedStyle(e).backgroundColor; if (c && !/rgba\(0, 0, 0, 0\)|transparent/.test(c)) return c; e = e.parentElement; } return 'rgb(255,255,255)'; };
                return ['#scanPath', '#scanSeverity', '#scanBtn', '.theme-switch'].map(sel => { const e = document.querySelector(sel); if (!e || e.offsetParent === null) return null; const cs = getComputedStyle(e);
                    const edge = cs.borderTopColor; const fill = cs.backgroundColor; const outer = bgOf(e.parentElement);
                    return {sel, border: +cr(edge, outer).toFixed(2), fill: +cr(fill, outer).toFixed(2)}; }).filter(Boolean);
            }""")
            for item in nt:
                check(f"non-text contrast >= 3:1: {item['sel']} ({tag})", max(item["border"], item["fill"]) >= 3.0, json.dumps(item))

            page.click("#tab-sweep")
            run("sweep form")
            page.click("#tab-history")
            page.wait_for_selector("#historyList table")
            run("history")
            page.click("#tab-overview")
            page.wait_for_selector(".recent-item")
            run("overview (populated)")

            if theme == "light" and vp_name == "desktop":
                # quarantine one file so the quarantine table has content
                page.click("#tab-scan")
                page.fill("#scanPath", str(samples))
                page.click("#scanBtn")
                page.wait_for_selector(".result-item", timeout=60000)
                check("scan done: focus moved to the result summary",
                      page.evaluate("document.activeElement.classList.contains('summary-card')"))
                check("scan done: error cleared",
                      page.evaluate("document.querySelector('#scanError').hidden && !document.querySelector('#scanPath').hasAttribute('aria-invalid')"))
                page.evaluate("document.querySelectorAll('.result-head').forEach(b => b.click())")
                page.locator(".result-item", has_text="report.pdf.exe").locator(".btn-danger").click()
                page.wait_for_timeout(800)
            page.click("#tab-quarantine")
            page.wait_for_selector("#quarantineList table")
            run("quarantine")
            page.locator("#quarantineList .btn-danger").first.click()
            page.wait_for_selector("#confirmModal")
            run("confirm dialog")

            if theme == "light" and vp_name == "desktop":
                # ---- keyboard: dialog focus management ----
                check("dialog: initial focus on Cancel", page.evaluate("document.activeElement.id") == "confirmCancel")
                check("dialog: page behind is inert", page.evaluate("document.querySelector('.app').inert === true"))
                page.keyboard.press("Tab")
                a = page.evaluate("document.activeElement.id")
                page.keyboard.press("Tab")
                b = page.evaluate("document.activeElement.id")
                check("dialog: Tab is trapped inside", {a, b} == {"confirmOk", "confirmCancel"}, f"{a} -> {b}")
                page.keyboard.press("Escape")
                check("dialog: Escape closes", page.evaluate("document.querySelector('#confirmBackdrop').hidden"))
                check("dialog: focus returns to the opener",
                      page.evaluate("document.activeElement.textContent") == "Delete")
            else:
                page.keyboard.press("Escape")

            # Same DOM changes the Quit button makes (without stopping the server).
            page.evaluate("document.querySelector('.app').hidden = true; document.querySelector('.skip-link').hidden = true; document.querySelector('#stoppedScreen').hidden = false; document.title = 'Warden has stopped'")
            run("stopped screen")

            # ---- reflow (1.4.10) ----
            if vp_name == "mobile":
                page.goto(URL)
                page.set_viewport_size({"width": 320, "height": 800})
                page.evaluate("t => applyTheme(t)", theme)
                for tab in ("overview", "scan", "sweep", "history", "quarantine"):
                    page.click(f"#tab-{tab}")
                    page.wait_for_timeout(250)
                    w = page.evaluate("document.documentElement.scrollWidth")
                    check(f"reflow 320px: {tab} ({theme})", w <= 320, f"scrollWidth={w}")
            ctx.close()

    # ---- keyboard walk + focus visibility + target size (desktop, light) ----
    ctx = browser.new_context(viewport={"width": 1280, "height": 800}, bypass_csp=True)
    page = ctx.new_page()
    page.goto(URL)
    page.wait_for_selector("#overviewStats .stat")
    order = []
    invisible = []
    for _ in range(40):
        page.keyboard.press("Tab")
        info = page.evaluate("""() => {
            const e = document.activeElement; if (!e || e === document.body) return null;
            const cs = getComputedStyle(e);
            return {name: (e.id || e.className || e.tagName) + ':' + (e.textContent || e.getAttribute('aria-label') || '').trim().slice(0, 24),
                    outline: cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 2,
                    tag: e.tagName};
        }""")
        if info is None:
            break
        order.append(info["name"])
        if not info["outline"]:
            invisible.append(info["name"])
        if len(order) > 3 and order[-1] == order[0]:
            break
    check("keyboard: skip link is first focus stop", order and order[0].startswith("skip-link"), order[0] if order else "")
    check("keyboard: every focus stop has a visible >=2px outline", not invisible, "; ".join(invisible[:6]))
    check("keyboard: focus order (informational)", True, " > ".join(order[:22]))

    # arrow keys in the tablist
    page.focus("#tab-overview")
    page.keyboard.press("ArrowDown")
    check("tablist: ArrowDown moves and selects next tab",
          page.evaluate("document.activeElement.id") == "tab-scan"
          and page.evaluate("document.querySelector('#tab-scan').getAttribute('aria-selected')") == "true")
    page.keyboard.press("End")
    check("tablist: End jumps to last tab", page.evaluate("document.activeElement.id") == "tab-quarantine")
    page.keyboard.press("Home")
    check("tablist: Home jumps to first tab", page.evaluate("document.activeElement.id") == "tab-overview")

    for tab in ("overview", "scan", "sweep", "history", "quarantine"):
        page.click(f"#tab-{tab}")
        page.wait_for_timeout(300)
        small = page.evaluate("""() => Array.from(document.querySelectorAll('button, a[href], input, select'))
            .filter(e => e.offsetParent !== null)
            .map(e => { const r = e.getBoundingClientRect(); return {n: (e.id || e.textContent.trim().slice(0, 20) || e.tagName), w: Math.round(r.width), h: Math.round(r.height), inline: getComputedStyle(e).display === 'inline'}; })
            .filter(x => (x.w < 24 || x.h < 24) && !x.inline)""")
        check(f"target size >= 24px: {tab}", not small, json.dumps(small)[:300])

    # text spacing (1.4.12): apply the WCAG overrides and look for clipped text
    page.click("#tab-scan")
    page.add_style_tag(content="* { line-height: 1.5 !important; letter-spacing: 0.12em !important; word-spacing: 0.16em !important; } p { margin-bottom: 2em !important; }")
    page.wait_for_timeout(200)
    clipped = page.evaluate("""() => Array.from(document.querySelectorAll('button, label, h1, h2, .nav-item, .stat-label, th'))
        .filter(e => e.offsetParent !== null && (e.scrollWidth > e.clientWidth + 1 || e.scrollHeight > e.clientHeight + 1) && getComputedStyle(e).overflow !== 'visible')
        .map(e => (e.id || e.textContent.trim().slice(0, 30)))""")
    check("text spacing overrides: no clipped controls/headings", not clipped, "; ".join(clipped[:8]))

    # page-level
    page.goto(URL)
    check("page has lang", page.evaluate("document.documentElement.lang") == "en")
    check("page has a title", bool(page.title()))
    check("exactly one h1 visible", page.evaluate("Array.from(document.querySelectorAll('h1')).filter(e => e.offsetParent !== null).length") == 1)
    check("reduced motion rule present", "prefers-reduced-motion" in (REPO / "warden/gui/static/style.css").read_text(encoding="utf-8"))
    ctx.close()
    browser.close()

server.terminate()

print("=== axe summary (state: violations / needs-review / passes) ===")
for label, v, i, ps in summary:
    flag = "" if not v and not i else "   <--"
    print(f"{label:55} {v} / {i} / {ps}{flag}")
print()
seen = {}
for r in results:
    key = (r["kind"], r["id"])
    seen.setdefault(key, {"states": [], "r": r})["states"].append(r["state"])
print(f"=== distinct axe findings: {len(seen)} ===")
for (kind, rid), info in seen.items():
    r = info["r"]
    print(f"[{kind}] {rid} ({r['impact']}) {r['tags']} - {r['help']}")
    print(f"    in {len(info['states'])} state(s), e.g. {info['states'][:3]}")
    for n in r["nodes"][:3]:
        print(f"    node {n['target']} :: {n['html']}")
        if n["summary"]:
            print(f"         {n['summary'].replace(chr(10), ' | ')[:260]}")
print()
print("=== scripted checks ===")
for c in checks:
    print(("PASS  " if c["ok"] else "FAIL  ") + c["check"] + (f"   [{c['detail']}]" if c["detail"] else ""))
(SCRATCH / "a11y_results.json").write_text(json.dumps({"axe": results, "checks": checks, "summary": summary}, indent=1), encoding="utf-8")

violations = [r for r in results if r["kind"] == "violations"]
failed = [c for c in checks if not c["ok"]]
print()
print(f"axe violations: {len(violations)}   failed scripted checks: {len(failed)}")
sys.exit(1 if violations or failed else 0)
