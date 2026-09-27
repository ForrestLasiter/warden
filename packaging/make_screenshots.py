"""Capture dashboard screenshots for the README (dev-only helper).

Assumes a Warden dashboard is running locally. Usage:
    warden gui --port 8790 --no-open   # in another terminal
    python packaging/make_screenshots.py http://127.0.0.1:8790/
"""

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8790/"
# Neutral demo path (no personal username) for public screenshots.
SCAN_PATH = sys.argv[2] if len(sys.argv) > 2 else r"C:\Users\Public\WardenDemo\samples"
OUT = Path(__file__).resolve().parent.parent / "docs" / "images"
OUT.mkdir(parents=True, exist_ok=True)


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1280, "height": 800}, device_scale_factor=2)
        page = ctx.new_page()

        # --- dark theme: the Overview dashboard (hero shot) ---
        page.goto(URL, wait_until="networkidle")
        page.click('[data-theme-choice="dark"]')
        page.wait_for_selector("#overviewStats .stat", timeout=15000)
        page.wait_for_timeout(500)
        page.screenshot(path=str(OUT / "dashboard-dark.png"))
        print("wrote dashboard-dark.png")

        # --- light theme: scan results with an expanded finding ---
        page.click('[data-theme-choice="light"]')
        page.click("#tab-scan")
        page.fill("#scanPath", SCAN_PATH)
        page.click("#scanBtn")
        page.wait_for_selector(".summary-card", timeout=15000)
        head = page.query_selector(".result-head")
        if head:
            head.click()
        page.wait_for_timeout(4300)  # let the status toast auto-dismiss
        page.screenshot(path=str(OUT / "dashboard-light.png"))
        print("wrote dashboard-light.png")

        browser.close()


if __name__ == "__main__":
    run()
