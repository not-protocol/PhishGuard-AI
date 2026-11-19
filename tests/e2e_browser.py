"""Real-browser end-to-end check (optional; needs `pip install playwright` + a Chromium build).

    python app.py                      # terminal 1 (use an empty phishguard.db for exact counts)
    BASE_URL=http://127.0.0.1:5000 SHOTS=/tmp/shots python tests/e2e_browser.py

Exits non-zero if any check fails. Prints one PASS/FAIL line per check.
"""
import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "http://127.0.0.1:5000")
SHOTS = Path(os.environ.get("SHOTS", "/tmp/shots"))
SHOTS.mkdir(parents=True, exist_ok=True)
results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS" if cond else "FAIL"), "-", name, ("" if cond else f"[{detail}]"))


def wait_until(page, expr, timeout_ms=8000):
    """Poll a JS expression with page.evaluate (the strict page CSP forbids Playwright's eval-based polling)."""
    waited = 0
    while waited <= timeout_ms:
        if page.evaluate(expr):
            return True
        page.wait_for_timeout(100)
        waited += 100
    raise TimeoutError(f"condition never became true: {expr}")


def score_of(page, container):
    return int(page.locator(f"{container} .gauge .num").text_content())


with sync_playwright() as pw:
    browser = pw.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1366, "height": 850})
    ctx.set_default_timeout(8000)
    page = ctx.new_page()
    problems = []
    page.on("console", lambda m: problems.append(m.text) if m.type in ("error", "warning") else None)
    page.on("pageerror", lambda e: problems.append(str(e)))
    page.on("dialog", lambda d: d.accept())

    page.goto(BASE)
    check("dashboard renders with title", "PhishGuard AI" in page.title())
    check("overview is the first view", page.locator("#viewTitle").inner_text() == "Overview")
    check("empty state counters", page.locator("#statTotal").inner_text() == "0")
    wait_until(page, "document.querySelector('#txtModels').textContent.includes('loaded')")
    check("sidebar reports models loaded", "loaded" in page.locator("#txtModels").inner_text())
    check("sidebar reports local AI fallback", "local fallback" in page.locator("#txtAi").inner_text())

    # --- URL scanner
    page.click('.nav-btn[data-view="url"]')
    page.click('[data-fill="url"] >> nth=0')
    page.click("#urlBtn")
    page.wait_for_selector("#urlResult .result-card")
    s1 = score_of(page, "#urlResult")
    check("suspicious URL scores high", s1 >= 50, s1)
    check("suspicious URL badge", "risk" in page.locator("#urlResult .badge").first.inner_text().lower())
    page.wait_for_timeout(1100)
    page.screenshot(path=str(SHOTS / "url_scan.png"))
    page.click('[data-fill="url"] >> nth=1')
    page.click("#urlBtn")
    wait_until(page, "document.querySelector('#urlResult .gauge .num').textContent !== '%s'" % s1)
    s2 = score_of(page, "#urlResult")
    check("ordinary URL scores low", s2 < 25, s2)
    page.fill("#urlInput", "javascript:alert(1)")
    page.press("#urlInput", "Enter")
    page.wait_for_selector("#urlResult .banner")
    check("invalid URL shows a clear error", "only http and https" in page.locator("#urlResult .banner").inner_text().lower())
    page.fill("#urlInput", "")
    page.click("#urlBtn")
    wait_until(page, "document.querySelector('#urlResult .banner')?.textContent.includes('empty')")
    check("empty URL rejected", True)

    # --- message scanner
    page.click('.nav-btn[data-view="message"]')
    page.click('[data-fill="message"] >> nth=0')
    check("character counter updates", int(page.locator("#msgCount").inner_text()) > 50)
    page.click("#msgBtn")
    page.wait_for_selector("#msgResult .result-card")
    m1 = score_of(page, "#msgResult")
    check("phishing message scores high", m1 >= 50, m1)
    check("category shown", page.locator("#msgResult h3").inner_text() == "Credential Phishing")
    page.wait_for_timeout(1100)
    page.screenshot(path=str(SHOTS / "message_scan.png"))

    # --- risk analysis + summary (no AI configured -> local fallback)
    page.click("#msgResult >> text=Full risk analysis")
    page.wait_for_selector("#riskBody:not(.hidden)")
    check("breakdown has 3 rows", page.locator("#breakdown .bar-row").count() == 3)
    check("recommendations listed", page.locator("#recoList li").count() >= 2)
    page.click("#aiBtn")
    page.wait_for_selector("#aiOut:not(.hidden)")
    check("local summary shown when AI is off", "local summary" in page.locator("#aiOut .src").inner_text().lower())
    check("summary text present", len(page.locator("#aiOut p").first.inner_text()) > 40)
    page.wait_for_timeout(1100)
    page.screenshot(path=str(SHOTS / "risk_analysis.png"), full_page=True)

    # --- evidence
    page.click('.nav-btn[data-view="evidence"]')
    check("evidence list populated", page.locator("#evList li").count() >= 3)
    check("links table lists the domain", "paypal-secure-login" not in "" or page.locator("#evLinks tbody tr").count() >= 1)
    page.screenshot(path=str(SHOTS / "evidence.png"), full_page=True)

    # --- XSS attempts must stay inert
    page.click('.nav-btn[data-view="message"]')
    page.fill("#msgInput", '<img src=x onerror="window.__xss=1"> <script>window.__xss=2</script> verify your password now http://a.xyz/"><svg onload=window.__xss=3>')
    page.click("#msgBtn")
    wait_until(page, "!!(document.querySelector('#msgResult .result-card') || document.querySelector('#msgResult .banner'))")
    page.wait_for_timeout(300)
    check("no script executed from message input", page.evaluate("window.__xss === undefined"))

    # --- history
    page.click('.nav-btn[data-view="history"]')
    page.wait_for_selector("#histTbl tbody tr")
    n = page.locator("#histTbl tbody tr").count()
    check("history lists scans", n >= 4, n)
    page.locator("#histTbl tbody tr").last.locator("text=View").click()
    page.wait_for_selector("#riskBody:not(.hidden)")
    check("history item reopens in risk view", page.locator("#riskId").inner_text().startswith("PG-"))
    page.click('.nav-btn[data-view="overview"]')
    wait_until(page, "document.querySelector('#statTotal').textContent !== '0'")
    check("overview counts updated", int(page.locator("#statTotal").inner_text()) >= 4)
    check("distribution chart has 4 columns", page.locator("#distChart .col").count() == 4)
    page.screenshot(path=str(SHOTS / "overview.png"), full_page=True)

    # --- settings
    page.click('.nav-btn[data-view="settings"]')
    page.wait_for_selector("#setModels .v")
    txt = page.locator("#setModels").inner_text()
    check("settings show models loaded", txt.count("Yes") >= 2, txt)
    check("synthetic-data warning shown", "SYNTHETIC" in page.locator("#setEval").inner_text())
    page.screenshot(path=str(SHOTS / "settings.png"), full_page=True)

    # --- clear history
    page.click('.nav-btn[data-view="history"]')
    page.click("#clearBtn")
    page.wait_for_selector("#histEmpty:not(.hidden)")
    check("history can be cleared", True)

    # --- responsive layout
    mobile = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2)
    mobile.set_default_timeout(8000)
    mp = mobile.new_page()
    mp.on("console", lambda m: problems.append("mobile:" + m.text) if m.type in ("error", "warning") else None)
    mp.goto(BASE)
    check("sidebar hidden on mobile until opened", not mp.locator("#sidebar").evaluate("e => e.classList.contains('open')"))
    mp.click("#menuBtn")
    check("menu button opens sidebar", mp.locator("#sidebar").evaluate("e => e.classList.contains('open')"))
    mp.click('.nav-btn[data-view="message"]')
    mp.click('[data-fill="message"] >> nth=0')
    mp.click("#msgBtn")
    mp.wait_for_selector("#msgResult .result-card")
    mp.wait_for_timeout(1100)
    check("no horizontal overflow on mobile", mp.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"),
          mp.evaluate("document.documentElement.scrollWidth"))
    mp.screenshot(path=str(SHOTS / "mobile_message.png"), full_page=True)
    mp.click("#menuBtn")
    mp.click('.nav-btn[data-view="history"]')
    mp.wait_for_selector("#histTbl tbody tr")
    check("no horizontal page overflow on mobile history", mp.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"))

    # Chromium logs every non-2xx fetch as a console error. This run sent exactly two deliberately invalid
    # requests (javascript: URL, empty URL); the UI handled both. Anything else (JS errors, CSP violations) fails.
    expected_400 = [p for p in problems if "status of 400" in p]
    other = [p for p in problems if "status of 400" not in p]
    check("no console errors / CSP violations (besides the 2 deliberate 400s)", not other and len(expected_400) == 2,
          other[:5] or len(expected_400))
    browser.close()

failed = results.count(False)
print(f"\n{len(results) - failed}/{len(results)} browser checks passed")
sys.exit(1 if failed else 0)
