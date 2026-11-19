# PhishGuard AI

AI-assisted phishing detection for **messages (SMS / email text)** and **URLs**, with a Security Operations Center style web dashboard.

* Detection, feature extraction, risk scoring and classification run **locally and offline** (scikit-learn + deterministic rules).
* An optional **OpenAI or Gemini** call only *explains* the finished result. It can never change the score, and the app works without it.
* Submitted URLs are **parsed as text and never opened**.

> **Read this first: the bundled models are trained on SYNTHETIC seed data.**
> No real phishing dataset was available where this project was built (no internet access), so `datasets/generate_seed.py` produces template-based sample data. The metrics below prove the pipeline works end to end; they say **nothing reliable about real-world accuracy**. For research or competition use, train on real, licence-checked data (see [Using real datasets](#using-real-datasets)).

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python train.py          # trains both models, writes models/ and models/evaluation.json
python app.py            # http://127.0.0.1:5000
```

`python train.py` generates the synthetic seed data automatically if `datasets/messages.csv` / `urls.csv` do not exist. Without trained models the app still runs, but scores use rule-based evidence only and every report carries a visible warning (rule-only scores can under-report risk).

Developed and tested on Python 3.12 (3.11+ should work) with Flask 3.1, scikit-learn 1.9, pandas 3.0, numpy 2.5, joblib 1.6, requests 2.34.

## Architecture

```
 message / URL
      │
      ▼
┌──────────────────── LOCAL (offline) ─────────────────────┐
│ detector.py   parse + validate → features / text → ML     │
│               message: TF-IDF + Logistic Regression       │
│               URL:     29 structural features + Random Forest │
│               + readable evidence (rules, typosquat, …)   │
│ risk_engine.py  documented weights → 0-100 score,         │
│                 level, category, recommendations          │
└───────────────────────────┬──────────────────────────────┘
                            ▼
                 structured report (SQLite history)
                            │  only on user click, only labels/numbers
                            ▼
        ai_summary.py ─► OpenAI / Gemini (optional)  ─► explanation text
                            └─ any failure → deterministic local summary
```

| File | Responsibility |
|---|---|
| `app.py` | Flask routes, SQLite history, CSRF/origin checks, security headers |
| `detector.py` | URL parsing, feature extraction, message indicators, verified model loading |
| `risk_engine.py` | Deterministic scoring (imports nothing, so it cannot depend on an AI layer) |
| `ai_summary.py` | Optional OpenAI/Gemini explanations, output validation, local fallback |
| `train.py` | Grouped train/test split, training, evaluation, robustness check, model manifest |
| `datasets/generate_seed.py` | Synthetic seed data generator (clearly labelled) |
| `templates/index.html`, `static/` | Dashboard (HTML + custom CSS + vanilla JS, no CDN, no framework) |
| `tests/` | 96 unit/integration tests + an optional real-browser end-to-end script |

## Configuration

Copy `.env.example` to `.env`. **Everything is optional**: detection needs none of it.

| Variable | Meaning |
|---|---|
| `AI_ENABLED` | `true` to allow AI summaries (default `false`) |
| `AI_PROVIDER` | `openai` or `gemini` |
| `OPENAI_API_KEY`, `OPENAI_MODEL` | Used only when provider is `openai`. Use a model your account supports |
| `GEMINI_API_KEY`, `GEMINI_MODEL` | Used only when provider is `gemini` |
| `AI_TIMEOUT` | Seconds before falling back to the local summary (default 20) |
| `SECRET_KEY` | Fixed Flask session secret (random per start if unset) |
| `PORT` | Port (default 5000). The server binds to `127.0.0.1` only |

Only the selected provider's key is needed. Keys stay on the server and are never sent to the browser (`/api/settings` reports only whether one is present).

### What an AI provider receives

Only a small JSON object built by `ai_summary.build_findings`: risk score, level, category, model confidence, **fixed evidence labels**, score breakdown and a link count. It never contains your message, URLs, domains or the TLD (tests assert this). The summary is requested per click from the Risk Analysis page, and the findings are rebuilt on the server from the saved report, so the client cannot inject content. The response is treated as untrusted: markup is stripped, length capped, and it is **rejected** (local summary shown instead) if it states a score that differs from the local one.

## Dashboard

Overview · URL Scanner · Message Scanner · Risk Analysis (gauge, score breakdown, recommendations, summary) · Detection Evidence · Analysis History · Settings (model and AI status, evaluation snapshot).

## API

State-changing requests need the session CSRF token (`X-CSRF-Token`) and `Content-Type: application/json`.

```bash
B=http://127.0.0.1:5000
TOKEN=$(curl -s -c jar $B/ | grep -o 'csrf-token" content="[^"]*' | cut -d'"' -f3)
curl -s -b jar -H "X-CSRF-Token: $TOKEN" -H "Content-Type: application/json" \
     -d '{"url":"http://secure-paypal-login.xyz/verify"}' $B/api/analyze/url
```

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Liveness |
| `POST /api/analyze/url` `{"url": …}` | Analyse a URL (≤ 2048 chars, http/https only) |
| `POST /api/analyze/message` `{"message": …}` | Analyse text (≤ 5000 chars) |
| `POST /api/summary` `{"analysis_id": "PG-000001"}` | AI (or local fallback) explanation of a saved analysis |
| `GET /api/history`, `GET /api/history/<id>`, `DELETE /api/history` | History |
| `GET /api/stats`, `GET /api/settings`, `GET /api/models/status` | Dashboard data |

## How the risk score works

`risk_score` (0-100) is **not** the model probability; both are reported. Weights are fixed, documented heuristics (not calibrated probabilities) in `risk_engine.py`.

| Report | Components |
|---|---|
| URL | 60 × P(phishing) from the Random Forest + up to 40 for structural evidence (IP host 15, typosquat 15, brand misuse 15, `@` 10, punycode 8, suspicious TLD 8, shortener 6, …) |
| Message | 40 × P(phishing) from the text model + up to 45 for language evidence (credential request 15, urgency 10, account threat 10, secrecy 10, brand/link mismatch 12, …) + up to 20 from the riskiest embedded link |

Levels: `<25` low · `<50` medium · `<75` high · `≥75` critical. Evidence over its cap is scaled down proportionally. The same input always gives the same score.

Language evidence is negation-aware ("never share your OTP" is advice, not a credential request).

## Training and evaluation

```bash
python train.py [--messages my_messages.csv] [--urls my_urls.csv]
```

* **Grouped splits**: messages are split by template, URLs by registered domain, so the 25 % test set contains templates and domains **never seen in training** (asserted in code). Seeded (`42`), hence reproducible.
* Reports accuracy, precision, recall, F1, ROC-AUC, false-positive rate and confusion matrix, plus grouped 5-fold CV, URL feature importances, a URL-variation robustness check, and an end-to-end evaluation of model + evidence + risk engine (`score ≥ 50` ⇒ phishing).
* Models are saved with a SHA-256 manifest and verified before loading.

### Measured results (SYNTHETIC data, held-out groups)

| | n test | Precision | Recall | F1 | ROC-AUC | FPR | Confusion (TN/FP/FN/TP) |
|---|---|---|---|---|---|---|---|
| Message model alone | 139 | 0.916 | 0.987 | 0.950 | 0.990 | 0.113 | 55 / 7 / 1 / 76 |
| URL model alone | 341 | 1.000 | 0.985 | 0.992 | 1.000 | 0.000 | 148 / 0 / 3 / 190 |
| Message end-to-end | 139 | 1.000 | 0.987 | 0.994 | 1.000 | 0.000 | 62 / 0 / 1 / 76 |
| URL end-to-end | 341 | 1.000 | 0.959 | 0.979 | 1.000 | 0.000 | 148 / 0 / 8 / 185 |

Grouped 5-fold CV F1: messages 0.965 ± 0.056, URLs 0.999 ± 0.002. URL recall after variations: query string appended 0.948, scheme swapped 0.959, trailing slash 0.979, uppercase host 0.985 (baseline 0.985).

**How to read these honestly**

* The data is synthetic and template-generated, so it is far easier than real traffic. Near-perfect URL scores mostly reflect easily separable generator patterns (top features: suspicious TLD, HTTPS, brand misuse).
* Of the message model's 7 false positives, 6 come from one legitimate template ("Payment … received"), and only 16 templates were held out, so message figures are high-variance (note the ±0.056).
* The indicator rules were written by the same author using the same vocabulary as the generator, so the end-to-end message result is **optimistic**, not independent evidence.
* I inspected held-out errors while fixing defects (e.g. typosquat logic), so this test set is no longer perfectly untouched. For a publishable result, freeze a fresh test set first.
* Query-string appending visibly reduces URL recall: a real, measured weakness.

### Using real datasets

Provide CSVs (UTF-8, header row required) and delete `datasets/SYNTHETIC_DATA.txt` so results are no longer flagged synthetic:

* `messages.csv`: `text,label,group`: `label` 1 = phishing, 0 = legitimate; `group` = source/campaign/template id (keeps near-duplicates on one side of the split).
* `urls.csv`: `url,label,group`: `group` = registered domain.

Candidate sources (verify each one's current licence and terms before use): phishing-email corpora for messages; PhishTank/OpenPhish-style feeds for phishing URLs; a top-sites list such as Tranco for legitimate domains. The SMS Spam Collection is **spam, not phishing**; do not treat spam as phishing. Remove duplicates and document sources, versions and licences in your report.

## Testing

```bash
python -m unittest discover -s tests -t .        # 96 tests (pytest also discovers them)
```

Covers URL parsing and validation, features, typosquat/brand logic, negation handling, model integrity checks, risk scoring, AI provider success and every failure mode (timeouts, HTTP errors, malformed or contradicting output, missing key), privacy of provider payloads, CSRF/origin handling, no-network URL analysis, raw-content storage, SQL-injection attempts, rate limiting, offline and no-model operation, and regex run-time bounds.

Optional real-browser check (needs `pip install playwright` and a Chromium build):

```bash
python app.py &                                   # use an empty phishguard.db
BASE_URL=http://127.0.0.1:5000 python tests/e2e_browser.py
```

It drives the real UI (both scanners, risk view, evidence, history, settings, clearing history, mobile layout and overflow), confirms an injected `<script>`/`onerror` payload does not execute, and fails on any unexpected console error or CSP violation.

## Security notes

| Area | Status |
|---|---|
| SSRF / URL visiting | URLs are only parsed; a test fails if any socket, DNS or `requests` call happens during analysis |
| XSS | All dynamic text is inserted via `textContent` (no `innerHTML`); strict CSP: no inline script/style, no third-party origins, no `unsafe-eval` |
| CSRF | Per-session token on all state-changing calls, `Origin` check, `SameSite=Strict` HttpOnly cookie, JSON-only bodies |
| Injection | Parameterised SQL only; no shell/subprocess/eval anywhere |
| Secrets | Keys only in server environment; never in responses, pages or logs; `.env` is git-ignored |
| Privacy | Message text and full URLs are not stored. History keeps scores, evidence labels and registered domains of scanned links |
| DoS | Body ≤ 64 KB, message ≤ 5000, URL ≤ 2048 chars, ≤ 5 links/message, bounded regexes (worst measured adversarial input ≈ 10 ms), 10 AI summaries/min/client |
| Model loading | `joblib` uses pickle. Files are SHA-256-verified against `models/manifest.json` before loading. This catches accidental or partial tampering, **not** an attacker who can rewrite both files, so treat `models/` as trusted-only |
| Not done | Dependency CVE scan (no network here; run `pip-audit`), HTTPS/`Secure` cookies (run behind a TLS proxy and set `SESSION_COOKIE_SECURE=True` in `create_app`), production WSGI server (`python app.py` is Flask's development server; use waitress/gunicorn), authentication, multi-user separation (history is global) |

## Limitations

* Trained on synthetic data until you supply real data. Real-world precision/recall are **unknown**.
* English only. Hinglish and other languages are future work.
* URL analysis is structural only: no live reputation, WHOIS, domain age, page content or redirect following. A brand-new clean-looking phishing domain can score low; a legitimate odd-looking URL can score high.
* The brand and typosquat lists are small and hand-written; very short brand names (e.g. 3-4 letters) are not edit-distance matched to avoid false alarms.
* The message model is a bag-of-words model: it cannot judge sender identity, headers, attachments or images.
* Risk weights are heuristic, not calibrated. A "low risk" result is **not** a guarantee of safety.
* Generative explanations can be imperfect; they are validated but not fact-checked beyond the score check.
* Provider calls were exercised only against mocked HTTP responses. They have **not** been run against live OpenAI/Gemini endpoints (no network or keys here). Check that your chosen model name is valid for your account.
* Without models the app still works but under-reports (it warns when this happens).

## Project layout

```
app.py  detector.py  risk_engine.py  ai_summary.py  train.py
datasets/   generate_seed.py, SYNTHETIC_DATA.txt, messages.csv, urls.csv (synthetic)
models/     message_model.joblib, url_model.joblib, manifest.json, evaluation.json
templates/  index.html          static/  style.css, app.js
tests/      test_detector.py, test_risk_engine.py, test_ai_summary.py, test_app.py, e2e_browser.py
requirements.txt  .env.example  .gitignore  README.md
```
