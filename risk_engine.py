"""PhishGuard AI - deterministic risk engine.

The 0-100 risk score is computed ONLY from local evidence with the fixed weights
below. It is reproducible (same input -> same score) and is never influenced by
any external AI provider.

NOTE: the weights are hand-set heuristics, not calibrated probabilities. The
score is a prioritisation aid, distinct from the ML model probability.
"""

LEVELS = [(25, "low"), (50, "medium"), (75, "high"), (101, "critical")]

# ---- URL scoring weights -------------------------------------------------
URL_ML_MAX = 60  # points = 60 * P(phishing) from the URL model
URL_EVIDENCE_POINTS = {
    "ip_host": 15, "at_symbol": 10, "typosquat": 15, "brand_misuse": 15, "punycode": 8, "suspicious_tld": 8,
    "shortener": 6, "brand_in_domain": 6, "many_subdomains": 6, "keyword_host": 6, "hyphens": 4,
    "no_https": 5, "nonstd_port": 5, "long_url": 3, "risky_extension": 3, "encoded_chars": 3,
}
URL_EVIDENCE_CAP = 40

# ---- message scoring weights ----------------------------------------------
MSG_ML_MAX = 40  # points = 40 * P(phishing) from the message model
MSG_EVIDENCE_POINTS = {
    "credential_request": 15, "urgency": 10, "account_threat": 10, "financial_lure": 8, "delivery_lure": 4,
    "brand_link_mismatch": 12, "generic_greeting": 4, "attachment_lure": 6, "secrecy_request": 10,
}
MSG_EVIDENCE_CAP = 45
MSG_LINK_MAX = 20  # points = 0.20 * highest embedded-URL risk score (0-100)

# Without a trained model we cannot award ML points; scores then rest on evidence only. Such reports carry an
# explicit warning because rule-only scores can under-report risk.
NO_MODEL_WARNING = ("Detection model unavailable: this score uses rule-based evidence only and may under-report "
                    "risk. Run `python train.py` to create the models.")


def risk_level(score):
    for bound, name in LEVELS:
        if score < bound:
            return name
    return "critical"


def classification(score):
    if score >= 50:
        return "phishing"
    if score >= 25:
        return "suspicious"
    return "low_risk"


def _confidence(p):
    return None if p is None else round(max(p, 1 - p), 3)


def _evidence_with_points(evidence, table, cap):
    """Attach points to each evidence item, scaling down proportionally if the cap is exceeded."""
    raw = [(e, table.get(e["code"], 0)) for e in evidence]
    total = sum(p for _, p in raw)
    scale = min(1.0, cap / total) if total else 1.0
    items, running = [], 0
    for e, pts in raw:
        scaled = int(round(pts * scale))
        running += scaled
        items.append({**e, "points": scaled})
    return items, running


RECOMMENDATIONS = {
    "Credential Phishing": [
        "Do not click the link or enter any password, OTP or card details.",
        "If you think the account is genuinely affected, open the service's official app or type its address yourself.",
        "Report the message as phishing to your provider or IT/security team, then delete it.",
    ],
    "Financial Scam": [
        "Do not pay any fee or share bank or card details to claim a prize, refund or grant.",
        "Genuine refunds and prizes never require upfront payment or your PIN/OTP.",
        "Report the message to your bank or the relevant fraud-reporting service.",
    ],
    "Delivery Scam": [
        "Do not pay customs or redelivery fees through links in messages.",
        "Check the parcel status using the tracking number on the courier's official website or app.",
    ],
    "Brand Impersonation": [
        "Do not use the link. Go to the organisation's official website or app directly.",
        "Contact the organisation through a phone number or address you already trust.",
    ],
    "Executive / Payment Fraud": [
        "Verify the request by calling the person on a known number before acting.",
        "Never send gift-card codes or change bank details based on a message alone.",
    ],
    "Malicious Link": [
        "Do not open this link. If you must inspect it, use a sandbox or a URL-reputation service.",
        "Do not enter credentials on the destination page.",
    ],
    "Suspicious Message": [
        "Treat the message with caution and verify the sender through another channel.",
        "Avoid clicking links or opening attachments until verified.",
    ],
    "No Strong Indicators": [
        "No strong phishing indicators were found, but this is not a guarantee of safety.",
        "Stay alert to unexpected requests for money, credentials or urgent action.",
    ],
}


def _message_category(evidence_codes, url_score, score):
    c = evidence_codes
    if score < 25:
        return "No Strong Indicators"
    if "secrecy_request" in c and ("financial_lure" in c or "urgency" in c):
        return "Executive / Payment Fraud"
    if "credential_request" in c:
        return "Credential Phishing"
    if "financial_lure" in c:
        return "Financial Scam"
    if "delivery_lure" in c:
        return "Delivery Scam"
    if "brand_link_mismatch" in c:
        return "Brand Impersonation"
    if url_score >= 50:
        return "Malicious Link"
    return "Suspicious Message"


def _url_category(evidence_codes, score):
    c = evidence_codes
    if score < 25:
        return "No Strong Indicators"
    if c & {"brand_misuse", "typosquat", "brand_in_domain", "keyword_host"}:
        return "Credential Phishing"
    return "Malicious Link"


def score_url(analysis):
    p = analysis["model_probability"]
    ml_points = int(round(URL_ML_MAX * p)) if p is not None else 0
    items, ev_points = _evidence_with_points(analysis["indicators"], URL_EVIDENCE_POINTS, URL_EVIDENCE_CAP)
    score = max(0, min(100, ml_points + ev_points))
    codes = {i["code"] for i in items}
    category = _url_category(codes, score)
    breakdown = [
        {"factor": "URL classifier output (Random Forest)", "points": ml_points, "max": URL_ML_MAX,
         "note": "Model unavailable" if p is None else f"P(phishing) = {p:.2f}"},
        {"factor": "Structural URL evidence", "points": ev_points, "max": URL_EVIDENCE_CAP, "note": ""},
    ]
    return {
        "input_type": "url", "risk_score": score, "risk_level": risk_level(score),
        "classification": classification(score), "threat_category": category,
        "model_probability": None if p is None else round(p, 4), "model_confidence": _confidence(p),
        "ml_available": p is not None, "breakdown": breakdown, "evidence": items,
        "recommendations": RECOMMENDATIONS[category],
        "warnings": [] if p is not None else [NO_MODEL_WARNING],
        "urls": [], "registered_domain": analysis["registered_domain"],
    }


def score_message(analysis):
    p = analysis["model_probability"]
    ml_points = int(round(MSG_ML_MAX * p)) if p is not None else 0
    items, ev_points = _evidence_with_points(analysis["indicators"], MSG_EVIDENCE_POINTS, MSG_EVIDENCE_CAP)
    url_reports = [score_url(u) for u in analysis["urls"]]
    top_url = max((u["risk_score"] for u in url_reports), default=0)
    link_points = int(round(MSG_LINK_MAX * top_url / 100))
    score = max(0, min(100, ml_points + ev_points + link_points))
    codes = {i["code"] for i in items}
    category = _message_category(codes, top_url, score)
    breakdown = [
        {"factor": "Message classifier output (TF-IDF + Logistic Regression)", "points": ml_points,
         "max": MSG_ML_MAX, "note": "Model unavailable" if p is None else f"P(phishing) = {p:.2f}"},
        {"factor": "Language and social-engineering evidence", "points": ev_points, "max": MSG_EVIDENCE_CAP,
         "note": ""},
        {"factor": "Embedded link risk", "points": link_points, "max": MSG_LINK_MAX,
         "note": f"{len(url_reports)} link(s) analysed" if url_reports else "No links found"},
    ]
    link_evidence = []
    for u in url_reports:
        for e in u["evidence"]:
            if e["severity"] in ("high", "medium"):
                link_evidence.append({**e, "label": f"[{u['registered_domain']}] {e['label']}", "points": 0})
    return {
        "input_type": "message", "risk_score": score, "risk_level": risk_level(score),
        "classification": classification(score), "threat_category": category,
        "model_probability": None if p is None else round(p, 4), "model_confidence": _confidence(p),
        "ml_available": p is not None, "breakdown": breakdown, "evidence": items + link_evidence,
        "recommendations": RECOMMENDATIONS[category],
        "warnings": [] if (p is not None and all(u["ml_available"] for u in url_reports)) else [NO_MODEL_WARNING],
        "urls": [{"registered_domain": u["registered_domain"], "risk_score": u["risk_score"],
                  "risk_level": u["risk_level"]} for u in url_reports],
        "char_count": analysis["char_count"],
    }
