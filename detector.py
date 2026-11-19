"""PhishGuard AI - local detection engine.

Everything here runs offline. Nothing in this module opens, resolves or fetches
a submitted URL; URLs are only parsed as strings.
"""
import hashlib
import ipaddress
import json
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

import joblib

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
MESSAGE_MODEL = "message_model.joblib"
URL_MODEL = "url_model.joblib"
MANIFEST = "manifest.json"

MAX_URL_LEN = 2048
MAX_MESSAGE_LEN = 5000
MAX_URLS_PER_MESSAGE = 5

MULTI_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "net.in",
                  "org.in", "co.jp", "com.br", "co.za", "com.cn", "com.mx", "co.nz", "com.sg", "com.tr"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "buzz", "tk", "ml", "ga", "cf", "gq", "icu", "rest", "work", "live",
                   "support", "zip", "mov", "country", "kim", "loan", "cam"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy",
              "shorturl.at", "tiny.cc"}
BRANDS = ["paypal", "microsoft", "google", "amazon", "netflix", "facebook", "instagram", "whatsapp", "linkedin",
          "dropbox", "adobe", "docusign", "fedex", "dhl", "usps", "paytm", "hdfc", "icici", "sbi", "chase",
          "wellsfargo", "citibank", "bankofamerica", "outlook", "office365", "coinbase", "binance", "metamask",
          "apple", "icloud", "steam", "spotify"]
URL_KEYWORDS = ["login", "signin", "sign-in", "verify", "verification", "secure", "account", "update", "confirm",
                "password", "bank", "billing", "wallet", "support", "unlock", "suspend", "recover", "validate",
                "authenticate", "webscr", "payment"]
RISKY_EXTENSIONS = (".php", ".exe", ".scr", ".zip", ".apk", ".bat", ".js", ".jar")

URL_FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len", "host_dots", "n_subdomains", "has_ip", "has_at",
    "host_hyphens", "host_digit_ratio", "is_https", "nonstd_port", "n_params", "kw_host", "kw_path",
    "brand_misuse", "brand_in_domain_inexact", "typosquat", "punycode", "non_ascii", "suspicious_tld",
    "shortener", "host_entropy", "n_pct_encoded", "double_slash_path", "path_depth", "risky_extension",
    "reg_len", "longest_label",
]


# --------------------------------------------------------------------------- URL parsing
def _split_host(host):
    labels = host.split(".")
    if len(labels) < 2:
        return "", host, ""
    if ".".join(labels[-2:]) in MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[:-3]), ".".join(labels[-3:]), ".".join(labels[-2:])
    return ".".join(labels[:-2]), ".".join(labels[-2:]), labels[-1]


def _is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"0x[0-9a-f]{6,8}", host))


def parse_url(raw):
    """Parse and validate a URL string. Raises ValueError for unusable input."""
    if not isinstance(raw, str):
        raise ValueError("URL must be a string.")
    raw = raw.strip()
    if not raw:
        raise ValueError("URL is empty.")
    if len(raw) > MAX_URL_LEN:
        raise ValueError(f"URL is longer than {MAX_URL_LEN} characters.")
    if re.search(r"[\s\x00-\x1f\x7f]", raw):
        raise ValueError("URL contains whitespace or control characters.")
    scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*):(?!\d+(?:[/?#]|$))", raw)  # "host:8080" is a port, not a scheme
    if scheme_match and scheme_match.group(1).lower() not in ("http", "https"):
        raise ValueError("Only http and https URLs can be analysed.")
    candidate = raw
    if "://" not in candidate:
        candidate = "http://" + candidate.lstrip("/")  # string-level default only; never visited
    scheme = candidate.split("://", 1)[0].lower()
    if scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs can be analysed.")
    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"Malformed URL: {exc}") from None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host or "." not in host and not _is_ip(host):
        raise ValueError("URL has no valid host name.")
    userinfo = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else ""
    if _is_ip(host):
        sub, reg, tld = "", host, ""
    else:
        sub, reg, tld = _split_host(host)
    return {
        "raw": raw, "scheme": parts.scheme.lower(), "host": host, "port": port, "path": parts.path,
        "query": parts.query, "userinfo": userinfo, "sub": sub, "reg": reg, "tld": tld,
        "had_scheme": "://" in raw,
    }


def _entropy(s):
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def _leet(s):
    s = s.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "$": "s", "@": "a"}))
    return s.replace("rn", "m").replace("vv", "w")


def _edit_distance_le1(a, b):
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = diff = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        diff += 1
        if diff > 1:
            return False
        if len(a) == len(b):
            i += 1
        j += 1
    return diff + (len(b) - j) + (len(a) - i) <= 1


def _brand_flags(p):
    if _is_ip(p["host"]):
        return 0, 0, 0
    reg_label = p["reg"].split(".")[0]
    tokens = set(re.split(r"[^a-z0-9]+", (p["sub"] + "/" + p["path"]).lower()))
    misuse = int(any(b in tokens and b != reg_label and b not in reg_label for b in BRANDS))
    leet = _leet(reg_label)
    # Edit-distance matching is limited to longer brand names: short ones (apple, chase, steam) are too
    # close to ordinary words (maple, phase, stream) and would cause false alarms.
    typo = int(any(
        b != reg_label and ((len(b) >= 6 and _edit_distance_le1(reg_label, b)) or
                            (len(b) >= 4 and b not in reg_label and b in leet))
        for b in BRANDS))
    inexact = int(any(b in reg_label and b != reg_label for b in BRANDS))
    return misuse, inexact, typo


def url_features(p):
    """Return an ordered dict of numeric features for a parsed URL."""
    host, path = p["host"], p["path"]
    misuse, inexact, typo = _brand_flags(p)
    host_digits = sum(c.isdigit() for c in host)
    labels = host.split(".")
    low = (host, path.lower())
    feats = {
        "url_len": len(p["raw"]), "host_len": len(host), "path_len": len(path), "query_len": len(p["query"]),
        "host_dots": host.count("."), "n_subdomains": len([s for s in p["sub"].split(".") if s]),
        "has_ip": int(_is_ip(host)), "has_at": int("@" in p["raw"].split("?", 1)[0]),
        "host_hyphens": host.count("-"), "host_digit_ratio": host_digits / max(len(host), 1),
        "is_https": int(p["scheme"] == "https"),
        "nonstd_port": int(p["port"] not in (None, 80, 443)),
        "n_params": len([q for q in p["query"].split("&") if q]),
        "kw_host": sum(k in low[0] for k in URL_KEYWORDS), "kw_path": sum(k in low[1] for k in URL_KEYWORDS),
        "brand_misuse": misuse, "brand_in_domain_inexact": inexact, "typosquat": typo,
        "punycode": int(any(l.startswith("xn--") for l in labels)),
        "non_ascii": int(any(ord(c) > 127 for c in host)),
        "suspicious_tld": int(p["tld"].split(".")[-1] in SUSPICIOUS_TLDS),
        "shortener": int(p["reg"] in SHORTENERS), "host_entropy": _entropy(host),
        "n_pct_encoded": len(re.findall(r"%[0-9a-fA-F]{2}", p["raw"])),
        "double_slash_path": int("//" in path), "path_depth": len([s for s in path.split("/") if s]),
        "risky_extension": int(path.lower().endswith(RISKY_EXTENSIONS)),
        "reg_len": len(p["reg"]), "longest_label": max((len(l) for l in labels), default=0),
    }
    return feats


def url_vector(feats):
    return [float(feats[n]) for n in URL_FEATURE_NAMES]


def url_indicators(p, f):
    """Deterministic, human-readable evidence derived from URL features."""
    ev = []

    def add(code, label, severity):
        ev.append({"code": code, "label": label, "severity": severity})

    if f["has_ip"]:
        add("ip_host", "Uses a raw IP address instead of a domain name", "high")
    if f["has_at"]:
        add("at_symbol", "Contains '@', which can disguise the real destination", "high")
    if f["typosquat"]:
        add("typosquat", "Domain closely imitates a well-known brand name", "high")
    if f["brand_misuse"]:
        add("brand_misuse", "Brand name appears in the subdomain or path but not in the registered domain", "high")
    if f["punycode"] or f["non_ascii"]:
        add("punycode", "Internationalised (punycode / non-ASCII) host can hide look-alike characters", "medium")
    if f["suspicious_tld"]:
        add("suspicious_tld", "Top-level domain is frequently abused for phishing", "medium")
    if f["shortener"]:
        add("shortener", "Link shortener hides the final destination", "medium")
    if f["brand_in_domain_inexact"] and not f["typosquat"]:
        add("brand_in_domain", "Brand name embedded inside a different domain name", "medium")
    if f["n_subdomains"] >= 3:
        add("many_subdomains", f"Unusually many subdomains ({f['n_subdomains']})", "medium")
    if f["kw_host"] >= 1:
        add("keyword_host", "Credential-related keyword in the host name", "medium")
    if f["host_hyphens"] >= 3:
        add("hyphens", "Many hyphens in host name", "low")
    if not f["is_https"]:
        add("no_https", "Connection is not HTTPS", "low")
    if f["nonstd_port"]:
        add("nonstd_port", "Uses a non-standard port", "medium")
    if f["url_len"] > 100:
        add("long_url", f"Very long URL ({f['url_len']} characters)", "low")
    if f["risky_extension"]:
        add("risky_extension", "Path points to a script or executable-type file", "low")
    if f["n_pct_encoded"] >= 3:
        add("encoded_chars", "Heavy percent-encoding can obscure the real path", "low")
    return ev


# --------------------------------------------------------------------------- message analysis
_URL_RE = re.compile(
    r"(?:https?://[^\s<>\"']+|www\.[^\s<>\"']+|"
    r"(?<![@\w.\-])(?:[a-z0-9\-]{1,63}\.){1,10}(?:com|net|org|info|xyz|top|click|link|ly|co|in|io|live|buzz|work|icu)"
    r"\b(?:/[^\s<>\"']*)?)", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}")  # bounded: no quadratic backtracking


def extract_urls(text):
    found = []
    for m in _URL_RE.finditer(_EMAIL_RE.sub(" ", text)):
        u = m.group(0).rstrip(".,;:!?)]}>'\"")
        if u and u not in found:
            found.append(u)
    return found[:MAX_URLS_PER_MESSAGE]


def preprocess_message(text):
    """Lower-case and normalise URLs / emails / numbers. Used by the TF-IDF vectoriser."""
    t = _EMAIL_RE.sub(" emailtoken ", text)
    t = _URL_RE.sub(" urltoken ", t)
    t = t.lower()
    t = re.sub(r"\d+", " numtoken ", t)
    return re.sub(r"\s+", " ", t).strip()


_PATTERNS = {
    "urgency": (re.compile(r"\b(immediately|urgent(?:ly)?|asap|act now|right away|final notice|last chance|"
                           r"within \d+ (?:hours?|hrs?|minutes?)|expires? (?:today|tonight|soon|in)|"
                           r"as soon as possible|today only|before it'?s too late|tonight)\b", re.I),
                "Urgent or time-pressure language", "medium"),
    "credential_request": (re.compile(
        r"(\b(?:verify|confirm|update|validate|re-?activate|re-?enter)\b[^.!?\n;,]{0,40}\b(?:account|identity|password|"
        r"details|information|payment|billing|card|credentials|kyc|pan|aadhaar)\b)|"
        r"(\b(?:enter|provide|send|reply with|share|submit)\b[^.!?\n;,]{0,25}\b(?:password|otp|pin|cvv|card number|"
        r"ssn|bank details|account number|recovery phrase|seed phrase)\b)|"
        r"(\b(?:log ?in|sign ?in)\b[^.!?\n]{0,30}\b(?:to (?:view|verify|keep|confirm|restore|unlock)|with your)\b)",
        re.I), "Requests credentials, verification or sensitive details", "high"),
    "account_threat": (re.compile(
        r"\b(suspend(?:ed)?|locked|limited|terminat\w+|deactivat\w+|unauthori[sz]ed|compromised|blocked|"
        r"disconnect\w*|frozen|closure|permanent(?:ly)? (?:suspension|closed)|legal action|"
        r"will be (?:deleted|cancel+ed|returned))\b", re.I),
        "Threatens account suspension or other negative consequences", "medium"),
    "financial_lure": (re.compile(
        r"\b(you(?:'ve| have)? won|winner|lottery|prize|gift ?cards?|claim your|refund of|tax refund|inheritance|"
        r"grant of|crypto|bitcoin|wire transfer|processing fee|earn [^.]{0,15}per week|work from home)\b", re.I),
        "Financial lure, prize, refund or payment demand", "medium"),
    "delivery_lure": (re.compile(
        r"\b(parcel|package|shipment|customs fee|redelivery|could not be delivered|undelivered)\b", re.I)
        , "Delivery / parcel-themed wording", "low"),
    "generic_greeting": (re.compile(r"\bdear (customer|user|client|member|account holder|sir/madam)\b", re.I),
                         "Generic greeting instead of a personal name", "low"),
    "attachment_lure": (re.compile(r"\b(open the attach\w+|enable (?:macros|content)|see attached file)\b", re.I),
                        "Pushes the reader to open an attachment or enable macros", "medium"),
    "secrecy_request": (re.compile(r"\b(keep this confidential|do not call|don'?t tell|do not tell|"
                                   r"between us|send me the codes)\b", re.I),
                        "Asks for secrecy or to bypass normal verification", "high"),
}
_BRAND_RE = re.compile(r"\b(" + "|".join(re.escape(b) for b in BRANDS + ["hdfc bank", "wells fargo"]) + r")\b", re.I)


# A negation earlier in the same clause ("never share your OTP", "do not enter your password") turns a
# credential request into protective advice, so those matches must not count as evidence.
_NEGATION_AWARE = {"credential_request"}
_NEGATION_RE = re.compile(r"(?:\b(?:never|not|no one|cannot|can't|won't)\b|n['\u2019]t\b)[^,;.!?]*$", re.I)


def _has_unnegated_match(rx, text):
    for m in rx.finditer(text):
        if not _NEGATION_RE.search(text[max(0, m.start() - 50):m.start()]):
            return True
    return False


def message_indicators(text, url_analyses):
    ev = []
    for code, (rx, label, sev) in _PATTERNS.items():
        hit = _has_unnegated_match(rx, text) if code in _NEGATION_AWARE else rx.search(text)
        if hit:
            ev.append({"code": code, "label": label, "severity": sev})
    brands = {m.group(1).lower().replace(" ", "") for m in _BRAND_RE.finditer(text)}
    if brands and url_analyses:
        for u in url_analyses:
            reg_label = u["registered_domain"].split(".")[0]
            if not any(b in reg_label for b in brands):
                ev.append({"code": "brand_link_mismatch",
                           "label": "A well-known brand is mentioned but the link points to an unrelated domain",
                           "severity": "high"})
                break
    return ev


# --------------------------------------------------------------------------- model loading
def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(model_dir, extra=None):
    model_dir = Path(model_dir)
    data = {"files": {n: _sha256(model_dir / n) for n in (MESSAGE_MODEL, URL_MODEL)}}
    data.update(extra or {})
    (model_dir / MANIFEST).write_text(json.dumps(data, indent=2))


def _load_verified(model_dir, name, manifest):
    path = Path(model_dir) / name
    if not path.exists():
        return None, "model file not found"
    expected = (manifest or {}).get("files", {}).get(name)
    if not expected:
        return None, "no integrity record in manifest.json"
    if _sha256(path) != expected:
        return None, "integrity check failed (file changed since training)"
    try:
        return joblib.load(path), "loaded"
    except Exception as exc:  # corrupted / incompatible versions
        return None, f"could not be loaded: {type(exc).__name__}"


class Detector:
    """Holds the trained models and produces structured local analysis results."""

    def __init__(self, message_model=None, url_model=None, status=None):
        self.message_model = message_model
        self.url_model = url_model
        self.status = status or {
            "message_model": {"loaded": message_model is not None, "detail": "in-memory"},
            "url_model": {"loaded": url_model is not None, "detail": "in-memory"},
        }

    @classmethod
    def load(cls, model_dir=MODEL_DIR):
        model_dir = Path(model_dir)
        manifest = None
        mpath = model_dir / MANIFEST
        if mpath.exists():
            try:
                manifest = json.loads(mpath.read_text())
            except ValueError:
                manifest = None
        msg, msg_detail = _load_verified(model_dir, MESSAGE_MODEL, manifest)
        url, url_detail = _load_verified(model_dir, URL_MODEL, manifest)
        status = {"message_model": {"loaded": msg is not None, "detail": msg_detail},
                  "url_model": {"loaded": url is not None, "detail": url_detail}}
        return cls(msg, url, status)

    # -- URL ---------------------------------------------------------------
    def analyze_url(self, raw):
        p = parse_url(raw)
        f = url_features(p)
        prob = None
        if self.url_model is not None:
            prob = float(self.url_model.predict_proba([url_vector(f)])[0][1])
        return {
            "registered_domain": p["reg"], "host": p["host"], "features": f,
            "model_probability": prob, "ml_available": prob is not None,
            "indicators": url_indicators(p, f),
        }

    # -- message -----------------------------------------------------------
    def analyze_message(self, text):
        if not isinstance(text, str):
            raise ValueError("Message must be a string.")
        text = text.strip()
        if not text:
            raise ValueError("Message is empty.")
        if len(text) > MAX_MESSAGE_LEN:
            raise ValueError(f"Message is longer than {MAX_MESSAGE_LEN} characters.")
        if "\x00" in text:
            raise ValueError("Message contains invalid characters.")
        urls = []
        for u in extract_urls(text):
            try:
                urls.append(self.analyze_url(u))
            except ValueError:
                continue  # unparsable fragments are ignored, never fetched
        prob = None
        if self.message_model is not None:
            prob = float(self.message_model.predict_proba([text])[0][1])
        return {
            "model_probability": prob, "ml_available": prob is not None, "urls": urls,
            "indicators": message_indicators(text, urls), "char_count": len(text),
        }
