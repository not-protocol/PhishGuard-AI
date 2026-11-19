"""Shared test helpers: an in-memory trained Detector built from the seed CSVs."""
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import detector as det  # noqa: E402
import train  # noqa: E402

_CACHE = {}


def get_detector():
    """Detector with freshly trained models (cached per test run). Deterministic (seeded)."""
    if "d" not in _CACHE:
        msgs = pd.read_csv(ROOT / "datasets" / "messages.csv")
        urls = pd.read_csv(ROOT / "datasets" / "urls.csv")
        mm = train.message_pipeline().fit(msgs["text"], msgs["label"])
        um = train.url_model().fit(train.url_matrix(urls["url"]), urls["label"])
        _CACHE["d"] = det.Detector(mm, um)
    return _CACHE["d"]


PHISH_MSG = ("Dear customer, your PayPal account has been suspended due to unusual activity. Verify your "
             "password immediately at http://paypal-secure-login.xyz/verify or your account will be locked.")
BENIGN_MSG = "Hi Sam, are we still on for lunch tomorrow at 1 PM? Let me know if you want to change the place."
PHISH_URL = "http://paypal-secure-login.xyz/verify/account.php"
BENIGN_URL = "https://www.wikipedia.org/"
