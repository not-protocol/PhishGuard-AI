import shutil
import tempfile
import unittest
from pathlib import Path

import joblib

import detector as det
from tests.common import BENIGN_MSG, BENIGN_URL, PHISH_MSG, PHISH_URL, ROOT, get_detector


class ParseUrlTests(unittest.TestCase):
    def test_valid_urls(self):
        p = det.parse_url("https://accounts.google.com/signin?x=1")
        self.assertEqual((p["host"], p["reg"], p["sub"], p["tld"]), ("accounts.google.com", "google.com", "accounts", "com"))
        self.assertEqual(det.parse_url("bbc.co.uk/news")["reg"], "bbc.co.uk")  # no scheme is tolerated
        self.assertEqual(det.parse_url("http://news.bbc.co.uk")["sub"], "news")

    def test_ip_host(self):
        p = det.parse_url("http://192.168.10.5:8080/login")
        self.assertEqual(p["host"], "192.168.10.5")
        self.assertEqual(p["port"], 8080)
        self.assertEqual(det.url_features(p)["has_ip"], 1)

    def test_rejects_bad_input(self):
        for bad in ["", "   ", None, 123, "javascript:alert(1)", "ftp://example.com/x", "file:///etc/passwd",
                    "data:text/html,<script>", "http://", "http://[::1", "http://exa mple.com", "http://a.com/\x00",
                    "http://" + "a" * 2100 + ".com", "nodots", "http:///path"]:
            with self.subTest(bad=repr(bad)[:40]):
                with self.assertRaises(ValueError):
                    det.parse_url(bad)


    def test_unsupported_schemes_get_a_clear_message(self):
        for bad in ["javascript:alert(1)", "mailto:a@b.com", "data:text/html,x", "ftp://example.com/x", "file:///etc/passwd"]:
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, "Only http and https"):
                    det.parse_url(bad)

    def test_host_with_port_is_not_mistaken_for_a_scheme(self):
        self.assertEqual(det.parse_url("example.com:8080/login")["port"], 8080)
        self.assertEqual(det.parse_url("HTTPS://Example.com/")["host"], "example.com")


class FeatureTests(unittest.TestCase):
    def feats(self, url):
        return det.url_features(det.parse_url(url))

    def test_feature_vector_is_complete_and_numeric(self):
        f = self.feats(PHISH_URL)
        self.assertEqual(set(f), set(det.URL_FEATURE_NAMES))
        self.assertEqual(len(det.url_vector(f)), len(det.URL_FEATURE_NAMES))

    def test_at_symbol_and_https(self):
        self.assertEqual(self.feats("http://paypal.com@evil-site.xyz/a")["has_at"], 1)
        self.assertEqual(self.feats("https://example.com/")["is_https"], 1)
        self.assertEqual(self.feats("http://example.com/")["is_https"], 0)

    def test_brand_misuse_vs_legit(self):
        self.assertEqual(self.feats("http://paypal.secure-update.xyz/login")["brand_misuse"], 1)
        self.assertEqual(self.feats("https://www.paypal.com/signin")["brand_misuse"], 0)
        self.assertEqual(self.feats("https://support.microsoft.com/help")["brand_misuse"], 0)

    def test_typosquats(self):
        for url in ["https://paypa1.com/login", "https://googlee.com/", "https://netfliix.com/", "https://micros0ft.com/"]:
            with self.subTest(url=url):
                self.assertEqual(self.feats(url)["typosquat"], 1)
        for url in ["https://www.paypal.com/", "https://maple-syrup.com/", "https://stream.example.org/", "https://phase.io/"]:
            with self.subTest(url=url):
                self.assertEqual(self.feats(url)["typosquat"], 0)

    def test_punycode_and_tld(self):
        self.assertEqual(self.feats("http://xn--pypal-4ve.com/")["punycode"], 1)
        self.assertEqual(self.feats("http://something.xyz/")["suspicious_tld"], 1)
        self.assertEqual(self.feats("http://something.com/")["suspicious_tld"], 0)

    def test_indicators_are_readable_and_deterministic(self):
        p = det.parse_url("http://203.0.113.9/paypal/login.php")
        ev = det.url_indicators(p, det.url_features(p))
        codes = {e["code"] for e in ev}
        self.assertIn("ip_host", codes)
        self.assertIn("no_https", codes)
        self.assertEqual(ev, det.url_indicators(p, det.url_features(p)))


class MessageTextTests(unittest.TestCase):
    def test_extract_urls(self):
        text = "Visit http://a.example.com/x, or www.test.org/path. Mail me at bob@gmail.com. Also bit.ly/abc123!"
        urls = det.extract_urls(text)
        self.assertIn("http://a.example.com/x", urls)
        self.assertIn("www.test.org/path", urls)
        self.assertIn("bit.ly/abc123", urls)
        self.assertFalse(any("gmail" in u for u in urls))  # e-mail domains are not links

    def test_extract_urls_limit(self):
        text = " ".join(f"http://site{i}.com/" for i in range(20))
        self.assertEqual(len(det.extract_urls(text)), det.MAX_URLS_PER_MESSAGE)

    def test_preprocess_normalises(self):
        out = det.preprocess_message("Click HTTP://Evil.com/x NOW! Call 555-1234 or mail a@b.com")
        self.assertIn("urltoken", out)
        self.assertIn("numtoken", out)
        self.assertIn("emailtoken", out)
        self.assertNotIn("evil", out)

    def codes(self, text, urls=()):
        return {e["code"] for e in det.message_indicators(text, list(urls))}

    def test_phishing_indicators(self):
        c = self.codes(PHISH_MSG)
        self.assertTrue({"urgency", "credential_request", "account_threat"} <= c, c)

    def test_legit_otp_and_security_tip_not_credential_request(self):
        for text in ["Your Google verification code is 123456. Do not share this code with anyone.",
                     "Security tip: never share your OTP or password with anyone, including bank staff.",
                     "Your password was changed successfully. If you did this, no action is needed."]:
            with self.subTest(text=text[:40]):
                self.assertNotIn("credential_request", self.codes(text))

    def test_negation_is_clause_scoped(self):
        for text in ["Never share your OTP with anyone.", "We will never ask you to share your password.",
                     "Don't enter your card number on unknown sites."]:
            with self.subTest(text=text):
                self.assertNotIn("credential_request", self.codes(text))
        for text in ["Please do not share this; reply with your OTP to cancel.",
                     "Do not delay, enter your password now to keep your account.",
                     "Verify your account details immediately."]:
            with self.subTest(text=text):
                self.assertIn("credential_request", self.codes(text))

    def test_brand_link_mismatch(self):
        link = [{"registered_domain": "secure-login.xyz"}]
        self.assertIn("brand_link_mismatch", self.codes("Your PayPal account needs attention", link))
        self.assertNotIn("brand_link_mismatch", self.codes("Your PayPal account needs attention", [{"registered_domain": "paypal.com"}]))

    def test_secrecy_and_gift_cards(self):
        self.assertIn("secrecy_request", self.codes("I need gift cards today. Keep this confidential."))


class PathologicalInputTests(unittest.TestCase):
    """Adversarial 5,000-character inputs must stay fast (guards against regex backtracking blow-ups)."""

    def test_bounded_runtime(self):
        import time
        d = get_detector()
        inputs = ["a." * 2490, "a" * 4990, "http://" + "a" * 4980, "a" * 4990 + "@", "x." * 1200 + "com",
                  "verify " * 700, "enter your " * 450, ("a-" * 1200) + ".com", "!?.;," * 990]
        for text in inputs:
            with self.subTest(sample=text[:12], n=len(text)):
                start = time.perf_counter()
                d.analyze_message(text[: det.MAX_MESSAGE_LEN])
                self.assertLess(time.perf_counter() - start, 1.0)


class ModelBehaviourTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = get_detector()

    def test_url_probabilities(self):
        bad = self.d.analyze_url(PHISH_URL)
        good = self.d.analyze_url(BENIGN_URL)
        self.assertTrue(bad["ml_available"])
        self.assertGreater(bad["model_probability"], 0.5)
        self.assertLess(good["model_probability"], 0.5)

    def test_message_probabilities(self):
        bad = self.d.analyze_message(PHISH_MSG)
        good = self.d.analyze_message(BENIGN_MSG)
        self.assertGreater(bad["model_probability"], 0.5)
        self.assertLess(good["model_probability"], 0.5)
        self.assertEqual(len(bad["urls"]), 1)  # the embedded link was analysed locally

    def test_deterministic(self):
        self.assertEqual(self.d.analyze_message(PHISH_MSG), self.d.analyze_message(PHISH_MSG))
        self.assertEqual(self.d.analyze_url(PHISH_URL), self.d.analyze_url(PHISH_URL))

    def test_message_validation(self):
        for bad in ["", "   ", None, 5, "x" * (det.MAX_MESSAGE_LEN + 1), "hi\x00there"]:
            with self.subTest(bad=repr(bad)[:30]):
                with self.assertRaises(ValueError):
                    self.d.analyze_message(bad)

    def test_unparsable_link_fragments_are_skipped(self):
        r = self.d.analyze_message("see http://[bad and www.ok-site.com/page")
        self.assertIsInstance(r["urls"], list)

    def test_works_without_models(self):
        d = det.Detector()
        self.assertFalse(d.analyze_url(PHISH_URL)["ml_available"])
        self.assertFalse(d.analyze_message(PHISH_MSG)["ml_available"])


class ModelIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        d = get_detector()
        joblib.dump(d.message_model, self.tmp / det.MESSAGE_MODEL)
        joblib.dump(d.url_model, self.tmp / det.URL_MODEL)
        det.write_manifest(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_loads_when_manifest_matches(self):
        d = det.Detector.load(self.tmp)
        self.assertTrue(d.status["message_model"]["loaded"] and d.status["url_model"]["loaded"])

    def test_rejects_tampered_file(self):
        with open(self.tmp / det.URL_MODEL, "ab") as f:
            f.write(b"tamper")
        d = det.Detector.load(self.tmp)
        self.assertFalse(d.status["url_model"]["loaded"])
        self.assertIn("integrity", d.status["url_model"]["detail"])
        self.assertTrue(d.status["message_model"]["loaded"])  # the untouched model still loads

    def test_rejects_when_manifest_missing_or_corrupt(self):
        (self.tmp / det.MANIFEST).write_text("{not json")
        d = det.Detector.load(self.tmp)
        self.assertFalse(d.status["message_model"]["loaded"])
        (self.tmp / det.MANIFEST).unlink()
        self.assertFalse(det.Detector.load(self.tmp).status["url_model"]["loaded"])

    def test_missing_model_files(self):
        empty = Path(tempfile.mkdtemp())
        try:
            d = det.Detector.load(empty)
            self.assertFalse(d.status["message_model"]["loaded"])
            self.assertEqual(d.status["message_model"]["detail"], "model file not found")
        finally:
            shutil.rmtree(empty, ignore_errors=True)


class SeedDataTests(unittest.TestCase):
    def test_seed_files_present_and_labelled_synthetic(self):
        self.assertTrue((ROOT / "datasets" / "SYNTHETIC_DATA.txt").exists())
        header = (ROOT / "datasets" / "messages.csv").read_text().splitlines()[0]
        self.assertEqual(header, "text,label,group")


if __name__ == "__main__":
    unittest.main()
