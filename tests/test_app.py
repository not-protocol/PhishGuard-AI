import json
import os
import re
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app as app_module
import detector as det
from tests.common import BENIGN_MSG, PHISH_MSG, PHISH_URL, get_detector

SECRET_MARKER = "UNIQUERAWTEXT7782"


class AppTestCase(unittest.TestCase):
    detector = None  # None -> trained test detector

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db = self.tmp / "t.db"
        d = get_detector() if self.detector is None else self.detector
        self.app = app_module.create_app(db_path=self.db, detector=d, secret_key="test-secret")
        self.client = self.app.test_client()
        page = self.client.get("/")
        self.token = re.search(r'name="csrf-token" content="([^"]+)"', page.get_data(as_text=True)).group(1)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def post(self, path, body, token=True, **kw):
        headers = {"X-CSRF-Token": self.token} if token is True else ({"X-CSRF-Token": token} if token else {})
        headers.update(kw.pop("headers", {}))
        return self.client.post(path, json=body, headers=headers, **kw)


class PageAndHeaderTests(AppTestCase):
    def test_index_renders_dashboard(self):
        r = self.client.get("/")
        html = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 200)
        for s in ("URL Scanner", "Message Scanner", "Risk Analysis", "Detection Evidence", "Analysis History", "Settings", "Overview"):
            self.assertIn(s, html)
        self.assertNotIn("<script>", html)          # no inline script
        self.assertNotIn(" style=", html)           # no inline style attributes

    def test_security_headers(self):
        r = self.client.get("/")
        csp = r.headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("http", csp.replace("http-equiv", ""))  # no third-party origins
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["Referrer-Policy"], "no-referrer")

    def test_static_assets_served(self):
        for path in ("/static/app.js", "/static/style.css"):
            with self.client.get(path) as r:
                self.assertEqual(r.status_code, 200)

    def test_health_and_unknown_routes(self):
        self.assertEqual(self.client.get("/api/health").get_json(), {"status": "ok"})
        r = self.client.get("/api/nope")
        self.assertEqual(r.status_code, 404)
        self.assertIn("error", r.get_json())
        self.assertEqual(self.client.get("/api/analyze/url").status_code, 405)


class CsrfAndRequestValidationTests(AppTestCase):
    def test_missing_or_wrong_csrf_rejected(self):
        for token in (False, "wrong-token", ""):
            with self.subTest(token=token):
                r = self.post("/api/analyze/url", {"url": PHISH_URL}, token=token)
                self.assertEqual(r.status_code, 403)

    def test_fresh_client_without_session_rejected(self):
        c = self.app.test_client()
        r = c.post("/api/analyze/url", json={"url": PHISH_URL}, headers={"X-CSRF-Token": self.token})
        self.assertEqual(r.status_code, 403)  # token belongs to another session

    def test_cross_origin_rejected(self):
        r = self.post("/api/analyze/url", {"url": PHISH_URL}, headers={"Origin": "http://evil.example"})
        self.assertEqual(r.status_code, 403)
        ok = self.post("/api/analyze/url", {"url": PHISH_URL}, headers={"Origin": "http://localhost"})
        self.assertEqual(ok.status_code, 200)

    def test_delete_requires_csrf(self):
        self.assertEqual(self.client.delete("/api/history").status_code, 403)

    def test_wrong_content_type(self):
        r = self.client.post("/api/analyze/url", data="url=http://a.com", headers={"X-CSRF-Token": self.token},
                             content_type="application/x-www-form-urlencoded")
        self.assertEqual(r.status_code, 415)

    def test_bad_json_bodies(self):
        for body in ("[]", '"str"', "123", "null"):
            with self.subTest(body=body):
                r = self.client.post("/api/analyze/url", data=body, headers={"X-CSRF-Token": self.token},
                                     content_type="application/json")
                self.assertEqual(r.status_code, 400)
        r = self.client.post("/api/analyze/url", data="{broken", headers={"X-CSRF-Token": self.token},
                             content_type="application/json")
        self.assertEqual(r.status_code, 400)

    def test_oversized_body(self):
        r = self.post("/api/analyze/message", {"message": "a" * 70000})
        self.assertEqual(r.status_code, 413)


class AnalyzeUrlTests(AppTestCase):
    def test_phishing_url(self):
        r = self.post("/api/analyze/url", {"url": PHISH_URL})
        self.assertEqual(r.status_code, 200)
        j = r.get_json()
        self.assertEqual(j["analysis_id"], "PG-000001")
        self.assertGreaterEqual(j["risk_score"], 50)
        self.assertTrue(j["evidence"] and j["recommendations"] and j["breakdown"])
        self.assertTrue(j["ml_available"])

    def test_benign_url(self):
        j = self.post("/api/analyze/url", {"url": "https://www.wikipedia.org/"}).get_json()
        self.assertLess(j["risk_score"], 25)
        self.assertEqual(j["classification"], "low_risk")

    def test_invalid_inputs(self):
        for body in ({}, {"url": ""}, {"url": "   "}, {"url": None}, {"url": 42}, {"url": ["a"]},
                     {"url": "javascript:alert(1)"}, {"url": "ftp://x.com"}, {"url": "http://" + "a" * 3000},
                     {"url": "not a url"}, {"nope": "x"}):
            with self.subTest(body=str(body)[:40]):
                r = self.post("/api/analyze/url", body)
                self.assertEqual(r.status_code, 400)
                self.assertIn("error", r.get_json())

    def test_url_is_never_fetched(self):
        """Analysing a URL must not touch the network (no SSRF / no visiting)."""
        with mock.patch("socket.socket.connect", side_effect=AssertionError("network used")), \
                mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")), \
                mock.patch("requests.sessions.Session.request", side_effect=AssertionError("requests used")):
            for u in ("http://127.0.0.1:9/admin", "http://169.254.169.254/latest/meta-data/",
                      "http://internal.corp.example/secret"):
                self.assertEqual(self.post("/api/analyze/url", {"url": u}).status_code, 200)
            self.assertEqual(self.post("/api/analyze/message", {"message": "see http://10.0.0.1/a now"}).status_code, 200)


class AnalyzeMessageTests(AppTestCase):
    def test_phishing_message(self):
        j = self.post("/api/analyze/message", {"message": PHISH_MSG}).get_json()
        self.assertGreaterEqual(j["risk_score"], 50)
        self.assertEqual(j["input_type"], "message")
        self.assertEqual(len(j["urls"]), 1)

    def test_benign_message(self):
        j = self.post("/api/analyze/message", {"message": BENIGN_MSG}).get_json()
        self.assertLess(j["risk_score"], 25)

    def test_invalid_inputs(self):
        for body in ({}, {"message": ""}, {"message": "   \n "}, {"message": 5}, {"message": None},
                     {"message": "x" * 5001}, {"message": "a\x00b"}):
            with self.subTest(body=str(body)[:40]):
                self.assertEqual(self.post("/api/analyze/message", body).status_code, 400)

    def test_unicode_and_html_safe(self):
        text = "<script>alert(1)</script> verify your account \u202e password \U0001F600 http://x.xyz/<b>"
        r = self.post("/api/analyze/message", {"message": text})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("<script>", r.get_data(as_text=True))  # raw input is never echoed back

    def test_raw_message_not_stored_or_returned(self):
        text = f"{PHISH_MSG} {SECRET_MARKER}"
        r = self.post("/api/analyze/message", {"message": text})
        self.assertNotIn(SECRET_MARKER, r.get_data(as_text=True))
        con = sqlite3.connect(self.db)
        dump = "\n".join(con.iterdump())
        con.close()
        self.assertNotIn(SECRET_MARKER, dump)
        self.assertNotIn("/verify", dump)                       # link paths / queries are not stored
        self.assertNotIn("http://", dump)                       # nor any full URL
        self.assertNotIn("unusual activity", dump)              # nor any message wording
        self.assertIn("paypal-secure-login.xyz", dump)          # documented: registered domains ARE kept
        self.assertNotIn(SECRET_MARKER, self.client.get("/api/history").get_data(as_text=True))


class HistoryTests(AppTestCase):
    def test_history_stats_and_item(self):
        self.post("/api/analyze/url", {"url": PHISH_URL})
        self.post("/api/analyze/message", {"message": BENIGN_MSG})
        hist = self.client.get("/api/history").get_json()
        self.assertEqual([h["analysis_id"] for h in hist], ["PG-000002", "PG-000001"])
        stats = self.client.get("/api/stats").get_json()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["types"], {"url": 1, "message": 1})
        self.assertEqual(sum(stats["levels"].values()), 2)
        item = self.client.get("/api/history/PG-000001").get_json()
        self.assertEqual(item["report"]["analysis_id"], "PG-000001")
        self.assertIsNone(item["ai_summary"])

    def test_item_lookup_validation(self):
        for bad in ("PG-999999", "PG-abc", "../etc/passwd", "1", "PG-" + "9" * 30):
            with self.subTest(bad=bad):
                self.assertEqual(self.client.get(f"/api/history/{bad}").status_code, 404)

    def test_sql_injection_attempts_are_inert(self):
        r = self.post("/api/analyze/url", {"url": "http://a.com/?q=1';DROP%20TABLE%20analyses;--"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.get("/api/history/PG-000001' OR '1'='1").status_code, 404)
        self.assertEqual(self.client.get("/api/stats").get_json()["total"], 1)

    def test_clear_history(self):
        self.post("/api/analyze/url", {"url": PHISH_URL})
        self.assertEqual(self.client.delete("/api/history", headers={"X-CSRF-Token": self.token}).status_code, 200)
        self.assertEqual(self.client.get("/api/history").get_json(), [])
        self.assertEqual(self.client.get("/api/stats").get_json()["total"], 0)

    def test_empty_state(self):
        s = self.client.get("/api/stats").get_json()
        self.assertEqual((s["total"], s["avg_score"]), (0, None))


class SummaryEndpointTests(AppTestCase):
    def analyze(self):
        return self.post("/api/analyze/message", {"message": PHISH_MSG}).get_json()["analysis_id"]

    def test_works_without_any_ai_configuration(self):
        aid = self.analyze()
        with mock.patch.dict(os.environ, {}, clear=True):
            r = self.post("/api/summary", {"analysis_id": aid})
        self.assertEqual(r.status_code, 200)
        j = r.get_json()
        self.assertEqual(j["status"], "fallback")
        self.assertTrue(j["summary"])
        item = self.client.get(f"/api/history/{aid}").get_json()
        self.assertEqual(item["ai_summary"]["status"], "fallback")

    def test_provider_failure_does_not_break_report(self):
        aid = self.analyze()
        env = {"AI_ENABLED": "true", "AI_PROVIDER": "gemini", "GEMINI_API_KEY": "k", "GEMINI_MODEL": "m"}
        import requests
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch("ai_summary.requests.post", side_effect=requests.exceptions.ConnectionError()):
            j = self.post("/api/summary", {"analysis_id": aid}).get_json()
        self.assertEqual(j["status"], "fallback")
        before = self.client.get(f"/api/history/{aid}").get_json()["report"]["risk_score"]
        self.assertEqual(before, self.client.get("/api/history").get_json()[0]["risk_score"])

    def test_client_cannot_inject_findings(self):
        aid = self.analyze()
        env = {"AI_ENABLED": "true", "AI_PROVIDER": "openai", "OPENAI_API_KEY": "k", "OPENAI_MODEL": "m"}
        good = mock.Mock(status_code=200)
        good.raise_for_status.return_value = None
        good.json.return_value = {"choices": [{"message": {"content": "Explanation. Avoid the link."}}]}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch("ai_summary.requests.post", return_value=good) as post:
            self.post("/api/summary", {"analysis_id": aid, "findings": {"risk_score": 1}, "message": SECRET_MARKER})
        sent = json.dumps(post.call_args.kwargs["json"])
        self.assertNotIn(SECRET_MARKER, sent)
        self.assertNotIn('"risk_score":1,', sent)

    def test_validation(self):
        self.assertEqual(self.post("/api/summary", {}).status_code, 400)
        self.assertEqual(self.post("/api/summary", {"analysis_id": "bogus"}).status_code, 400)
        self.assertEqual(self.post("/api/summary", {"analysis_id": "PG-424242"}).status_code, 404)
        self.assertEqual(self.post("/api/summary", {"analysis_id": "PG-000001"}, token=False).status_code, 403)

    def test_rate_limit(self):
        aid = self.analyze()
        codes = [self.post("/api/summary", {"analysis_id": aid}).status_code for _ in range(12)]
        self.assertEqual(codes[:10], [200] * 10)
        self.assertEqual(codes[10:], [429, 429])


class SettingsAndOfflineTests(AppTestCase):
    def test_settings_never_expose_keys(self):
        env = {"AI_ENABLED": "true", "AI_PROVIDER": "openai", "OPENAI_API_KEY": "sk-LEAK-CHECK", "OPENAI_MODEL": "m"}
        with mock.patch.dict(os.environ, env, clear=True):
            body = self.client.get("/api/settings").get_data(as_text=True)
        self.assertNotIn("sk-LEAK-CHECK", body)
        self.assertTrue(json.loads(body)["ai"]["ready"])
        self.assertNotIn("sk-LEAK-CHECK", self.client.get("/").get_data(as_text=True))

    def test_models_status(self):
        j = self.client.get("/api/models/status").get_json()
        self.assertTrue(j["models"]["message_model"]["loaded"])


class NoModelsTests(AppTestCase):
    detector = det.Detector()  # simulates missing / rejected model files

    def test_app_still_analyses_without_models(self):
        r = self.post("/api/analyze/url", {"url": "http://203.0.113.5/paypal/login.php"})
        self.assertEqual(r.status_code, 200)
        j = r.get_json()
        self.assertFalse(j["ml_available"])
        self.assertGreater(j["risk_score"], 0)
        self.assertEqual(len(j["warnings"]), 1)  # the user is told the score is rules-only
        self.assertEqual(self.post("/api/analyze/message", {"message": PHISH_MSG}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
