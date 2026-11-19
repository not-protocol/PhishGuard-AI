import copy
import json
import os
import unittest
from unittest import mock

import requests

import ai_summary
import risk_engine
from tests.common import get_detector

MARKER = "UNIQUEMARKER9431"
RAW = (f"Dear customer, verify your PayPal password immediately at http://{MARKER.lower()}-login.xyz/verify "
       f"{MARKER}")


def make_report():
    return risk_engine.score_message(get_detector().analyze_message(RAW)) | {"analysis_id": "PG-000001"}


def env(**kw):
    base = {"AI_ENABLED": "true", "AI_PROVIDER": "openai", "OPENAI_API_KEY": "sk-test-SECRET",
            "OPENAI_MODEL": "test-model", "AI_TIMEOUT": "5"}
    base.update(kw)
    return mock.patch.dict(os.environ, base, clear=True)


def fake_response(payload, status=200):
    r = mock.Mock()
    r.status_code = status
    r.json.return_value = payload
    if status >= 400:
        r.raise_for_status.side_effect = requests.exceptions.HTTPError(response=r)
    else:
        r.raise_for_status.return_value = None
    return r


def openai_payload(text):
    return {"choices": [{"message": {"content": text}}]}


class FindingsPrivacyTests(unittest.TestCase):
    def test_findings_never_contain_raw_content_or_domains(self):
        report = make_report()
        blob = json.dumps(ai_summary.build_findings(report)).lower()
        self.assertNotIn(MARKER.lower(), blob)
        self.assertNotIn("xyz", blob)  # not even the TLD of the submitted link may leak
        self.assertNotIn("http", blob)
        self.assertNotIn("registered_domain", blob)

    def test_findings_have_expected_shape(self):
        f = ai_summary.build_findings(make_report())
        self.assertEqual(set(f), {"input_type", "risk_score", "risk_level", "classification", "threat_category",
                                  "model_confidence", "evidence", "score_breakdown", "links_found"})


class FallbackTests(unittest.TestCase):
    def test_disabled(self):
        with env(AI_ENABLED="false"), mock.patch("ai_summary.requests.post") as post:
            res = ai_summary.generate(make_report())
        post.assert_not_called()
        self.assertEqual(res["status"], "fallback")
        self.assertTrue(res["summary"])

    def test_missing_key_provider_or_model(self):
        for kw in ({"OPENAI_API_KEY": ""}, {"AI_PROVIDER": "bogus"}, {"OPENAI_MODEL": ""}, {"OPENAI_MODEL": "bad model/../x"}):
            with self.subTest(kw=kw), env(**kw), mock.patch("ai_summary.requests.post") as post:
                res = ai_summary.generate(make_report())
                post.assert_not_called()
                self.assertEqual(res["status"], "fallback")

    def test_no_environment_at_all(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            res = ai_summary.generate(make_report())
        self.assertEqual(res["status"], "fallback")
        self.assertIn("risk score", res["summary"])

    def test_failures_fall_back_with_reason(self):
        cases = [
            (requests.exceptions.Timeout(), "timed out"),
            (requests.exceptions.ConnectionError(), "could not be reached"),
            (fake_response({}, 500), "HTTP 500"),
            (fake_response({}, 401), "HTTP 401"),
            (fake_response({"unexpected": 1}), "rejected"),
            (fake_response(openai_payload("")), "rejected"),
        ]
        for effect, expect in cases:
            with self.subTest(expect=expect), env(), mock.patch("ai_summary.requests.post") as post:
                if isinstance(effect, Exception):
                    post.side_effect = effect
                else:
                    post.return_value = effect
                res = ai_summary.generate(make_report())
            self.assertEqual(res["status"], "fallback")
            self.assertIn(expect, res["reason"])
            self.assertTrue(res["summary"])
            self.assertNotIn("sk-test-SECRET", json.dumps(res))


class ProviderTests(unittest.TestCase):
    def test_openai_success_and_payload_privacy(self):
        report = make_report()
        with env(), mock.patch("ai_summary.requests.post") as post:
            post.return_value = fake_response(openai_payload("This message is risky. Do not click the link."))
            res = ai_summary.generate(report)
        self.assertEqual((res["status"], res["provider"]), ("generated", "openai"))
        kwargs = post.call_args.kwargs
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer sk-test-SECRET")
        sent = json.dumps(kwargs["json"]).lower()
        self.assertNotIn(MARKER.lower(), sent)
        self.assertNotIn("sk-test-secret", sent)       # key only in the header
        self.assertEqual(post.call_args.args[0], ai_summary.OPENAI_URL)
        self.assertEqual(kwargs["timeout"], 5.0)

    def test_gemini_success(self):
        payload = {"candidates": [{"content": {"parts": [{"text": "Looks risky. "}, {"text": "Avoid the link."}]}}]}
        with env(AI_PROVIDER="gemini", GEMINI_API_KEY="g-key", GEMINI_MODEL="gem-model"), \
                mock.patch("ai_summary.requests.post") as post:
            post.return_value = fake_response(payload)
            res = ai_summary.generate(make_report())
        self.assertEqual((res["status"], res["provider"]), ("generated", "gemini"))
        self.assertEqual(res["summary"], "Looks risky. Avoid the link.")
        self.assertIn("gem-model:generateContent", post.call_args.args[0])
        self.assertEqual(post.call_args.kwargs["headers"]["x-goog-api-key"], "g-key")
        self.assertNotIn("g-key", post.call_args.args[0])  # never in the URL


class OutputValidationTests(unittest.TestCase):
    def gen(self, text):
        with env(), mock.patch("ai_summary.requests.post") as post:
            post.return_value = fake_response(openai_payload(text))
            return ai_summary.generate(make_report())

    def test_contradicting_score_is_rejected(self):
        report = make_report()
        wrong = 5 if report["risk_score"] != 5 else 6
        res = self.gen(f"This is perfectly safe with a score of {wrong}/100.")
        self.assertEqual(res["status"], "fallback")
        self.assertIn("contradicts", res["reason"])

    def test_matching_score_is_accepted(self):
        res = self.gen(f"The engine scored this {make_report()['risk_score']}/100. Avoid the link.")
        self.assertEqual(res["status"], "generated")

    def test_markup_is_stripped(self):
        res = self.gen("Careful <script>alert(1)</script><b>now</b>. **Do not click**.")
        self.assertEqual(res["status"], "generated")
        self.assertNotIn("<", res["summary"])
        self.assertNotIn(">", res["summary"])
        self.assertNotIn("*", res["summary"])

    def test_length_is_capped(self):
        res = self.gen("word " * 2000)
        self.assertLessEqual(len(res["summary"]), ai_summary.MAX_SUMMARY_CHARS + 3)

    def test_claims_of_visiting_links_rejected(self):
        res = self.gen("I visited the link and it looked fine.")
        self.assertEqual(res["status"], "fallback")

    def test_report_is_never_modified(self):
        report = make_report()
        before = copy.deepcopy(report)
        with env(), mock.patch("ai_summary.requests.post") as post:
            post.return_value = fake_response(openai_payload("Score is 1/100, all fine."))
            ai_summary.generate(report)
        self.assertEqual(report, before)


class StatusTests(unittest.TestCase):
    def test_public_status_never_contains_key(self):
        with env():
            s = ai_summary.public_status()
        self.assertNotIn("sk-test-SECRET", json.dumps(s))
        self.assertTrue(s["ready"])
        with env(OPENAI_API_KEY=""):
            self.assertFalse(ai_summary.public_status()["ready"])

    def test_local_summary_for_low_and_high(self):
        d = get_detector()
        low = risk_engine.score_message(d.analyze_message("Hi Sam, lunch tomorrow at 1 PM?"))
        self.assertIn("not a guarantee", ai_summary.local_summary(low))
        self.assertIn("Credential Phishing", ai_summary.local_summary(make_report()))


if __name__ == "__main__":
    unittest.main()
