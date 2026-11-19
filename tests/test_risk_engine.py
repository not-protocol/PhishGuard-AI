import copy
import unittest

import risk_engine as re_
from tests.common import BENIGN_MSG, BENIGN_URL, PHISH_MSG, PHISH_URL, get_detector


def url_analysis(prob, codes=()):
    ev = [{"code": c, "label": c, "severity": "high"} for c in codes]
    return {"registered_domain": "x.example", "host": "x.example", "features": {}, "model_probability": prob,
            "ml_available": prob is not None, "indicators": ev}


class LevelTests(unittest.TestCase):
    def test_level_boundaries(self):
        cases = {0: "low", 24: "low", 25: "medium", 49: "medium", 50: "high", 74: "high", 75: "critical", 100: "critical"}
        for score, level in cases.items():
            with self.subTest(score=score):
                self.assertEqual(re_.risk_level(score), level)

    def test_classification_boundaries(self):
        self.assertEqual(re_.classification(24), "low_risk")
        self.assertEqual(re_.classification(25), "suspicious")
        self.assertEqual(re_.classification(50), "phishing")


class UrlScoringTests(unittest.TestCase):
    def test_score_bounds_and_breakdown_sum(self):
        for p in (0.0, 0.3, 0.77, 1.0, None):
            for codes in ((), ("ip_host",), tuple(re_.URL_EVIDENCE_POINTS)):
                r = re_.score_url(url_analysis(p, codes))
                with self.subTest(p=p, n=len(codes)):
                    self.assertTrue(0 <= r["risk_score"] <= 100)
                    self.assertEqual(r["risk_score"], sum(b["points"] for b in r["breakdown"]))

    def test_evidence_cap(self):
        r = re_.score_url(url_analysis(0.0, tuple(re_.URL_EVIDENCE_POINTS)))
        self.assertLessEqual(r["breakdown"][1]["points"], re_.URL_EVIDENCE_CAP)
        self.assertLessEqual(sum(e["points"] for e in r["evidence"]), re_.URL_EVIDENCE_CAP + 2)  # rounding slack

    def test_no_model_means_no_ml_points(self):
        r = re_.score_url(url_analysis(None, ("ip_host",)))
        self.assertEqual(r["breakdown"][0]["points"], 0)
        self.assertFalse(r["ml_available"])
        self.assertIsNone(r["model_probability"])
        self.assertIsNone(r["model_confidence"])

    def test_probability_and_score_are_distinct_quantities(self):
        r = re_.score_url(url_analysis(0.9))
        self.assertEqual(r["model_probability"], 0.9)
        self.assertEqual(r["model_confidence"], 0.9)
        self.assertEqual(r["risk_score"], 54)  # 60 * 0.9, not 90
        self.assertEqual(re_.score_url(url_analysis(0.1))["model_confidence"], 0.9)

    def test_is_pure_function(self):
        a = url_analysis(0.62, ("typosquat", "no_https"))
        before = copy.deepcopy(a)
        self.assertEqual(re_.score_url(a), re_.score_url(a))
        self.assertEqual(a, before)


class MessageScoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = get_detector()

    def test_phishing_vs_benign(self):
        bad = re_.score_message(self.d.analyze_message(PHISH_MSG))
        good = re_.score_message(self.d.analyze_message(BENIGN_MSG))
        self.assertGreaterEqual(bad["risk_score"], 50)
        self.assertIn(bad["risk_level"], ("high", "critical"))
        self.assertEqual(bad["threat_category"], "Credential Phishing")
        self.assertLess(good["risk_score"], 25)
        self.assertEqual(good["threat_category"], "No Strong Indicators")

    def test_url_phishing_vs_benign(self):
        bad = re_.score_url(self.d.analyze_url(PHISH_URL))
        good = re_.score_url(self.d.analyze_url(BENIGN_URL))
        self.assertGreaterEqual(bad["risk_score"], 50)
        self.assertLess(good["risk_score"], 25)

    def test_breakdown_sums_to_score(self):
        r = re_.score_message(self.d.analyze_message(PHISH_MSG))
        self.assertEqual(r["risk_score"], min(100, sum(b["points"] for b in r["breakdown"])))

    def test_link_evidence_is_surfaced(self):
        r = re_.score_message(self.d.analyze_message(PHISH_MSG))
        self.assertTrue(any(e["label"].startswith("[") for e in r["evidence"]))
        self.assertEqual(len(r["urls"]), 1)

    def test_reproducible(self):
        a = re_.score_message(self.d.analyze_message(PHISH_MSG))
        b = re_.score_message(self.d.analyze_message(PHISH_MSG))
        self.assertEqual(a, b)

    def test_works_without_models(self):
        from detector import Detector
        r = re_.score_message(Detector().analyze_message(PHISH_MSG))
        self.assertFalse(r["ml_available"])
        self.assertGreater(r["risk_score"], 0)  # rule evidence still produces a score

    def test_warning_only_when_a_model_is_missing(self):
        from detector import Detector
        full = re_.score_message(self.d.analyze_message(PHISH_MSG))
        self.assertEqual(full["warnings"], [])
        self.assertEqual(re_.score_url(self.d.analyze_url(PHISH_URL))["warnings"], [])
        blind = Detector()
        self.assertEqual(re_.score_message(blind.analyze_message(PHISH_MSG))["warnings"], [re_.NO_MODEL_WARNING])
        self.assertEqual(re_.score_url(blind.analyze_url(PHISH_URL))["warnings"], [re_.NO_MODEL_WARNING])
        half = Detector(message_model=self.d.message_model)  # URL model missing -> embedded links are rules-only
        self.assertEqual(re_.score_message(half.analyze_message(PHISH_MSG))["warnings"], [re_.NO_MODEL_WARNING])

    def test_every_category_has_recommendations(self):
        for cat, recs in re_.RECOMMENDATIONS.items():
            self.assertTrue(recs, cat)

    def test_engine_is_independent_of_ai_layer(self):
        with open(re_.__file__, encoding="utf-8") as f:
            imports = [ln for ln in f.read().splitlines() if ln.startswith(("import ", "from "))]
        self.assertEqual(imports, [])  # the engine imports nothing: no AI layer, no network library


if __name__ == "__main__":
    unittest.main()
