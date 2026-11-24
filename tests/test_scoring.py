"""Scoring, classification and the per-repo cap."""

import unittest

from gitanalyzer.scoring import (
    apply_repo_cap,
    categorize,
    classify_finding_type,
    classify_severity,
    score_finding,
    sort_findings,
)


class TestScore(unittest.TestCase):
    def test_verified_credential_outranks_everything(self):
        score = score_finding("AKIA...", "config.py", "key", "trufflehog", verified=True)
        self.assertGreaterEqual(score, 95)

    def test_test_paths_are_penalised(self):
        real = score_finding("secret", "src/config.yml", "api_key: x", "ripgrep")
        test = score_finding("secret", "tests/fixtures/config.yml", "api_key: x", "ripgrep")
        self.assertLess(test, real)

    def test_low_value_detector_is_demoted(self):
        normal = score_finding("x", "a.py", "x", "trufflehog", detector="Stripe")
        noisy = score_finding("x", "a.py", "x", "trufflehog", detector="PubNubPublishKey")
        self.assertLess(noisy, normal)

    def test_private_key_in_test_data_is_not_promoted(self):
        real = score_finding("k", "deploy/id_rsa", "-----BEGIN PRIVATE KEY-----", "ripgrep")
        fake = score_finding("k", "testdata/id_rsa", "-----BEGIN PRIVATE KEY-----", "ripgrep")
        self.assertLess(fake, real)

    def test_internal_hostname_is_promoted(self):
        plain = score_finding("u", "a.py", "https://example.com/x", "ripgrep")
        internal = score_finding("u", "a.py", "https://api.internal.acme.com/x", "ripgrep")
        self.assertGreater(internal, plain)

    def test_score_stays_in_range(self):
        for args in (
            ("x", "tests/example/sample/mock.py", "user:password@example.com", "ripgrep"),
            ("x", ".env", "PRIVATE KEY AKIA", "trufflehog", True, "aws"),
        ):
            score = score_finding(*args)
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)


class TestClassify(unittest.TestCase):
    def test_severity_bands(self):
        self.assertEqual(classify_severity(95), "critical")
        self.assertEqual(classify_severity(70), "high")
        self.assertEqual(classify_severity(45), "medium")
        self.assertEqual(classify_severity(25), "low")

    def test_informative_is_not_low(self):
        """"Low" means reportable-but-minor. The bottom band is for things
        that are not a vulnerability at all, and must not be confused."""
        self.assertEqual(classify_severity(10), "informative")
        self.assertEqual(classify_severity(0), "informative")
        self.assertEqual(classify_severity(19), "informative")
        self.assertEqual(classify_severity(20), "low")

    def test_detector_wins_over_text(self):
        self.assertEqual(classify_finding_type("whatever", "AWS"), "aws_key")
        self.assertEqual(classify_finding_type("whatever", "StripeKey"), "payment_key")

    def test_text_classification(self):
        self.assertEqual(classify_finding_type("https://acme.okta.com"), "okta")
        self.assertEqual(classify_finding_type("https://docs.google.com/document/d/x"), "google_docs")
        self.assertEqual(classify_finding_type("postgresql://u:p@h/db"), "db_credential")
        self.assertEqual(classify_finding_type("api_key = 'x'"), "hardcoded_secret")
        self.assertEqual(classify_finding_type("nothing here"), "other")


class TestCategorize(unittest.TestCase):
    def test_keyword_match_is_recorded(self):
        finding = {"finding_type": "url", "preview": "https://acme.okta.com", "pattern": "", "scanner": "ripgrep"}
        categorize(finding, ["acme"])
        self.assertTrue(finding["company_match"])
        self.assertEqual(finding["matched_keywords"], ["acme"])

    def test_secret_category_beats_keyword(self):
        finding = {"finding_type": "aws_key", "preview": "acme AKIA", "pattern": "", "scanner": "trufflehog"}
        categorize(finding, ["acme"])
        self.assertEqual(finding["category"], "secret")

    def test_plain_url_is_separated(self):
        finding = {"finding_type": "url", "preview": "https://example.com", "pattern": "", "scanner": "ripgrep"}
        categorize(finding, [])
        self.assertEqual(finding["category"], "all_url")


class TestCap(unittest.TestCase):
    def _findings(self, category, count, score=10):
        return [{"category": category, "score": score} for _ in range(count)]

    def test_cap_drops_only_noise(self):
        findings = self._findings("secret", 5) + self._findings("all_url", 500)
        capped, dropped = apply_repo_cap(findings, 50)
        self.assertEqual(len(capped), 50)
        self.assertEqual(dropped, 455)
        self.assertEqual(sum(1 for f in capped if f["category"] == "secret"), 5)

    def test_secrets_are_never_dropped_even_past_the_cap(self):
        findings = self._findings("secret", 300)
        capped, dropped = apply_repo_cap(findings, 50)
        self.assertEqual(len(capped), 300)
        self.assertEqual(dropped, 0)

    def test_keyword_matches_are_never_dropped(self):
        findings = self._findings("company_match", 80) + self._findings("all_url", 80)
        capped, _ = apply_repo_cap(findings, 20)
        self.assertEqual(sum(1 for f in capped if f["category"] == "company_match"), 80)

    def test_zero_means_unlimited(self):
        findings = self._findings("all_url", 1000)
        capped, dropped = apply_repo_cap(findings, 0)
        self.assertEqual(len(capped), 1000)
        self.assertEqual(dropped, 0)

    def test_highest_scoring_noise_survives(self):
        findings = self._findings("all_url", 10, score=5) + [{"category": "all_url", "score": 99}]
        capped, _ = apply_repo_cap(findings, 1)
        self.assertEqual(capped[0]["score"], 99)


class TestSort(unittest.TestCase):
    def test_secrets_first_then_score(self):
        findings = [
            {"category": "all_url", "score": 99},
            {"category": "secret", "score": 10},
            {"category": "secret", "score": 90},
            {"category": "company_match", "score": 50},
        ]
        order = [(f["category"], f["score"]) for f in sort_findings(findings)]
        self.assertEqual(
            order,
            [("secret", 90), ("secret", 10), ("company_match", 50), ("all_url", 99)],
        )


if __name__ == "__main__":
    unittest.main()
