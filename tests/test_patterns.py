"""Pattern and false-positive heuristics.

These are the rules that decide what a scan reports, so they are the part of
the project most worth pinning down: a regression here is silent.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

from gitanalyzer.patterns import (
    EXCLUDE_GLOBS,
    INCLUDE_GLOBS,
    build_ripgrep_pattern,
    is_placeholder,
)


class TestIsPlaceholder(unittest.TestCase):
    def test_drops_template_text(self):
        for value in (
            "changeme",
            "your_api_key",
            "<your-token-here>",
            "${DATABASE_PASSWORD}",
            "{{ secret }}",
            # Shaped like a Stripe test key, deliberately not one: the prefix is
            # what `is_placeholder` matches on, and a fixture with 24 alphanumeric
            # characters after `sk_test_` is blocked by GitHub push protection.
            "sk_test_this-is-not-a-key",
            "xxxxxxxxxxxx",
            "aaaaaaaaaaaa",
            "0123456789",
            "short",
        ):
            self.assertTrue(is_placeholder(value), value)

    def test_drops_references_to_a_secret(self):
        """`API_KEY=os.environ["X"]` is code, not a leaked value."""
        for value in (
            'API_KEY=os.environ["TOKEN"]',
            "api_key = os.getenv(TOKEN)",
            "SECRET=process.env.SECRET",
        ):
            self.assertTrue(is_placeholder(value), value)

    def test_keeps_real_looking_values(self):
        for value in (
            "f3a9c2b8e1d47650aa93",
            "Hunter2Hunter2",
            "postgresql://admin:Sup3rS3cret@db.internal.acme.com:5432/prod",
            "https://acme.okta.com",
            "AKIAIOSFODNN7EXAMPLE",
        ):
            self.assertFalse(is_placeholder(value), value)

    def test_substring_filler_does_not_drop_a_real_match(self):
        """Regression: 'abcdef' anywhere used to discard the whole match.

        Google Docs and Drive ids are random, so a run of letters inside one is
        expected and must not be read as filler.
        """
        url = "https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/edit"
        self.assertFalse(is_placeholder(url))


class TestRipgrepPattern(unittest.TestCase):
    def test_pattern_compiles(self):
        # Rust and Python regex differ, but a syntax error shows up in both.
        re.compile(build_ripgrep_pattern([]).replace("(?i)", ""))

    def test_custom_patterns_are_appended(self):
        pattern = build_ripgrep_pattern(["acme-internal-project"])
        self.assertIn("acme-internal-project", pattern)


@unittest.skipUnless(shutil.which("rg"), "ripgrep not installed")
class TestAgainstRipgrep(unittest.TestCase):
    """End-to-end through the real binary: a regex that works in Python but
    not in Rust is worthless here."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gitanalyzer_test_")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, name, body):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)
        return path

    def matches(self):
        from gitanalyzer.scanners import run_ripgrep

        findings, error = run_ripgrep(self.dir, [], set(), 60)
        self.assertEqual(error, "")
        return [f["preview"] for f in findings]

    def test_unquoted_dotenv_secret_is_found(self):
        """Regression: `.env` files are the headline case and used to score zero,
        because the pattern required the value to be quoted."""
        self.write(".env", "INTERNAL_API_TOKEN=f3a9c2b8e1d47650aa93\n")
        self.assertTrue(any("INTERNAL_API_TOKEN" in m for m in self.matches()))

    def test_quoted_secret_is_found(self):
        self.write("config.yml", 'api_key: "f3a9c2b8e1d47650"\n')
        self.assertTrue(any("api_key" in m for m in self.matches()))

    def test_infrastructure_urls_are_found(self):
        self.write(
            "notes.md",
            "Jira: https://acme.atlassian.net/browse/SEC-1\n"
            "SSO: https://acme.okta.com\n"
            "Doc: https://docs.google.com/document/d/1QwErTyUiOpAsDfGhJkLzXcVbNm/edit\n",
        )
        found = " ".join(self.matches())
        self.assertIn("atlassian.net", found)
        self.assertIn("okta.com", found)
        self.assertIn("docs.google.com", found)

    def test_lowercase_env_assignment_is_not_reported(self):
        """`timeout_key = value` in source code is not a secret. The dotenv
        shape is upper-case on purpose."""
        self.write("app.py", "retry_pass = compute_something\n")
        self.assertEqual([m for m in self.matches() if "retry_pass" in m], [])


class TestGlobs(unittest.TestCase):
    def test_no_glob_is_empty_or_whitespace(self):
        for glob in INCLUDE_GLOBS + EXCLUDE_GLOBS:
            self.assertTrue(glob.strip(), repr(glob))

    def test_credential_stores_are_included(self):
        for name in ("rclone.conf", ".npmrc", ".netrc"):
            self.assertIn(name, INCLUDE_GLOBS)


if __name__ == "__main__":
    unittest.main()
