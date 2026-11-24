"""Storage, account parsing, reporting, redaction and the CLI surface.

The scan pipeline itself is exercised against a real local git repository, so
no network and no GitHub token are needed.
"""

import datetime as _dt
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from gitanalyzer.cli import build_parser
from gitanalyzer.config import ScanConfig
from gitanalyzer.github import parse_account, read_account_list
from gitanalyzer.report import build_page, markdown_report
from gitanalyzer.store import ScanStore, new_scan_id
from gitanalyzer.triage import mask, redact


class TestParseAccount(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(parse_account("octocat"), "octocat")
        self.assertEqual(parse_account("https://github.com/octocat"), "octocat")
        self.assertEqual(parse_account("github.com/octocat/repo"), "octocat")
        self.assertEqual(parse_account("https://github.com/octocat?tab=repositories"), "octocat")
        self.assertEqual(parse_account("  octocat  "), "octocat")

    def test_blanks_and_comments(self):
        self.assertIsNone(parse_account(""))
        self.assertIsNone(parse_account("   "))
        self.assertIsNone(parse_account("# a comment"))

    def test_file_is_deduplicated_in_order(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
        handle.write("# list\nbeta\nalpha\nbeta\nhttps://github.com/alpha\n\n")
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        self.assertEqual(read_account_list(handle.name), ["beta", "alpha"])


class TestStore(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gitanalyzer_test_")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.store = ScanStore(self.dir)

    def test_round_trip(self):
        scan = {"id": "abc", "status": "completed", "findings": [], "config": {"accounts": ["x"]}}
        self.store.save(scan)
        self.assertEqual(self.store.load("abc")["status"], "completed")

    def test_unknown_scan_is_none(self):
        self.assertIsNone(self.store.load("does-not-exist"))

    def test_path_traversal_is_stripped(self):
        path = self.store.path_for("../../etc/passwd")
        self.assertTrue(os.path.dirname(path) == self.store.dir)
        self.assertNotIn("..", os.path.basename(path))

    def test_corrupt_file_is_skipped_not_raised(self):
        with open(os.path.join(self.dir, "scan-broken.json"), "w", encoding="utf-8") as handle:
            handle.write("{ not json")
        self.assertEqual(self.store.list_scans(), [])
        self.assertIsNone(self.store.load("broken"))

    def test_listing_is_newest_first(self):
        for index, started in enumerate(["2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"]):
            self.store.save({"id": "s%d" % index, "status": "completed", "started_at": started})
        self.assertEqual([s["id"] for s in self.store.list_scans()], ["s1", "s0"])

    def test_cooldown_history(self):
        self.assertIsNone(self.store.days_since_scan("nobody"))
        self.store.record_account("Octocat", 3, 7)
        age = self.store.days_since_scan("octocat")  # case-insensitive
        self.assertIsNotNone(age)
        self.assertLess(age, 1)

    def test_scan_ids_are_unique(self):
        self.assertNotEqual(new_scan_id(), new_scan_id())


class TestRedaction(unittest.TestCase):
    def test_mask_keeps_shape_not_value(self):
        self.assertEqual(mask("short"), "*****")
        masked = mask("f3a9c2b8e1d47650aa93")
        self.assertTrue(masked.startswith("f3a"))
        self.assertTrue(masked.endswith("a93"))
        self.assertNotIn("c2b8e1d476", masked)

    def test_secret_value_does_not_survive_redaction(self):
        line = 'api_key = "f3a9c2b8e1d47650aa93"'
        self.assertNotIn("f3a9c2b8e1d47650aa93", redact(line))

    def test_url_password_is_masked(self):
        line = "postgresql://admin:Sup3rS3cretValue@db.internal.acme.com:5432/prod"
        out = redact(line)
        self.assertNotIn("Sup3rS3cretValue", out)
        self.assertIn("db.internal.acme.com", out)  # context survives


SCAN = {
    "id": "test", "label": "unit", "status": "completed",
    "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:10:00Z",
    "config": {"accounts": ["example"], "keywords": ["acme"]},
    "stats": {"accounts_scanned": 1, "repos_scanned": 1, "total_findings": 2},
    "skipped_accounts": [], "log": [],
    "findings": [
        {
            "account": "example", "repo": "example/repo",
            "repo_url": "https://github.com/example/repo",
            "file": "config.yml", "line": 3, "pattern": 'api_key: "x"',
            "preview": 'api_key: "x"', "score": 70, "severity": "high",
            "scanner": "ripgrep", "verified": False, "detector": "",
            "finding_type": "hardcoded_secret", "category": "secret",
            "company_match": True, "matched_keywords": ["acme"],
        },
        {
            "account": "example", "repo": "example/repo",
            "repo_url": "https://github.com/example/repo",
            "file": "README.md", "line": 1, "pattern": "https://example.com",
            "preview": "https://example.com", "score": 20, "severity": "low",
            "scanner": "ripgrep", "verified": False, "detector": "",
            "finding_type": "url", "category": "all_url",
            "company_match": False, "matched_keywords": [],
        },
    ],
}


class TestReport(unittest.TestCase):
    def test_html_is_self_contained(self):
        page = build_page(SCAN)
        self.assertNotIn("/*__EMBEDDED_SCAN__*/", page)
        self.assertNotIn("/*__STYLE__*/", page)
        self.assertNotIn("/*__APP__*/", page)
        self.assertIn("example/repo", page)
        self.assertNotIn("<script src=", page)

    def test_live_page_has_no_data_embedded(self):
        page = build_page(None)
        self.assertIn("window.__SCAN__ = null", page.replace("/*__EMBEDDED_SCAN__*/ ", ""))

    def test_embedded_json_cannot_break_out_of_the_script_tag(self):
        scan = json.loads(json.dumps(SCAN))
        scan["findings"][0]["preview"] = "</script><img src=x onerror=alert(1)>"
        page = build_page(scan)
        self.assertNotIn("</script><img", page)

    def test_markdown_hides_plain_urls_and_keeps_findings(self):
        text = markdown_report(SCAN)
        self.assertIn("config.yml", text)
        self.assertIn("example/repo", text)
        self.assertNotIn("README.md", text)

    def test_markdown_survives_incomplete_findings(self):
        markdown_report({"findings": [{"account": "a", "repo": "r"}], "stats": {}, "config": {}})


class TestCli(unittest.TestCase):
    def test_results_flag_before_or_after_the_subcommand(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["--results", "X", "doctor"]).results, "X")
        self.assertEqual(parser.parse_args(["doctor", "--results", "X"]).results, "X")
        self.assertEqual(parser.parse_args(["doctor"]).results, "results")

    def test_scan_defaults(self):
        args = build_parser().parse_args(["scan", "octocat"])
        self.assertEqual(args.accounts, ["octocat"])
        self.assertEqual(args.max_age, 24)
        self.assertEqual(args.cap, 200)
        self.assertFalse(args.ai_triage)

    def test_config_round_trip_ignores_unknown_keys(self):
        config = ScanConfig.from_dict({"accounts": ["a"], "not_a_field": 1})
        self.assertEqual(config.accounts, ["a"])
        self.assertIn("max_repo_age_months", config.to_dict())


@unittest.skipUnless(
    shutil.which("git") and shutil.which("rg"), "git and ripgrep are required"
)
class TestScanPipeline(unittest.TestCase):
    """Clone -> scan -> score -> cap, against a local repository."""

    @classmethod
    def setUpClass(cls):
        cls.repo = tempfile.mkdtemp(prefix="gitanalyzer_repo_")
        run = lambda *args: subprocess.run(args, cwd=cls.repo, check=True, capture_output=True)
        run("git", "init", "-q", ".")
        run("git", "config", "user.email", "test@example.invalid")
        run("git", "config", "user.name", "test")
        with open(os.path.join(cls.repo, "notes.md"), "w", encoding="utf-8") as handle:
            handle.write("Runbook: https://acme.atlassian.net/browse/SEC-1\n")
        with open(os.path.join(cls.repo, ".env"), "w", encoding="utf-8") as handle:
            handle.write("INTERNAL_API_TOKEN=f3a9c2b8e1d47650aa93\n")
        run("git", "add", "-A")
        run("git", "commit", "-qm", "init")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.repo, ignore_errors=True)

    def test_scan_repo_finds_and_annotates(self):
        from gitanalyzer.scanner import DeepScanner

        results = tempfile.mkdtemp(prefix="gitanalyzer_out_")
        self.addCleanup(shutil.rmtree, results, True)
        config = ScanConfig(
            accounts=["local"], keywords=["acme"], use_trufflehog=False,
            delay_between_repos=0, delay_between_accounts=0,
        )
        scanner = DeepScanner(config, ScanStore(results), log=lambda _m: None)
        findings = scanner.scan_repo(
            "local",
            {
                "full_name": "local/repo",
                "html_url": "https://github.com/local/repo",
                "clone_url": "file://" + self.repo,
            },
        )
        self.assertTrue(findings)
        for finding in findings:
            self.assertEqual(finding["account"], "local")
            self.assertEqual(finding["repo"], "local/repo")
            self.assertIn("category", finding)
            self.assertFalse(os.path.isabs(finding["file"]), finding["file"])

        previews = " ".join(f["preview"] for f in findings)
        self.assertIn("INTERNAL_API_TOKEN", previews)
        self.assertIn("atlassian.net", previews)
        self.assertTrue(any(f["company_match"] for f in findings))

    def test_clone_failure_is_reported_not_raised(self):
        from gitanalyzer.scanner import DeepScanner

        results = tempfile.mkdtemp(prefix="gitanalyzer_out_")
        self.addCleanup(shutil.rmtree, results, True)
        scanner = DeepScanner(ScanConfig(accounts=["x"]), ScanStore(results), log=lambda _m: None)
        findings = scanner.scan_repo(
            "x", {"full_name": "x/nope", "clone_url": "file:///nonexistent/repo.git"}
        )
        self.assertEqual(findings, [])
        self.assertEqual(scanner.stats["clone_failures"], 1)

    def test_wordlist_override_changes_what_is_searched(self):
        """An edited pattern list is what the scan actually runs."""
        from gitanalyzer.scanner import DeepScanner

        results = tempfile.mkdtemp(prefix="gitanalyzer_out_")
        self.addCleanup(shutil.rmtree, results, True)
        config = ScanConfig(
            accounts=["local"], use_trufflehog=False,
            delay_between_repos=0, delay_between_accounts=0,
            # Only the Atlassian runbook link, nothing else in the repository.
            wordlists={"rg_patterns": [r"atlassian\.net/browse/[A-Z]+-[0-9]+"]},
        )
        scanner = DeepScanner(config, ScanStore(results), log=lambda _m: None)
        findings = scanner.scan_repo(
            "local", {"full_name": "local/repo", "clone_url": "file://" + self.repo}
        )
        self.assertEqual(len(findings), 1, [f["preview"] for f in findings])
        self.assertIn("atlassian.net", findings[0]["preview"])

    def test_a_pattern_ripgrep_rejects_is_reported_not_silent(self):
        """A scan that searched for nothing must not look like a clean repo."""
        from gitanalyzer.scanners import run_ripgrep

        findings, error = run_ripgrep(
            self.repo, [], set(), 60,
            __import__("gitanalyzer.patterns", fromlist=["Wordlists"])
            .Wordlists.resolve({"rg_patterns": ["(unclosed"]}),
        )
        self.assertEqual(findings, [])
        self.assertIn("ripgrep failed", error)

    def test_clone_leaves_nothing_behind(self):
        """Cloned code must be deleted once scanned — only JSON stays."""
        from gitanalyzer.scanner import DeepScanner

        results = tempfile.mkdtemp(prefix="gitanalyzer_out_")
        self.addCleanup(shutil.rmtree, results, True)
        before = set(os.listdir(tempfile.gettempdir()))
        config = ScanConfig(accounts=["local"], use_trufflehog=False)
        scanner = DeepScanner(config, ScanStore(results), log=lambda _m: None)
        scanner.scan_repo("local", {"full_name": "local/repo", "clone_url": "file://" + self.repo})
        leaked = [
            name for name in set(os.listdir(tempfile.gettempdir())) - before
            if name.startswith("gitanalyzer_") and not name.startswith("gitanalyzer_out_")
        ]
        self.assertEqual(leaked, [])


if __name__ == "__main__":
    unittest.main()


class TestRepoEligibility(unittest.TestCase):
    """Which repositories a scan agrees to clone.

    The age filter is the one that silently empties a scan: every repository
    of a dormant account is "stale", and the run then looks like a clean
    result instead of a run that never happened.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gitanalyzer_elig_")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def scanner(self, **kwargs):
        from gitanalyzer.scanner import DeepScanner
        from gitanalyzer.store import ScanStore
        config = ScanConfig(accounts=["octocat"], **kwargs)
        return DeepScanner(config, store=ScanStore(self.dir), log=lambda *_: None)

    @staticmethod
    def repo(name, pushed, fork=False, archived=False, size=10):
        return {"name": name, "full_name": "octocat/" + name, "pushed_at": pushed,
                "fork": fork, "archived": archived, "size": size}

    def test_a_repo_pushed_long_ago_is_stale(self):
        repos = [self.repo("old", "2020-01-01T00:00:00Z"),
                 self.repo("fresh", _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))]
        eligible, reasons = self.scanner(max_repo_age_months=24)._eligible(repos)
        self.assertEqual([r["name"] for r in eligible], ["fresh"])
        self.assertEqual(reasons["stale"], 1)

    def test_zero_months_means_no_age_limit_not_no_repos(self):
        """0 must read as "any age" — a cutoff of now would filter everything."""
        repos = [self.repo("ancient", "2009-01-01T00:00:00Z"),
                 self.repo("old", "2020-01-01T00:00:00Z")]
        eligible, reasons = self.scanner(max_repo_age_months=0)._eligible(repos)
        self.assertEqual(len(eligible), 2)
        self.assertEqual(reasons["stale"], 0)

    def test_forks_and_archives_are_counted_separately(self):
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        repos = [self.repo("a-fork", now, fork=True),
                 self.repo("an-archive", now, archived=True),
                 self.repo("huge", now, size=900 * 1024),
                 self.repo("keep", now)]
        eligible, reasons = self.scanner(max_repo_age_months=24, max_repo_size_mb=500)._eligible(repos)
        self.assertEqual([r["name"] for r in eligible], ["keep"])
        self.assertEqual(reasons, {"fork": 1, "archived": 1, "stale": 0, "oversized": 1})

    def test_zero_size_means_no_size_limit(self):
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        repos = [self.repo("enormous", now, size=50 * 1024 * 1024)]
        eligible, reasons = self.scanner(max_repo_size_mb=0)._eligible(repos)
        self.assertEqual(len(eligible), 1)
        self.assertEqual(reasons["oversized"], 0)

    def test_the_shipped_dashboard_defaults_filter_nothing(self):
        """Settings ship at 0, so a dashboard scan must reach every repo."""
        from gitanalyzer import settings as st
        config = ScanConfig(accounts=["octocat"], **st.scan_defaults(dict(st.DEFAULTS)))
        self.assertEqual(
            (config.max_repo_age_months, config.max_repo_size_mb,
             config.rescan_days, config.max_findings_per_repo),
            (0, 0, 0, 0))
        repos = [self.repo("ancient", "2009-01-01T00:00:00Z", size=50 * 1024 * 1024)]
        from gitanalyzer.scanner import DeepScanner
        scanner = DeepScanner(config, store=ScanStore(self.dir), log=lambda *_: None)
        eligible, reasons = scanner._eligible(repos)
        self.assertEqual(len(eligible), 1)
        self.assertEqual(sum(reasons.values()), 0)

    def test_a_repo_with_no_pushed_at_is_kept(self):
        eligible, _ = self.scanner(max_repo_age_months=24)._eligible([self.repo("unknown", "")])
        self.assertEqual(len(eligible), 1)
