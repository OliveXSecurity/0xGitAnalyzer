"""The deep scan: resolve accounts, clone every eligible repo, scan, score.

Pipeline, per account:

    GitHub API -> repo list
      -> filter (fork / archived / age / size)
      -> git clone into a temp dir
      -> TruffleHog over full git history   (credentials)
      -> ripgrep over the working tree      (URLs, infra, config)
      -> score, classify, categorize, cap
      -> write partial results to disk      (the UI reads them live)
      -> delete the clone

Nothing is kept on disk except the JSON findings: cloned code is removed as
soon as it has been scanned.
"""

from __future__ import annotations

import datetime as _dt
import shutil
import tempfile
import time
from typing import Callable

from .config import ScanConfig
from .github import GitHubClient, GitHubError, RateLimited
from .patterns import Wordlists
from .scanners import clone_repo, require_tools, run_ripgrep, run_trufflehog
from .scoring import apply_repo_cap, categorize, sort_findings
from .store import ScanStore, new_scan_id, utc_now

Logger = Callable[[str], None]


def _cutoff(months: int) -> str:
    """Oldest `pushed_at` a repository may have. Empty means no age limit.

    0 means "no limit" everywhere else in the config — clone depth, findings
    cap — and taken literally here it would be a cutoff of *now*, which filters
    out every repository on earth. Nobody types 0 to scan nothing.
    """
    if months <= 0:
        return ""
    cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=months * 30)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


class DeepScanner:
    def __init__(
        self,
        config: ScanConfig,
        store: ScanStore,
        log: Logger | None = None,
        scan_id: str | None = None,
        secrets: dict | None = None,
    ):
        self.config = config
        self.store = store
        # Tokens travel here, NOT in config: config is serialised into every
        # scan file, and a scan file must never contain a credential of ours.
        self.secrets = secrets or {}
        # Resolved once per scan: a bad override should fail (or not) the same
        # way for every repository in the run.
        self.lists = Wordlists.resolve(config.wordlists)
        self.scan_id = scan_id or new_scan_id()
        self.started_at = utc_now()
        self._log_lines: list[str] = []
        self._external_log = log or (lambda msg: print(msg, flush=True))
        self.cancelled = False

        self.findings: list[dict] = []
        self.skipped_accounts: list[dict] = []
        self.stats = {
            "accounts_total": len(config.accounts),
            "accounts_scanned": 0,
            "repos_scanned": 0,
            "repos_skipped": 0,
            "clone_failures": 0,
            "trufflehog_findings": 0,
            "ripgrep_findings": 0,
            "verified_secrets": 0,
            "total_findings": 0,
            "keyword_matches": 0,
            "categories": {},
        }

    # -- logging -----------------------------------------------------------
    def log(self, message: str) -> None:
        stamp = _dt.datetime.now().strftime("%H:%M:%S")
        line = "[%s] %s" % (stamp, message)
        self._log_lines.append(line)
        if len(self._log_lines) > 5000:
            del self._log_lines[: len(self._log_lines) - 5000]
        self._external_log(line)

    # -- persistence -------------------------------------------------------
    def snapshot(self, status: str, finished: bool = False) -> dict:
        counts: dict[str, int] = {}
        verified = 0
        keyword_hits = 0
        for finding in self.findings:
            cat = finding.get("category", "other")
            counts[cat] = counts.get(cat, 0) + 1
            if finding.get("verified"):
                verified += 1
            if finding.get("company_match"):
                keyword_hits += 1

        self.stats["categories"] = counts
        self.stats["total_findings"] = len(self.findings)
        self.stats["verified_secrets"] = verified
        self.stats["keyword_matches"] = keyword_hits

        return {
            "id": self.scan_id,
            "label": self.config.label,
            "status": status,
            "started_at": self.started_at,
            "finished_at": utc_now() if finished else "",
            "config": self.config.to_dict(),
            "stats": dict(self.stats),
            "skipped_accounts": self.skipped_accounts,
            "log": self._log_lines[-800:],
            "findings": sort_findings(self.findings),
        }

    def flush(self, status: str = "running", finished: bool = False) -> None:
        self.store.save(self.snapshot(status, finished))

    # -- repo filtering ----------------------------------------------------
    def _eligible(self, repos: list[dict]) -> tuple[list[dict], dict[str, int]]:
        cutoff = _cutoff(self.config.max_repo_age_months)
        reasons = {"fork": 0, "archived": 0, "stale": 0, "oversized": 0}
        eligible = []
        for repo in repos:
            if self.config.skip_forks and repo.get("fork"):
                reasons["fork"] += 1
                continue
            if self.config.skip_archived and repo.get("archived"):
                reasons["archived"] += 1
                continue
            pushed = repo.get("pushed_at") or ""
            if cutoff and pushed and pushed < cutoff:
                reasons["stale"] += 1
                continue
            size_cap = self.config.max_repo_size_mb
            if size_cap > 0 and (repo.get("size") or 0) / 1024 > size_cap:
                reasons["oversized"] += 1
                continue
            eligible.append(repo)
        self.stats["repos_skipped"] += sum(reasons.values())
        return eligible, reasons

    # -- one repo ----------------------------------------------------------
    def scan_repo(self, account: str, repo: dict) -> list[dict]:
        name = repo.get("full_name") or repo.get("name") or "unknown"
        html_url = repo.get("html_url") or "https://github.com/%s" % name
        clone_url = repo.get("clone_url") or html_url + ".git"

        tmp_dir = tempfile.mkdtemp(prefix="gitanalyzer_")
        try:
            ok, error = clone_repo(
                clone_url, tmp_dir, self.config.clone_timeout, self.config.clone_depth
            )
            if not ok:
                self.stats["clone_failures"] += 1
                self.log("    %s — %s" % (name, error))
                return []

            repo_findings: list[dict] = []
            seen: set[str] = set()

            if self.config.use_trufflehog:
                th_findings, seen, th_error = run_trufflehog(
                    tmp_dir, self.config.trufflehog_timeout, self.lists
                )
                if th_error:
                    self.log("    %s — %s" % (name, th_error))
                repo_findings += th_findings
                self.stats["trufflehog_findings"] += len(th_findings)

            if self.config.use_ripgrep:
                rg_findings, rg_error = run_ripgrep(
                    tmp_dir, self.config.custom_patterns, seen,
                    self.config.ripgrep_timeout, self.lists,
                )
                if rg_error:
                    self.log("    %s — %s" % (name, rg_error))
                repo_findings += rg_findings
                self.stats["ripgrep_findings"] += len(rg_findings)

            for finding in repo_findings:
                finding["account"] = account
                finding["repo"] = name
                finding["repo_url"] = html_url
                categorize(finding, self.config.keywords)

            repo_findings, dropped = apply_repo_cap(repo_findings, self.config.max_findings_per_repo)
            th_count = sum(1 for f in repo_findings if f.get("scanner") == "trufflehog")
            rg_count = len(repo_findings) - th_count
            suffix = " (capped -%d)" % dropped if dropped else ""
            self.log("    %s — secrets:%d other:%d%s" % (name, th_count, rg_count, suffix))

            self.stats["repos_scanned"] += 1
            return repo_findings
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # -- one account -------------------------------------------------------
    def scan_account(self, client: GitHubClient, account: str, index: int, total: int) -> None:
        self.log("Account %d/%d: %s" % (index, total, account))

        if self.config.rescan_days > 0:
            age = self.store.days_since_scan(account)
            if age is not None and age < self.config.rescan_days:
                self.log("  skipped — scanned %.1f days ago (cooldown %dd)" % (age, self.config.rescan_days))
                self.skipped_accounts.append(
                    {
                        "account": account,
                        "reason": "cooldown",
                        "detail": "scanned %.1f days ago" % age,
                    }
                )
                return

        try:
            repos = client.user_repos(account)
        except RateLimited as exc:
            self.log("  rate limited — sleeping %ds" % exc.reset_in)
            time.sleep(exc.reset_in)
            repos = client.user_repos(account)
        except GitHubError as exc:
            self.log("  error — %s" % exc)
            self.skipped_accounts.append({"account": account, "reason": "api_error", "detail": str(exc)})
            return

        if not repos:
            self.log("  no public repos")
            self.skipped_accounts.append({"account": account, "reason": "no_repos", "detail": ""})
            return

        eligible, reasons = self._eligible(repos)
        detail = ", ".join("%d %s" % (v, k) for k, v in reasons.items() if v)
        self.log("  repos: %d total, %d eligible%s" % (len(repos), len(eligible), " (%s filtered)" % detail if detail else ""))

        if not eligible:
            self.skipped_accounts.append(
                {"account": account, "reason": "all_filtered", "detail": detail}
            )
            return

        account_findings = 0
        for repo in eligible:
            if self.cancelled:
                return
            found = self.scan_repo(account, repo)
            self.findings.extend(found)
            account_findings += len(found)
            self.flush()
            time.sleep(self.config.delay_between_repos)

        self.stats["accounts_scanned"] += 1
        self.log("  total: %d findings across %d repos" % (account_findings, len(eligible)))
        if account_findings == 0:
            self.skipped_accounts.append(
                {"account": account, "reason": "no_findings", "detail": "%d repos scanned" % len(eligible)}
            )
        self.store.record_account(account, len(eligible), account_findings)
        self.flush()

    # -- entry point -------------------------------------------------------
    def run(self) -> dict:
        self.started_at = utc_now()
        required = ["git"]
        if self.config.use_trufflehog:
            required.append("trufflehog")
        if self.config.use_ripgrep:
            required.append("rg")
        statuses = require_tools(required)

        self.log("GitAnalyzer deep scan %s" % self.scan_id)
        for status in statuses:
            self.log("  %s: %s" % (status.name, status.version or "ok"))

        client = GitHubClient(self.secrets.get("github_token") or None, log=self.log)
        if client.token:
            self.log("GitHub token: present (5000 req/h)")
        else:
            self.log("GitHub token: MISSING — 60 req/h. Export GITHUB_TOKEN for real runs.")

        # Every limit reads 0 as "no limit", so the header says what is actually
        # in force: "age<=24m" and "age=any" are the difference between a clean
        # result and a scan that never looked.
        cfg = self.config
        self.log(
            "Filters: age%s, size%s, forks=%s, archived=%s, cooldown=%s, cap=%s/repo"
            % (
                "<=%dm" % cfg.max_repo_age_months if cfg.max_repo_age_months > 0 else "=any",
                "<=%dMB" % cfg.max_repo_size_mb if cfg.max_repo_size_mb > 0 else "=any",
                "skip" if cfg.skip_forks else "include",
                "skip" if cfg.skip_archived else "include",
                "%dd" % cfg.rescan_days if cfg.rescan_days > 0 else "off",
                cfg.max_findings_per_repo if cfg.max_findings_per_repo > 0 else "unlimited",
            )
        )
        if self.config.clone_depth > 0 and self.config.use_trufflehog:
            self.log(
                "WARNING: shallow clone (depth %d) — TruffleHog will only see the last "
                "%d commits, so deleted secrets in older history will be missed."
                % (self.config.clone_depth, self.config.clone_depth)
            )
        if self.config.keywords:
            self.log("Keywords: %s" % ", ".join(self.config.keywords))
        if self.config.custom_patterns:
            self.log("Custom patterns: %d" % len(self.config.custom_patterns))

        self.flush("running")

        try:
            total = len(self.config.accounts)
            for index, account in enumerate(self.config.accounts, start=1):
                if self.cancelled:
                    break
                self.scan_account(client, account, index, total)
                time.sleep(self.config.delay_between_accounts)
        except KeyboardInterrupt:
            self.log("Interrupted — saving partial results")
            self.flush("cancelled", finished=True)
            return self.snapshot("cancelled", finished=True)
        except Exception as exc:  # noqa: BLE001 - surface any failure in the report
            self.log("FAILED: %s: %s" % (type(exc).__name__, exc))
            self.flush("failed", finished=True)
            raise

        # Nothing to triage is not a triage run: announcing one when every repo
        # was filtered out reads like the model looked and found nothing.
        if self.config.ai_triage and self.findings:
            from .triage import triage_findings

            self.log("AI triage: reviewing top findings")
            try:
                triage_findings(self.findings, self.config, self.log,
                                api_key=self.secrets.get("ai_key") or "")
            except Exception as exc:  # noqa: BLE001 - triage is optional
                self.log("AI triage skipped: %s" % exc)
            self.flush()

        status = "cancelled" if self.cancelled else "completed"
        self.log(
            "Done — %d findings (%d verified secrets) across %d repos, %d accounts"
            % (
                len(self.findings),
                self.stats["verified_secrets"],
                self.stats["repos_scanned"],
                self.stats["accounts_scanned"],
            )
        )
        self.flush(status, finished=True)
        return self.snapshot(status, finished=True)
