"""Minimal GitHub REST client built on the standard library.

No third-party HTTP dependency on purpose: this tool should run on a fresh
machine with nothing but Python, git, ripgrep and TruffleHog.

Authentication is read from the environment (GITHUB_TOKEN or GH_TOKEN) and
never written to disk or to scan output.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Iterator

API_ROOT = "https://api.github.com"
USER_AGENT = "0xGitAnalyzer (+https://github.com/OliveXSecurity/0xGitAnalyzer)"

Logger = Callable[[str], None]


class GitHubError(RuntimeError):
    pass


class RateLimited(GitHubError):
    def __init__(self, reset_in: int):
        super().__init__("GitHub rate limit reached")
        self.reset_in = reset_in


def get_token() -> str | None:
    """Read a token from the environment. Never hardcode one."""
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(var, "").strip()
        if value:
            return value
    return None


class GitHubClient:
    def __init__(self, token: str | None = None, log: Logger | None = None):
        self.token = token if token is not None else get_token()
        self.log = log or (lambda _msg: None)

    # -- low level ---------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }
        if self.token:
            headers["Authorization"] = "Bearer %s" % self.token
        return headers

    def get(self, path: str, params: dict | None = None, retries: int = 3):
        url = path if path.startswith("http") else API_ROOT + path
        if params:
            url += "?" + urllib.parse.urlencode(params)

        request = urllib.request.Request(url, headers=self._headers())
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code in (403, 429):
                    remaining = exc.headers.get("X-RateLimit-Remaining")
                    reset = exc.headers.get("X-RateLimit-Reset")
                    if remaining == "0" and reset:
                        wait = max(0, int(reset) - int(time.time())) + 5
                        raise RateLimited(wait) from exc
                    retry_after = int(exc.headers.get("Retry-After", "60"))
                    self.log("  [throttled] waiting %ss" % retry_after)
                    time.sleep(retry_after)
                    continue
                if exc.code == 404:
                    raise GitHubError("not found: %s" % url) from exc
                if exc.code >= 500 and attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise GitHubError("HTTP %s for %s" % (exc.code, url)) from exc
            except urllib.error.URLError as exc:
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise GitHubError("network error for %s: %s" % (url, exc.reason)) from exc
        raise GitHubError("giving up on %s" % url)

    def paginate(self, path: str, params: dict | None = None) -> Iterator[dict]:
        page = 1
        params = dict(params or {})
        params.setdefault("per_page", 100)
        while True:
            params["page"] = page
            try:
                batch = self.get(path, params)
            except RateLimited as exc:
                self.log("  [rate limited] sleeping %ss" % exc.reset_in)
                time.sleep(exc.reset_in)
                continue
            if isinstance(batch, dict):
                message = batch.get("message", "unexpected response")
                raise GitHubError(message)
            if not batch:
                return
            yield from batch
            if len(batch) < params["per_page"]:
                return
            page += 1

    # -- high level --------------------------------------------------------
    def rate_limit(self) -> dict:
        data = self.get("/rate_limit")
        return data.get("resources", {}).get("core", {})

    def user_repos(self, username: str) -> list[dict]:
        """Public repos owned by a user (forks included; filtered later)."""
        return list(
            self.paginate(
                "/users/%s/repos" % urllib.parse.quote(username),
                {"sort": "pushed", "type": "owner"},
            )
        )

    def org_members(self, org: str) -> list[str]:
        """Public members of an organization."""
        members = self.paginate("/orgs/%s/members" % urllib.parse.quote(org))
        return [m["login"] for m in members if m.get("login")]

    def org_repos(self, org: str) -> list[dict]:
        return list(self.paginate("/orgs/%s/repos" % urllib.parse.quote(org), {"sort": "pushed"}))


def parse_account(raw: str) -> str | None:
    """Normalize one input line into a GitHub login.

    Accepts `octocat`, `https://github.com/octocat`, `github.com/octocat/repo`.
    Returns None for blanks and comments.
    """
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    if "github.com/" in line:
        line = line.split("github.com/", 1)[1]
    line = line.strip("/").split("/")[0]
    line = line.split("?")[0].split("#")[0]
    return line or None


def read_account_list(path: str) -> list[str]:
    """Read an account list file, de-duplicated and order-preserving."""
    accounts: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            login = parse_account(line)
            if login and login not in accounts:
                accounts.append(login)
    return accounts
