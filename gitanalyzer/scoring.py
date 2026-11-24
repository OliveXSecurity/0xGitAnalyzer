"""Scoring, severity and classification for raw scanner output.

A scanner that reports everything reports nothing. This module turns a raw
match into a 0-100 confidence score, a severity, a finding type and a
category, so the UI can show the handful of lines that actually matter.
"""

from __future__ import annotations

import re

from .patterns import (
    CREDENTIAL_URL_RE,
    DEFAULT_WORDLISTS,
    FP_PRIVATE_KEY_PATHS,
    INTERESTING_TYPES,
    SECRET_TYPES,
    Wordlists,
    normalize_detector as _normalize_detector,
)


def score_finding(
    matched_text: str,
    file_path: str,
    line: str,
    scanner: str = "ripgrep",
    verified: bool = False,
    detector: str = "",
    lists: Wordlists | None = None,
) -> int:
    """Return a 0-100 confidence score for one match."""
    wl = lists or DEFAULT_WORDLISTS
    det = _normalize_detector(detector)
    fp = file_path.lower()

    # Base: a live-verified credential outranks everything else.
    if verified:
        score = 95
    elif scanner == "trufflehog":
        score = 70
    else:
        score = 50

    # Detector tiers
    if det in wl.low_set:
        score -= 40
    if det in wl.high_set and verified:
        score = 100

    # FTP demo servers are always public test boxes
    if det == "ftp" and any(x in line.lower() for x in ("demo", "test", "rebex")):
        score -= 50

    # The generic URI detector matches documentation examples
    if det == "uri":
        low = line.lower()
        if any(x in low for x in ("example.com", "localhost", "127.0.0.1", "0.0.0.0")):
            score -= 50
        elif "user:password" in low or "username:password" in low:
            score -= 40

    # File type signal
    if any(fp.endswith(ext) for ext in (".env", ".yml", ".yaml", ".json", ".properties", ".conf")):
        score += 15
    if "claude.md" in fp or "agents.md" in fp or ".cursor/" in fp or "mcp.json" in fp:
        score += 10

    # Path penalties
    if any(x in fp for x in ("test", "example", "sample", "mock", "fixture", "demo")):
        score -= 30
    if any(x in fp for x in ("_posts/", "blog/", "writeup", "walkthrough", ".rst", "docs/archive")):
        score -= 25
    if "forge-std" in fp or "foundry.toml" in fp:
        score -= 40
    if fp.endswith(".min.js") or "all.min.js" in fp or "bundle.js" in fp:
        score -= 20

    # Content signal
    if "PRIVATE KEY" in line:
        score += -30 if any(x in fp for x in FP_PRIVATE_KEY_PATHS) else 30
    if "AKIA" in line:
        score += 25
    if CREDENTIAL_URL_RE.search(line):
        low = line.lower()
        if not any(x in low for x in ("example.com", "localhost", "127.0.0.1", "user:password")):
            score += 20

    # Internal infrastructure
    if "docs.google.com" in line or "drive.google.com" in line:
        score += 15
    if ".atlassian.net" in line or ".okta.com" in line or ".auth0.com" in line:
        score += 15
    if ".internal." in line or ".corp." in line or ".staging." in line:
        score += 20
    if ".sharepoint.com" in line:
        score += 15

    # Credential stores
    if any(x in fp for x in ("rclone.conf", ".npmrc", ".docker/config", ".netrc", ".pgpass")):
        score += 20

    return max(0, min(100, score))


def classify_severity(score: int) -> str:
    """Map a score to a band a report can use.

    `informative` is deliberately separate from `low`. In a bug bounty
    programme "low" means reportable-but-minor; this bottom band is for
    things that are not a vulnerability at all — a public marketing URL, a
    documentation link, anything the model confidently dismissed. Folding
    those into `low` is what makes a `low` bucket useless to triage.
    """
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "informative"


# Worst first, for sorting and for rendering filter lists.
SEVERITIES = ("critical", "high", "medium", "low", "informative")


_DETECTOR_TYPE_RULES: list[tuple[tuple[str, ...], str]] = [
    (("aws", "akia"), "aws_key"),
    (("github",), "github_token"),
    (("cloudflare", "supabase", "azure", "gcp"), "cloud_credential"),
    (("stripe", "squareup", "square", "paypal"), "payment_key"),
    (("slack",), "slack"),
    (("sendgrid", "mailgun", "twilio"), "api_key"),
    (("privatekey", "private"), "private_key"),
    (("jwt",), "jwt"),
    (("telegram",), "bot_token"),
    (("discord",), "webhook"),
    (("openai", "anthropic", "gemini", "huggingface"), "ai_api_key"),
    (("algolia",), "search_key"),
    (("wandb", "weightsandbiases"), "ml_key"),
    (("infura", "alchemy"), "blockchain_key"),
    (("mongodb", "postgres", "mysql", "redis"), "db_credential"),
    (("npm", "pypi", "nuget", "dockerhub"), "package_token"),
    (("firebase",), "firebase"),
    (("heroku", "datadog", "newrelic", "vercel", "netlify"), "api_key"),
    (("ftp", "uri"), "credential_url"),
    (("pubnub", "pixabay", "rawg", "mockaroo", "disqus", "pastebin"), "low_value_key"),
    (("google",), "api_key"),
    (("bearer", "token", "key", "secret"), "api_key"),
]


def classify_finding_type(text: str, detector: str = "") -> str:
    """Map a match to a finding type used for filtering and colouring."""
    t = text.lower()
    d = detector.lower()

    if d:
        for needles, kind in _DETECTOR_TYPE_RULES:
            if any(n in d for n in needles):
                return kind

    if "docs.google.com" in t or "drive.google.com" in t:
        return "google_docs"
    if ".atlassian.net" in t or "jira" in t or "confluence" in t:
        return "jira"
    if "notion.so" in t:
        return "notion"
    if ".okta.com" in t:
        return "okta"
    if ".auth0.com" in t:
        return "auth0"
    if ".sharepoint.com" in t or "onedrive" in t:
        return "sharepoint"
    if "hooks.slack.com" in t:
        return "slack"
    if any(x in t for x in (".internal.", ".corp.", ".staging.", ".dev.")):
        return "internal_url"
    if "grafana" in t or "kibana" in t:
        return "dashboard"
    if "jenkins" in t:
        return "ci_cd"
    if "sentry.io" in t:
        return "sentry"
    if "firebaseio.com" in t or "appspot.com" in t:
        return "firebase"
    if re.search(r"(mongodb\+srv|mysql|postgresql|redis)://", t):
        return "db_credential"
    if "private key" in t:
        return "private_key"
    if re.search(r"akia[0-9a-z]", t):
        return "aws_key"
    if re.search(r"(password|passwd|pwd|secret|api_key|apikey|access_token)\s*[:=]", t):
        return "hardcoded_secret"
    if re.search(r"https?://", t):
        return "url"
    return "other"


def categorize(finding: dict, keywords: list[str]) -> None:
    """Annotate a finding in place with keyword matches and a category."""
    ftype = finding.get("finding_type", "other")
    haystack = (finding.get("preview", "") + " " + finding.get("pattern", "")).lower()

    matched = [k for k in keywords if k in haystack] if keywords else []
    finding["company_match"] = bool(matched)
    finding["matched_keywords"] = matched

    if finding.get("scanner") == "trufflehog" or ftype in SECRET_TYPES:
        finding["category"] = "secret"
    elif finding["company_match"]:
        finding["category"] = "company_match"
    elif ftype in INTERESTING_TYPES:
        finding["category"] = "interesting_url"
    elif ftype == "url":
        finding["category"] = "all_url"
    else:
        finding["category"] = "other"


CATEGORY_ORDER = {
    "secret": 0,
    "company_match": 1,
    "interesting_url": 2,
    "other": 3,
    "all_url": 4,
}


def sort_findings(findings: list[dict]) -> list[dict]:
    """Secrets first, then keyword hits, then infrastructure, then noise."""
    return sorted(
        findings,
        key=lambda f: (CATEGORY_ORDER.get(f.get("category", "other"), 5), -f.get("score", 0)),
    )


def apply_repo_cap(findings: list[dict], cap: int) -> tuple[list[dict], int]:
    """Cap findings per repo, never dropping secrets or keyword matches."""
    if cap <= 0 or len(findings) <= cap:
        return findings, 0
    keep_cats = ("secret", "company_match", "interesting_url")
    priority = [f for f in findings if f.get("category") in keep_cats]
    rest = sorted(
        (f for f in findings if f.get("category") not in keep_cats),
        key=lambda f: f.get("score", 0),
        reverse=True,
    )
    slots = max(0, cap - len(priority))
    capped = priority + rest[:slots]
    return capped, len(findings) - len(capped)
