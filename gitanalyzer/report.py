"""Report rendering.

The dashboard and the exported report are the same page: `index.html` plus
the CSS and JS from `gitanalyzer/web/`. The only difference is whether the
scan data is fetched from the local API or embedded in the file. That keeps
one UI to maintain and makes an exported report a single self-contained
file you can hand to a client with no server attached.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from .scoring import SEVERITIES

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


def _asset(name: str) -> str:
    with open(os.path.join(WEB_DIR, name), "r", encoding="utf-8") as handle:
        return handle.read()


def build_page(scan: dict | None = None) -> str:
    """Render the dashboard. With `scan`, the data is embedded (static mode)."""
    html = _asset("index.html")
    html = html.replace("/*__STYLE__*/", _asset("style.css"))
    html = html.replace("/*__APP__*/", _asset("app.js"))

    if scan is not None:
        payload = json.dumps(scan, ensure_ascii=False)
        # Keep the JSON from terminating the surrounding <script> element.
        payload = payload.replace("</", "<\\/").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
        html = html.replace("/*__EMBEDDED_SCAN__*/ null", payload)
        title = scan.get("label") or scan.get("id", "report")
        html = html.replace("<title>0xGitAnalyzer</title>",
                            "<title>0xGitAnalyzer — %s</title>" % _escape(title))
    return html


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def write_html_report(scan: dict, path: str) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(build_page(scan))
    return path


def markdown_report(scan: dict, include_urls: bool = True) -> str:
    """A plain-text report for tickets, pull requests and e-mail."""
    stats = scan.get("stats", {})
    config = scan.get("config", {})
    lines = [
        "# 0xGitAnalyzer report",
        "",
        "| | |",
        "|---|---|",
        "| Scan | `%s` |" % scan.get("id", ""),
        "| Started | %s |" % scan.get("started_at", ""),
        "| Finished | %s |" % (scan.get("finished_at") or "(still running)"),
        "| Accounts scanned | %s of %s |" % (stats.get("accounts_scanned", 0), stats.get("accounts_total", 0)),
        "| Repos scanned | %s (%s skipped) |" % (stats.get("repos_scanned", 0), stats.get("repos_skipped", 0)),
        "| Findings | %s |" % stats.get("total_findings", 0),
        "| Live-verified secrets | %s |" % stats.get("verified_secrets", 0),
        "",
    ]

    if config.get("keywords"):
        lines += ["Keywords: %s" % ", ".join(config["keywords"]), ""]

    by_severity: dict[str, int] = {}
    for finding in scan.get("findings", []):
        severity = finding.get("severity", "low")
        by_severity[severity] = by_severity.get(severity, 0) + 1
    if by_severity:
        lines.append("Severity: " + ", ".join(
            "%s %s" % (by_severity.get(s, 0), s) for s in SEVERITIES if by_severity.get(s)
        ))
        lines.append("")

    current_account = current_repo = None
    for finding in scan.get("findings", []):
        # Noise and non-findings stay out of the deliverable.
        if finding.get("category") == "all_url":
            continue
        if finding.get("severity") == "informative":
            continue
        account = finding.get("account", "unknown")
        repo = finding.get("repo", "unknown")
        if account != current_account:
            current_account = account
            current_repo = None
            lines += ["", "## %s" % current_account, ""]
        if repo != current_repo:
            current_repo = repo
            lines += ["", "### %s" % current_repo, ""]
        flags = []
        if finding.get("verified"):
            flags.append("live verified")
        if finding.get("ai_verdict"):
            flag = "ai: %s" % finding["ai_verdict"]
            # Show the move, not just the result: a reader who disagrees with
            # the model needs to know what scoring said before it.
            heuristic = finding.get("heuristic_score")
            if heuristic is not None and heuristic != finding.get("score"):
                flag += " — scored %s, moved to %s" % (heuristic, finding.get("score"))
            flags.append(flag)
        if finding.get("matched_keywords"):
            flags.append("keywords: %s" % ", ".join(finding["matched_keywords"]))
        lines.append(
            "- **[%s %d]** `%s:%s` — %s%s"
            % (
                finding.get("severity", "low").upper(),
                finding.get("score", 0),
                finding.get("file", ""),
                finding.get("line", 0),
                finding.get("finding_type", "other"),
                " (%s)" % "; ".join(flags) if flags else "",
            )
        )
        preview = (finding.get("preview") or "").replace("`", "'")[:240]
        lines.append("  - `%s`" % preview)
        if finding.get("ai_reason"):
            lines.append("  - %s" % finding["ai_reason"])
        if include_urls:
            lines.append("  - %s" % finding.get("repo_url", ""))

    skipped = scan.get("skipped_accounts") or []
    if skipped:
        lines += ["", "## Skipped accounts", ""]
        for item in skipped:
            lines.append("- `%s` — %s%s" % (
                item.get("account", ""), item.get("reason", ""),
                " (%s)" % item["detail"] if item.get("detail") else "",
            ))

    lines += [
        "",
        "---",
        "",
        "Generated by GitAnalyzer on %s." % datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    ]
    return "\n".join(lines)
