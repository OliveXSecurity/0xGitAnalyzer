"""Wrappers around the two external scanners.

TruffleHog finds credentials (with live verification where it can).
Ripgrep finds everything TruffleHog ignores: URLs, internal hostnames,
SaaS links and config keys.

Both are required. The project deliberately does not reimplement them —
a half-finished regex engine that misses real keys is worse than no scanner.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass

from .patterns import (
    DEFAULT_WORDLISTS,
    Wordlists,
    build_ripgrep_pattern,
    is_placeholder,
)
from .scoring import classify_finding_type, classify_severity, score_finding

TOOL_HINTS = {
    "git": "https://git-scm.com/downloads",
    "rg": "ripgrep — brew install ripgrep | apt install ripgrep",
    "trufflehog": "brew install trufflehog | https://github.com/trufflesecurity/trufflehog",
}


@dataclass
class ToolStatus:
    name: str
    available: bool
    version: str = ""
    hint: str = ""


def check_tools(required: list[str] | None = None) -> list[ToolStatus]:
    """Report which external binaries are present."""
    statuses = []
    for name in required or ["git", "rg", "trufflehog"]:
        path = shutil.which(name)
        version = ""
        if path:
            try:
                proc = subprocess.run(
                    [name, "--version"], capture_output=True, text=True, timeout=15
                )
                version = (proc.stdout or proc.stderr).strip().splitlines()[0][:80]
            except Exception:
                version = "unknown version"
        statuses.append(
            ToolStatus(name=name, available=bool(path), version=version, hint=TOOL_HINTS.get(name, ""))
        )
    return statuses


class MissingToolError(RuntimeError):
    pass


def require_tools(names: list[str]) -> list[ToolStatus]:
    statuses = check_tools(names)
    missing = [s for s in statuses if not s.available]
    if missing:
        lines = ["Missing required tools:"]
        lines += ["  - %s  (%s)" % (s.name, s.hint) for s in missing]
        raise MissingToolError("\n".join(lines))
    return statuses


def clone_repo(clone_url: str, dest: str, timeout: int = 120, depth: int = 0) -> tuple[bool, str]:
    """Clone a repository. Full history by default so TruffleHog can walk it."""
    cmd = ["git", "clone", "--quiet"]
    if depth > 0:
        cmd += ["--depth", str(depth)]
    cmd += [clone_url, dest]
    env = {"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return False, "clone timeout"
    if proc.returncode != 0:
        return False, (proc.stderr or "clone failed").strip().splitlines()[-1][:120]
    return True, ""


def run_trufflehog(
    repo_dir: str, timeout: int = 300, lists: Wordlists | None = None
) -> tuple[list[dict], set[str], str]:
    """Scan a cloned repo's full git history for credentials.

    Returns (findings, seen file:line keys, error message).
    """
    wl = lists or DEFAULT_WORDLISTS
    findings: list[dict] = []
    seen: set[str] = set()
    cmd = ["trufflehog", "git", "file://%s" % repo_dir, "--json", "--no-update"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return findings, seen, "trufflehog timeout"
    except FileNotFoundError:
        return findings, seen, "trufflehog not installed"

    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            secret = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "level" in secret:  # log line, not a finding
            continue

        detector = secret.get("DetectorName") or secret.get("DetectorType") or "Unknown"
        raw = (secret.get("Raw") or "")[:100]
        verified = bool(secret.get("Verified"))
        meta = (secret.get("SourceMetadata") or {}).get("Data", {}) or {}
        git_info = meta.get("Git") or meta.get("Filesystem") or {}
        file_path = git_info.get("file") or git_info.get("path") or ""
        line_num = git_info.get("line") or 0
        commit = git_info.get("commit") or ""

        if is_placeholder(raw, wl):
            continue

        seen.add("%s:%s" % (file_path, line_num))
        score = score_finding(raw, file_path, raw, "trufflehog", verified, str(detector), wl)
        preview = "[TruffleHog] %s%s | %s" % (
            detector,
            " VERIFIED" if verified else "",
            raw[:80],
        )
        findings.append(
            {
                "file": file_path,
                "line": line_num,
                "commit": commit[:12],
                "pattern": "[TH] %s%s" % (detector, " *" if verified else ""),
                "preview": preview,
                "score": score,
                "severity": classify_severity(score),
                "scanner": "trufflehog",
                "verified": verified,
                "detector": str(detector),
                "finding_type": classify_finding_type(raw, str(detector)),
            }
        )
    return findings, seen, ""


def rg_error(stderr: str, returncode: int) -> str:
    """ripgrep's own words, keeping the part that says what is wrong.

    A parse error prints "regex parse error:", then the whole pattern, then a
    caret, and only then "error: <reason>". The combined pattern is over a
    thousand characters, so truncating from the front throws away the one line
    worth reading and reports the echo instead.
    """
    lines = [
        line.strip() for line in (stderr or "").splitlines()
        if line.strip() and set(line.strip()) != {"^"}
    ]
    if not lines:
        return "exit %d" % returncode
    reason = next((l for l in reversed(lines) if l.startswith("error:")), lines[-1])
    if reason is not lines[0]:
        reason = "%s %s" % (lines[0], reason)
    return reason[:240]


def run_ripgrep(
    repo_dir: str,
    custom_patterns: list[str],
    already_seen: set[str],
    timeout: int = 600,
    lists: Wordlists | None = None,
) -> tuple[list[dict], str]:
    """Scan the working tree for URLs, infrastructure and config secrets."""
    wl = lists or DEFAULT_WORDLISTS
    findings: list[dict] = []
    pattern = build_ripgrep_pattern(custom_patterns, wl)

    # No global -i: each pattern sets (?i) for itself. The dotenv shape relies on
    # the key being upper-case, which a global -i would destroy.
    cmd = ["rg", "--json", "--max-filesize", "1M"]
    for glob in wl.include_globs:
        cmd += ["--glob", glob]
    for glob in wl.exclude_globs:
        cmd += ["--glob", "!%s" % glob]
    cmd += [pattern, repo_dir]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return findings, "ripgrep timeout"
    except FileNotFoundError:
        return findings, "ripgrep not installed"

    # 0 = matches, 1 = no matches. Anything else is ripgrep refusing to run,
    # and with editable patterns the usual cause is a regex it cannot compile.
    # Reporting it is the difference between "this repo is clean" and "this
    # scan searched for nothing".
    if proc.returncode not in (0, 1):
        return findings, "ripgrep failed: %s" % rg_error(proc.stderr, proc.returncode)

    for line in (proc.stdout or "").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") != "match":
            continue

        data = event.get("data", {})
        file_abs = (data.get("path", {}) or {}).get("text", "")
        try:
            file_rel = os.path.relpath(file_abs, repo_dir)
        except ValueError:  # different drive on Windows
            file_rel = file_abs
        line_num = data.get("line_number", 0)
        line_text = ((data.get("lines", {}) or {}).get("text") or "").strip()

        key = "%s:%s" % (file_rel, line_num)
        if key in already_seen:
            continue
        already_seen.add(key)

        submatches = data.get("submatches") or []
        matched = (
            (submatches[0].get("match", {}) or {}).get("text", "")
            if submatches
            else line_text[:100]
        )
        if is_placeholder(matched, wl):
            continue

        score = score_finding(matched, file_rel, line_text, "ripgrep", lists=wl)
        findings.append(
            {
                "file": file_rel,
                "line": line_num,
                "commit": "",
                "pattern": matched[:200],
                "preview": line_text[:300],
                "score": score,
                "severity": classify_severity(score),
                "scanner": "ripgrep",
                "verified": False,
                "detector": "",
                "finding_type": classify_finding_type(line_text),
            }
        )
    return findings, ""
