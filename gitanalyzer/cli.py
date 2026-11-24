"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .config import ScanConfig
from .github import GitHubClient, GitHubError, get_token, parse_account, read_account_list
from .report import build_page, markdown_report, write_html_report
from .scanner import DeepScanner
from .scanners import MissingToolError, check_tools
from .store import ScanStore

BANNER = r"""
  ___       ___ _ _      _                _
 / _ \__  _/ __(_) |_   /_\  _ _  __ _| |_  _ ______ _ _
| | | \ \/ / |  _| | __| / _ \| ' \/ _` | | || |_ / -_) '_|
| |_| |>  <| |_| | | |_ /_/ \_\_||_\__,_|_|\_, /__\___|_|
 \___//_/\_\\___|_|\__|                    |__/
 open-source GitHub exposure scanner — www.olivex.io
"""

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def resolve_accounts(args, client: GitHubClient) -> list[str]:
    accounts: list[str] = []

    for value in args.accounts or []:
        if os.path.isfile(value):
            for login in read_account_list(value):
                if login not in accounts:
                    accounts.append(login)
        else:
            login = parse_account(value)
            if login and login not in accounts:
                accounts.append(login)

    for org in args.org or []:
        print("Resolving public members of %s..." % org)
        try:
            members = client.org_members(org)
        except GitHubError as exc:
            print("  could not read members of %s: %s" % (org, exc), file=sys.stderr)
            continue
        print("  %d public members" % len(members))
        for login in members:
            if login not in accounts:
                accounts.append(login)

    return accounts


def config_from_args(args, accounts: list[str]) -> ScanConfig:
    patterns: list[str] = []
    if args.pattern_file and os.path.isfile(args.pattern_file):
        with open(args.pattern_file, "r", encoding="utf-8") as handle:
            patterns = [line.strip() for line in handle if line.strip() and not line.startswith("#")]

    return ScanConfig(
        accounts=accounts,
        max_repo_age_months=args.max_age,
        max_repo_size_mb=args.max_size,
        skip_forks=not args.include_forks,
        skip_archived=not args.include_archived,
        rescan_days=args.cooldown,
        custom_patterns=patterns,
        keywords=[k.strip().lower() for k in (args.keywords or "").split(",") if k.strip()],
        max_findings_per_repo=args.cap,
        clone_depth=args.depth,
        use_trufflehog=not args.no_trufflehog,
        use_ripgrep=not args.no_ripgrep,
        ai_triage=args.ai_triage,
        ai_model=args.ai_model,
        ai_base_url=args.ai_base_url,
        ai_api=args.ai_api,
        ai_key_env=args.ai_key_env,
        ai_redact=not args.ai_no_redact,
        ai_max_findings=args.ai_max,
        label=args.label or ("%d accounts" % len(accounts)),
    )


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_scan(args) -> int:
    client = GitHubClient()
    accounts = resolve_accounts(args, client)
    if not accounts:
        print("No accounts to scan. Pass logins, a file, or --org NAME.", file=sys.stderr)
        return 2

    store = ScanStore(args.results)
    config = config_from_args(args, accounts)

    if args.dry_run:
        print(json.dumps(config.to_dict(), indent=2))
        return 0

    scanner = DeepScanner(config, store)
    try:
        scan = scanner.run()
    except MissingToolError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130

    print("\nResults: %s" % store.path_for(scan["id"]))

    if args.html:
        path = args.html if args.html != "-" else "gitanalyzer-%s.html" % scan["id"]
        write_html_report(scan, path)
        print("HTML report: %s" % os.path.abspath(path))
    if args.md:
        path = args.md if args.md != "-" else "gitanalyzer-%s.md" % scan["id"]
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(markdown_report(scan))
        print("Markdown report: %s" % os.path.abspath(path))

    print("View it with:  gitanalyzer serve --results %s" % store.dir)
    print("               (or just `gitanalyzer serve` from this directory)")
    return 0


def cmd_serve(args) -> int:
    from .server import serve

    serve(args.results, args.host, args.port)
    return 0


def cmd_list(args) -> int:
    store = ScanStore(args.results)
    scans = store.list_scans()
    if not scans:
        print("No scans in %s" % store.dir)
        return 0
    print("%-26s %-10s %7s %7s  %s" % ("SCAN", "STATUS", "REPOS", "FINDS", "ACCOUNTS"))
    for scan in scans:
        stats = scan.get("stats", {})
        accounts = ", ".join(scan.get("accounts", [])[:4])
        if len(scan.get("accounts", [])) > 4:
            accounts += ", +%d" % (len(scan["accounts"]) - 4)
        print("%-26s %-10s %7s %7s  %s" % (
            scan["id"], scan["status"],
            stats.get("repos_scanned", 0), stats.get("total_findings", 0),
            accounts,
        ))
    return 0


def cmd_delete(args) -> int:
    """Delete stored scans by id.

    A scan file holds the only copy of its findings — the clones it read are
    temporary — so unless --yes is given it says what it is about to remove
    and asks.
    """
    store = ScanStore(args.results)
    summaries = {s["id"]: s for s in store.list_scans()}

    missing = [i for i in args.scan_ids if i not in summaries]
    for scan_id in missing:
        print("Scan not found: %s" % scan_id, file=sys.stderr)
    targets = [i for i in args.scan_ids if i in summaries]
    if not targets:
        return 2

    if not args.yes:
        for scan_id in targets:
            stats = summaries[scan_id].get("stats", {})
            print("%s  %s findings  %s" % (
                scan_id, stats.get("total_findings", 0),
                ", ".join(summaries[scan_id].get("accounts", [])) or "-"))
        answer = input("Delete %d scan(s) from %s? [y/N] " % (len(targets), store.dir))
        if answer.strip().lower() not in ("y", "yes"):
            print("Nothing deleted.")
            return 1

    for scan_id in targets:
        if store.delete(scan_id):
            print("deleted %s" % scan_id)
    return 2 if missing else 0


def cmd_report(args) -> int:
    store = ScanStore(args.results)
    scan = store.load(args.scan_id)
    if scan is None and os.path.isfile(args.scan_id):
        with open(args.scan_id, "r", encoding="utf-8") as handle:
            scan = json.load(handle)
    if scan is None:
        print("Scan not found: %s" % args.scan_id, file=sys.stderr)
        return 2

    if args.format == "md":
        text = markdown_report(scan)
    else:
        text = build_page(scan)

    if args.output == "-":
        sys.stdout.write(text)
    else:
        path = args.output or "gitanalyzer-%s.%s" % (scan["id"], args.format)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(os.path.abspath(path))
    return 0


def cmd_doctor(args) -> int:
    print(BANNER.strip("\n"))
    print("\nversion %s\n" % __version__)
    ok = True
    for status in check_tools(["git", "rg", "trufflehog"]):
        mark = "ok  " if status.available else "MISS"
        print("[%s] %-11s %s" % (mark, status.name, status.version or status.hint))
        ok = ok and status.available

    token = get_token()
    if token:
        try:
            core = GitHubClient(token).rate_limit()
            print("[ok  ] github      token present — %s/%s requests left"
                  % (core.get("remaining", "?"), core.get("limit", "?")))
        except GitHubError as exc:
            print("[WARN] github      token present but rejected: %s" % exc)
            ok = False
    else:
        print("[WARN] github      no GITHUB_TOKEN — limited to 60 requests/hour")

    from .config import ScanConfig
    from .triage import key_env_candidates, resolve_provider

    provider = resolve_provider(ScanConfig())
    if not provider.key:
        print("[ -- ] ai triage   disabled (no key in %s)"
              % ", ".join(key_env_candidates(ScanConfig(), provider.api)))
    elif provider.api == "anthropic":
        try:
            import anthropic  # noqa: F401
            print("[ok  ] ai triage   %s" % provider.describe())
        except ImportError:
            print('[WARN] ai triage   key present but SDK missing: pip install "gitanalyzer[ai]"')
    else:
        print("[ok  ] ai triage   %s" % provider.describe())

    print("\nresults dir: %s" % ScanStore(args.results).dir)
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gitanalyzer",
        description="Scan the public GitHub footprint of a list of accounts for leaked "
                    "credentials and internal infrastructure.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Only scan accounts you are authorized to assess.\n"
               "0xGitAnalyzer — developed by www.olivex.io",
    )
    parser.add_argument("--version", action="version", version="gitanalyzer %s" % __version__)
    parser.add_argument("--results", default="results", help="results directory (default: ./results)")

    # `--results` is accepted on either side of the subcommand. SUPPRESS keeps the
    # subcommand copy from overwriting the global one with its own default when it
    # is not given: `gitanalyzer --results X serve` and `gitanalyzer serve
    # --results X` both work, and neither clobbers the other.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--results", default=argparse.SUPPRESS,
                        help="results directory (default: ./results)")

    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    scan = sub.add_parser("scan", help="clone and scan every repo of every account", parents=[common])
    scan.add_argument("accounts", nargs="*", help="logins, profile URLs, or a file with one per line")
    scan.add_argument("--org", action="append", help="expand an organization's public members (repeatable)")
    scan.add_argument("--keywords", default="", help="comma-separated keywords to flag (company names, domains)")
    scan.add_argument("--pattern-file", help="file with extra literal strings to search for")
    scan.add_argument("--max-age", type=int, default=24, metavar="MONTHS", help="skip repos not pushed to in this long (default: 24, 0 = no limit)")
    scan.add_argument("--max-size", type=int, default=500, metavar="MB", help="skip repos larger than this (default: 500)")
    scan.add_argument("--cooldown", type=int, default=7, metavar="DAYS", help="skip accounts scanned recently (0 disables)")
    scan.add_argument("--cap", type=int, default=200, metavar="N", help="max findings per repo, secrets never dropped (0 = unlimited)")
    scan.add_argument("--depth", type=int, default=0, metavar="N", help="shallow clone depth; 0 = full history (default)")
    scan.add_argument("--include-forks", action="store_true", help="do not skip forks")
    scan.add_argument("--include-archived", action="store_true", help="do not skip archived repos")
    scan.add_argument("--no-trufflehog", action="store_true", help="disable the credential scanner")
    scan.add_argument("--no-ripgrep", action="store_true", help="disable the URL/infrastructure scanner")
    scan.add_argument("--ai-triage", action="store_true", help="review top findings with Claude (needs ANTHROPIC_API_KEY)")
    scan.add_argument("--ai-model", default="claude-opus-5-5", help="model for triage (default: claude-opus-5-5)")
    scan.add_argument("--ai-base-url", default="", metavar="URL",
                      help="any compatible endpoint (Kimi, DeepSeek, OpenRouter, Ollama, vLLM...)")
    scan.add_argument("--ai-api", default="", choices=["", "anthropic", "openai"],
                      help="wire format (default: inferred from --ai-base-url)")
    scan.add_argument("--ai-key-env", default="", metavar="NAME",
                      help="env var holding the API key (default: the provider's usual one)")
    scan.add_argument("--ai-max", type=int, default=150, metavar="N", help="max findings to triage (default: 150)")
    scan.add_argument("--ai-no-redact", action="store_true", help="send unmasked excerpts to the API (off by default)")
    scan.add_argument("--label", help="short name for this scan")
    scan.add_argument("--html", nargs="?", const="-", help="also write a self-contained HTML report")
    scan.add_argument("--md", nargs="?", const="-", help="also write a markdown report")
    scan.add_argument("--dry-run", action="store_true", help="print the resolved config and exit")
    scan.set_defaults(func=cmd_scan)

    # serve
    serve = sub.add_parser("serve", help="open the dashboard", parents=[common])
    serve.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8711, help="port (default: 8711)")
    serve.set_defaults(func=cmd_serve)

    # list
    listing = sub.add_parser("list", help="list stored scans", parents=[common])
    listing.set_defaults(func=cmd_list)

    # delete
    delete = sub.add_parser("delete", help="delete stored scans", parents=[common])
    delete.add_argument("scan_ids", nargs="+", metavar="SCAN_ID", help="scan ids, as `list` prints them")
    delete.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    delete.set_defaults(func=cmd_delete)

    # report
    report = sub.add_parser("report", help="export a stored scan", parents=[common])
    report.add_argument("scan_id", help="scan id or path to a scan JSON file")
    report.add_argument("--format", choices=["html", "md"], default="html")
    report.add_argument("-o", "--output", help="output file, or - for stdout")
    report.set_defaults(func=cmd_report)

    # doctor
    doctor = sub.add_parser("doctor", help="check dependencies and credentials", parents=[common])
    doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
