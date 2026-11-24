"""Local dashboard.

Binds to 127.0.0.1 by default and serves:

    GET  /                         the dashboard
    GET  /api/scans                scan summaries
    GET  /api/scans/<id>           one full scan (findings included)
    GET  /api/scans/<id>/report.html   self-contained export
    GET  /api/scans/<id>/report.md     markdown export
    POST /api/scan                 start a scan in a background thread
    POST /api/scans/<id>/cancel    stop a running scan
    DELETE /api/scans/<id>         delete a scan file
    GET  /api/status               tool / token / AI readiness (what `doctor` prints)
    GET  /api/settings             stored settings + provider catalogue
    GET  /api/patterns             every pattern, glob and word list a scan uses
    POST /api/settings             update settings
    POST /api/ai/models            ask an OpenAI-format endpoint for its model list

Settings may hold API tokens. They are stored 0600 and the API returns only a
masked hint, never the value.

Scan results contain credential material. The server has no authentication,
so keep it on loopback. If you pass --host to expose it, put it behind
something that does authenticate.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from . import settings as settings_mod
from .config import ScanConfig
from .report import build_page, markdown_report
from .scanner import DeepScanner
from .store import ScanStore

# scan id -> running scanner, so /cancel can reach it
RUNNING: dict[str, DeepScanner] = {}
_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "0xGitAnalyzer"
    store: ScanStore
    allow_remote: bool = False

    # -- plumbing ----------------------------------------------------------
    def log_message(self, fmt, *args):  # quieter default logging
        if self.path.startswith("/api/scans/") and self.command == "GET":
            return
        print("  %s %s" % (self.command, self.path))

    def _send(self, code: int, body: bytes, content_type: str, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, data, code: int = 200):
        self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, code: int, message: str):
        self._json({"error": message}, code)

    def _host_allowed(self) -> bool:
        """Reject DNS-rebinding style requests when bound to loopback."""
        if self.allow_remote:
            return True
        host = (self.headers.get("Host") or "").split(":")[0].strip("[]").lower()
        return host in ("localhost", "127.0.0.1", "::1", "")

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    # -- routes ------------------------------------------------------------
    # ---- readiness ----------------------------------------------------
    def _status(self) -> dict:
        """Everything `gitanalyzer doctor` prints, for the panel to show."""
        from .github import GitHubClient, GitHubError, get_token
        from .scanners import check_tools
        from .triage import key_env_candidates, resolve_provider

        stored = settings_mod.load(self.store.dir)
        tools = [
            {"name": t.name, "available": t.available,
             "version": t.version, "hint": t.hint}
            for t in check_tools(["git", "rg", "trufflehog"])
        ]

        token = (stored.get("github_token") or "").strip() or get_token() or ""
        github = {
            "token": bool(token),
            "source": "settings" if (stored.get("github_token") or "").strip()
                      else ("environment" if token else ""),
            "limit": 60, "remaining": None,
        }
        if token:
            try:
                core = GitHubClient(token).rate_limit()
                github["limit"] = core.get("limit", 5000)
                github["remaining"] = core.get("remaining")
            except (GitHubError, OSError) as exc:
                github["error"] = str(exc)

        config = ScanConfig.from_dict(settings_mod.scan_defaults(stored))
        provider = resolve_provider(config, (stored.get("ai_key") or "").strip())
        sdk = True
        if provider.api == "anthropic":
            try:
                import anthropic  # noqa: F401
            except ImportError:
                sdk = False

        return {
            "tools": tools,
            "results_dir": self.store.dir,
            "github": github,
            "ai": {
                "enabled": bool(stored.get("ai_triage")),
                "provider": stored.get("ai_provider", ""),
                "model": stored.get("ai_model", ""),
                "endpoint": provider.base_url or "https://api.anthropic.com",
                "api": provider.api,
                "key": bool(provider.key),
                "key_source": provider.key_env if provider.key else "",
                "sdk": sdk,
                "key_envs": key_env_candidates(config, provider.api),
            },
        }

    def _ai_models(self) -> None:
        """Ask the endpoint what it serves, so the model list is the
        provider's own and not a guess of ours that goes stale.

        Both shapes expose a list: `/v1/models` with `x-api-key` for the
        Anthropic one, `/models` with a bearer token for the OpenAI one.
        """
        import urllib.error
        import urllib.request

        from .triage import infer_api

        body = self._body()
        stored = settings_mod.load(self.store.dir)
        base = (body.get("ai_base_url") or stored.get("ai_base_url") or "").strip().rstrip("/")
        api = (body.get("ai_api") or stored.get("ai_api") or "").strip().lower() or infer_api(base)
        key = (body.get("ai_key") or "").strip() or (stored.get("ai_key") or "").strip()

        if api == "anthropic":
            base = base or "https://api.anthropic.com"
            url = base + "/v1/models"
            headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
        else:
            if not base:
                return self._error(400, "no endpoint configured")
            url = base + "/models"
            headers = {"Authorization": "Bearer %s" % key}
        headers["User-Agent"] = "gitanalyzer"

        if not key:
            return self._error(400, "enter the API key first — the endpoint will not list models without one")

        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=20
            ) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                return self._error(400, "the endpoint rejected the key (HTTP %s)" % exc.code)
            if exc.code == 404:
                return self._error(400, "no model list at %s — type the model id by hand" % url)
            return self._error(502, "endpoint answered HTTP %s" % exc.code)
        except Exception as exc:  # noqa: BLE001 - network, DNS, bad JSON
            return self._error(502, "could not reach %s (%s)" % (base, exc))

        rows = data.get("data") if isinstance(data, dict) else data
        models = []
        for row in rows or []:
            name = row.get("id") if isinstance(row, dict) else row
            if name:
                models.append(str(name))
        if not models:
            return self._error(400, "the endpoint returned no models")
        return self._json({"models": sorted(set(models))})

    def do_GET(self):  # noqa: N802
        if not self._host_allowed():
            return self._error(403, "host not allowed")
        path = unquote(urlparse(self.path).path)

        if path in ("/", "/index.html"):
            return self._send(200, build_page(None).encode("utf-8"), "text/html; charset=utf-8")

        if path == "/api/scans":
            return self._json({"scans": self.store.list_scans()})

        if path == "/api/settings":
            data = settings_mod.load(self.store.dir)
            return self._json({
                "settings": settings_mod.public(data),
                "providers": settings_mod.PROVIDERS,
            })

        if path == "/api/status":
            return self._json(self._status())

        if path == "/api/patterns":
            from . import patterns as pat
            from .triage import SYSTEM_PROMPT

            stored = settings_mod.load(self.store.dir)
            overrides = settings_mod.clean_wordlists(stored.get("wordlists"))
            effective = pat.Wordlists.resolve(overrides)
            return self._json({
                "order": list(pat.WORDLIST_FIELDS),
                "labels": {k: {"title": v[0], "hint": v[1]}
                           for k, v in pat.WORDLIST_LABELS.items()},
                # What ships with the tool, so the panel can offer "reset".
                "builtin": pat.builtin_wordlists(),
                # What a scan started right now would actually use.
                "effective": {name: getattr(effective, name) for name in pat.WORDLIST_FIELDS},
                "overridden": sorted(overrides.keys()),
                "secret_types": sorted(pat.SECRET_TYPES),
                "interesting_types": sorted(pat.INTERESTING_TYPES),
                "default_prompt": SYSTEM_PROMPT,
                "custom_patterns": stored.get("custom_patterns", []),
            })

        if path.startswith("/api/scans/"):
            rest = path[len("/api/scans/"):]
            scan_id, _, suffix = rest.partition("/")
            scan = self.store.load(scan_id)
            if scan is None:
                return self._error(404, "scan not found")
            if not suffix:
                return self._json(scan)
            if suffix == "report.html":
                body = build_page(scan).encode("utf-8")
                return self._send(200, body, "text/html; charset=utf-8",
                                  {"Content-Disposition": 'attachment; filename="gitanalyzer-%s.html"' % scan_id})
            if suffix == "report.md":
                body = markdown_report(scan).encode("utf-8")
                return self._send(200, body, "text/markdown; charset=utf-8",
                                  {"Content-Disposition": 'attachment; filename="gitanalyzer-%s.md"' % scan_id})
            return self._error(404, "unknown resource")

        return self._error(404, "not found")

    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def do_POST(self):  # noqa: N802
        if not self._host_allowed():
            return self._error(403, "host not allowed")
        path = unquote(urlparse(self.path).path)

        if path == "/api/settings":
            current = settings_mod.load(self.store.dir)
            merged = settings_mod.apply_provider(
                settings_mod.merge(current, self._body())
            )
            bad = _check_rg_patterns(merged.get("wordlists", {}).get("rg_patterns") or [])
            if bad:
                return self._error(400, bad)
            try:
                settings_mod.save(self.store.dir, merged)
            except OSError as exc:
                return self._error(500, "could not save settings: %s" % exc)
            return self._json({"settings": settings_mod.public(merged)})

        if path == "/api/ai/models":
            return self._ai_models()

        if path == "/api/scan":
            payload = self._body()
            accounts = [a.strip() for a in (payload.get("accounts") or []) if str(a).strip()]
            if not accounts:
                return self._error(400, "at least one account is required")
            from .github import parse_account

            logins: list[str] = []
            for raw in accounts:
                login = parse_account(raw)
                if login and login not in logins:
                    logins.append(login)

            # Saved settings are the defaults; anything the dialog sent wins.
            stored = settings_mod.load(self.store.dir)
            merged = settings_mod.scan_defaults(stored)
            merged.update({k: v for k, v in payload.items() if v is not None})
            merged["accounts"] = logins
            merged.setdefault("label", "%d accounts" % len(logins))

            config = ScanConfig.from_dict(merged)
            scanner = DeepScanner(config, self.store,
                                  secrets=settings_mod.secrets(stored))

            with _LOCK:
                RUNNING[scanner.scan_id] = scanner
            scanner.flush("running")

            def run():
                try:
                    scanner.run()
                except Exception as exc:  # noqa: BLE001 - surfaced in the scan file
                    print("  scan %s failed: %s" % (scanner.scan_id, exc))
                    scanner.log("FAILED: %s" % exc)
                    try:
                        scanner.flush("failed", finished=True)
                    except Exception:
                        pass
                finally:
                    with _LOCK:
                        RUNNING.pop(scanner.scan_id, None)

            threading.Thread(target=run, daemon=True, name="scan-%s" % scanner.scan_id).start()
            return self._json({"id": scanner.scan_id, "status": "running"}, 202)

        if path.startswith("/api/scans/") and path.endswith("/cancel"):
            scan_id = path[len("/api/scans/"):-len("/cancel")]
            with _LOCK:
                scanner = RUNNING.get(scan_id)
            if not scanner:
                return self._error(404, "scan is not running")
            scanner.cancelled = True
            return self._json({"id": scan_id, "status": "cancelling"})

        return self._error(404, "not found")

    def do_DELETE(self):  # noqa: N802
        if not self._host_allowed():
            return self._error(403, "host not allowed")
        path = unquote(urlparse(self.path).path)
        if path.startswith("/api/scans/"):
            scan_id = path[len("/api/scans/"):]
            with _LOCK:
                if scan_id in RUNNING:
                    return self._error(409, "scan is still running")
            if self.store.delete(scan_id):
                return self._json({"deleted": scan_id})
            return self._error(404, "scan not found")
        return self._error(404, "not found")


def _check_rg_patterns(patterns: list[str]) -> str:
    """Validate a ripgrep pattern override before it can break every scan.

    ripgrep uses Rust's regex crate, which is not Python's: `(?=...)` compiles
    here and is rejected there. So the check is done by ripgrep itself when it
    is installed, with `re` only as a fallback. Asking the real engine is the
    difference between catching this now and finding out when a scan comes
    back empty.
    """
    if not patterns:
        return ""
    import subprocess

    for raw in patterns:
        pattern = str(raw)
        try:
            proc = subprocess.run(
                ["rg", "--regexp", pattern, "--quiet"],
                input="", capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            try:
                import re as _re
                _re.compile(pattern)
            except _re.error as exc:
                return "pattern rejected (%s): %s" % (exc, pattern[:120])
            continue
        if proc.returncode not in (0, 1):
            detail = (proc.stderr or "").strip().replace("\n", " ")
            return "ripgrep rejected a pattern: %s" % (detail[:300] or pattern[:120])
    return ""


def serve(results_dir: str = "results", host: str = "127.0.0.1", port: int = 8711) -> None:
    store = ScanStore(results_dir)
    handler = type("BoundHandler", (Handler,), {"store": store, "allow_remote": host not in ("127.0.0.1", "localhost", "::1")})
    httpd = ThreadingHTTPServer((host, port), handler)
    print("0xGitAnalyzer dashboard: http://%s:%d" % (host, port))
    print("Results directory:     %s" % store.dir)
    if handler.allow_remote:
        print("WARNING: bound to %s — this server has no authentication and scan" % host)
        print("         results contain credential material. Use a tunnel instead.")
    print("Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
