"""On-disk storage for scans.

One JSON file per scan plus a small history file used for re-scan cooldowns.
No database: results should be greppable, diffable and easy to delete.
"""

from __future__ import annotations

import itertools
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone

HISTORY_FILE = ".history.json"

# Counter for the in-process half of a scan id, random bytes for the rest: the
# counter rules out a collision inside one dashboard, the bytes rule one out
# between concurrent processes.
_COUNTER = itertools.count()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_scan_id() -> str:
    """Timestamp plus random suffix.

    The suffix is random, not derived from the clock: the scan id is the name
    of the result file, and two scans started from the dashboard in the same
    second would otherwise overwrite each other.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return "%s-%04x%s" % (stamp, next(_COUNTER) & 0xFFFF, secrets.token_hex(2))


class ScanStore:
    def __init__(self, results_dir: str = "results"):
        self.dir = os.path.abspath(os.path.expanduser(results_dir))
        os.makedirs(self.dir, exist_ok=True)

    # -- scan files --------------------------------------------------------
    def path_for(self, scan_id: str) -> str:
        safe = "".join(c for c in scan_id if c.isalnum() or c in "-_")
        return os.path.join(self.dir, "scan-%s.json" % safe)

    def save(self, scan: dict) -> str:
        """Atomic write so a half-written file is never served to the UI."""
        path = self.path_for(scan["id"])
        fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(scan, handle, indent=2, ensure_ascii=False)
            os.replace(tmp, path)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return path

    def load(self, scan_id: str) -> dict | None:
        path = self.path_for(scan_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (json.JSONDecodeError, OSError):
            return None

    def list_scans(self) -> list[dict]:
        """Scan summaries, newest first (findings omitted)."""
        summaries = []
        for name in os.listdir(self.dir):
            if not (name.startswith("scan-") and name.endswith(".json")):
                continue
            try:
                with open(os.path.join(self.dir, name), "r", encoding="utf-8") as handle:
                    scan = json.load(handle)
            except (json.JSONDecodeError, OSError):
                continue
            summaries.append(
                {
                    "id": scan.get("id", name[5:-5]),
                    "label": scan.get("label", ""),
                    "status": scan.get("status", "unknown"),
                    "started_at": scan.get("started_at", ""),
                    "finished_at": scan.get("finished_at", ""),
                    "accounts": scan.get("config", {}).get("accounts", []),
                    "stats": scan.get("stats", {}),
                }
            )
        summaries.sort(key=lambda s: s.get("started_at", ""), reverse=True)
        return summaries

    def delete(self, scan_id: str) -> bool:
        path = self.path_for(scan_id)
        if os.path.exists(path):
            os.unlink(path)
            return True
        return False

    # -- rescan history ----------------------------------------------------
    def _history_path(self) -> str:
        return os.path.join(self.dir, HISTORY_FILE)

    def load_history(self) -> dict:
        path = self._history_path()
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (json.JSONDecodeError, OSError):
            return {}

    def record_account(self, account: str, repos: int, findings: int) -> None:
        history = self.load_history()
        history[account.lower()] = {
            "last_scanned": utc_now(),
            "repos_scanned": repos,
            "findings_count": findings,
        }
        fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(history, handle, indent=2)
        os.replace(tmp, self._history_path())

    def days_since_scan(self, account: str) -> float | None:
        entry = self.load_history().get(account.lower())
        if not entry or not entry.get("last_scanned"):
            return None
        try:
            last = datetime.strptime(entry["last_scanned"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return None
        return (datetime.now(timezone.utc) - last).total_seconds() / 86400.0
