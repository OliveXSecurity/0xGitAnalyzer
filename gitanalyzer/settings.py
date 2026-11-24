"""Dashboard settings: what the panel can change, and where it is kept.

Everything the CLI takes as a flag can also be set from the dashboard, so a
run started from the browser is not a second-class one.

Secrets are the delicate part. A token typed into the panel has to be stored
to be useful across restarts, so it is written to `<results>/.settings.json`
with mode 0600 — but:

  * the API never returns a token, only a masked hint and a boolean;
  * tokens are kept out of `ScanConfig`, so they can never reach a scan file;
  * the environment still works and still wins, so nothing forces you to
    write a secret to disk at all.

If you would rather keep secrets out of files entirely, leave the token
fields empty and export GITHUB_TOKEN / ANTHROPIC_API_KEY as before.
"""

from __future__ import annotations

import json
import os
import tempfile

SETTINGS_FILE = ".settings.json"

# Fields that are secret: masked on the way out, never copied into a scan.
SECRET_FIELDS = ("github_token", "ai_key")

DEFAULTS: dict = {
    # GitHub
    "github_token": "",
    # Scan defaults — these pre-fill the New scan dialog.
    # Every limit below takes 0 as "no limit", and that is what the dashboard
    # ships with: a filter you did not set should not be the reason a scan
    # comes back empty. The CLI keeps its own tuned defaults (24m / 500MB /
    # 7d / 200), since there the values are typed, visible in `--help`, and
    # printed in the run header.
    "keywords": [],
    "custom_patterns": [],
    "max_repo_age_months": 0,
    "max_repo_size_mb": 0,
    "rescan_days": 0,
    "max_findings_per_repo": 0,
    "skip_forks": True,
    "skip_archived": True,
    "use_trufflehog": True,
    "use_ripgrep": True,
    "clone_depth": 0,
    # Overrides for the lists in patterns.py. Only the lists actually changed
    # are stored; an empty or absent one means "use the built-in list".
    "wordlists": {},
    # Timeouts and pacing (seconds)
    "clone_timeout": 120,
    "trufflehog_timeout": 300,
    "ripgrep_timeout": 600,
    "delay_between_repos": 1.5,
    "delay_between_accounts": 1.0,
    # AI triage
    "ai_triage": False,
    "ai_provider": "anthropic",
    "ai_model": "claude-opus-5-5",
    "ai_base_url": "",
    "ai_api": "",
    "ai_key": "",
    "ai_redact": True,
    "ai_max_findings": 150,
    "ai_batch_size": 15,
    "ai_timeout": 120,
    "ai_system_prompt": "",  # "" = the built-in triage prompt
}

# Known endpoints. `models` are suggestions only — the field stays free text,
# and for openai-format providers the dashboard can ask the endpoint itself.
PROVIDERS: list[dict] = [
    {
        "id": "anthropic",
        "label": "Anthropic",
        "base_url": "",
        "api": "anthropic",
        "key_env": "ANTHROPIC_API_KEY",
        "needs_sdk": True,
        "models": ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-2"],
    },
    {
        "id": "moonshot",
        "label": "Kimi (Moonshot)",
        "base_url": "https://api.moonshot.ai/anthropic",
        "api": "anthropic",
        "key_env": "MOONSHOT_API_KEY",
        "needs_sdk": True,
        "models": [],
    },
    {
        "id": "deepseek",
        "label": "DeepSeek",
        "base_url": "https://api.deepseek.com/v1",
        "api": "openai",
        "key_env": "DEEPSEEK_API_KEY",
        "needs_sdk": False,
        "models": [],
    },
    {
        "id": "openai",
        "label": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "api": "openai",
        "key_env": "OPENAI_API_KEY",
        "needs_sdk": False,
        "models": [],
    },
    {
        "id": "openrouter",
        "label": "OpenRouter",
        "base_url": "https://openrouter.ai/api/v1",
        "api": "openai",
        "key_env": "OPENROUTER_API_KEY",
        "needs_sdk": False,
        "models": [],
    },
    {
        "id": "ollama",
        "label": "Ollama (local)",
        "base_url": "http://localhost:11434/v1",
        "api": "openai",
        "key_env": "",
        "needs_sdk": False,
        "models": [],
    },
    {
        "id": "custom",
        "label": "Custom endpoint",
        "base_url": "",
        "api": "openai",
        "key_env": "",
        "needs_sdk": False,
        "models": [],
    },
]

PROVIDER_BY_ID = {p["id"]: p for p in PROVIDERS}


def mask_secret(value: str) -> str:
    """A hint that identifies the token without being the token."""
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) <= 10:
        return "*" * len(value)
    return "%s...%s" % (value[:4], value[-4:])


def path_for(results_dir: str) -> str:
    return os.path.join(results_dir, SETTINGS_FILE)


def load(results_dir: str) -> dict:
    """Stored settings merged over the defaults. Never raises."""
    data = dict(DEFAULTS)
    try:
        with open(path_for(results_dir), "r", encoding="utf-8") as handle:
            stored = json.load(handle)
        if isinstance(stored, dict):
            for key, value in stored.items():
                if key in DEFAULTS:
                    data[key] = value
    except (OSError, ValueError):
        pass
    return data


def save(results_dir: str, data: dict) -> dict:
    """Write atomically, owner-readable only. Returns what was written."""
    clean = {k: v for k, v in data.items() if k in DEFAULTS}
    os.makedirs(results_dir, exist_ok=True)
    target = path_for(results_dir)
    handle, tmp = tempfile.mkstemp(dir=results_dir, prefix=".settings-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            json.dump(clean, out, indent=1, sort_keys=True)
        os.chmod(tmp, 0o600)  # the file may hold tokens
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return clean


def merge(current: dict, incoming: dict) -> dict:
    """Apply a partial update.

    A secret that is absent is left alone, so the dashboard can save the rest
    of the form without ever round-tripping the token through the browser.
    An explicit empty string clears it.
    """
    merged = dict(current)
    for key, value in (incoming or {}).items():
        if key not in DEFAULTS:
            continue
        if key in SECRET_FIELDS and value is None:
            continue
        if key == "wordlists":
            merged[key] = clean_wordlists(value)
            continue
        merged[key] = value
    return merged


def clean_wordlists(value) -> dict:
    """Keep only known lists, only when they hold something.

    An empty list is dropped rather than stored, so clearing a field in the
    panel is exactly the same thing as never having touched it: the built-in
    list comes back.
    """
    from .patterns import WORDLIST_FIELDS

    # A regular expression may legitimately end in a space; a glob or a
    # detector name never does, and a stray space there silently stops it
    # matching. So only the pattern list is kept verbatim.
    verbatim = ("rg_patterns",)

    out: dict = {}
    if not isinstance(value, dict):
        return out
    for name in WORDLIST_FIELDS:
        items = value.get(name)
        if not isinstance(items, (list, tuple)):
            continue
        cleaned = [
            str(v) if name in verbatim else str(v).strip()
            for v in items
            if str(v).strip()
        ]
        if cleaned:
            out[name] = cleaned
    return out


def public(data: dict) -> dict:
    """What the API is allowed to hand back: no secrets, only hints."""
    out = {k: v for k, v in data.items() if k not in SECRET_FIELDS}
    for field in SECRET_FIELDS:
        value = (data.get(field) or "").strip()
        out[field + "_set"] = bool(value)
        out[field + "_hint"] = mask_secret(value)
    return out


def scan_defaults(data: dict) -> dict:
    """The subset that seeds a ScanConfig. Secrets are deliberately absent."""
    keys = (
        "keywords", "custom_patterns", "wordlists",
        "max_repo_age_months", "max_repo_size_mb", "rescan_days",
        "max_findings_per_repo", "skip_forks", "skip_archived", "clone_depth",
        "use_trufflehog", "use_ripgrep",
        "clone_timeout", "trufflehog_timeout", "ripgrep_timeout",
        "delay_between_repos", "delay_between_accounts",
        "ai_triage", "ai_model", "ai_base_url", "ai_api", "ai_redact",
        "ai_max_findings", "ai_batch_size", "ai_timeout", "ai_system_prompt",
    )
    return {k: data[k] for k in keys if k in data}


def secrets(data: dict) -> dict:
    """The values that must travel beside a config, never inside it."""
    return {
        "github_token": (data.get("github_token") or "").strip(),
        "ai_key": (data.get("ai_key") or "").strip(),
    }


def apply_provider(data: dict) -> dict:
    """Fill base_url / api from the chosen provider, unless custom."""
    provider = PROVIDER_BY_ID.get(data.get("ai_provider") or "anthropic")
    if not provider or provider["id"] == "custom":
        return data
    data = dict(data)
    data["ai_base_url"] = provider["base_url"]
    data["ai_api"] = provider["api"]
    return data
