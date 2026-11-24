"""Scan configuration."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class ScanConfig:
    """Everything that shapes a deep scan.

    Defaults are tuned for a first useful run on a mid-size account list:
    recent repos only, forks and archives skipped, and a per-repo finding cap
    so one noisy monorepo cannot drown the report.
    """

    accounts: list[str] = field(default_factory=list)

    # Repo selection
    max_repo_age_months: int = 24
    max_repo_size_mb: int = 500
    skip_forks: bool = True
    skip_archived: bool = True
    rescan_days: int = 7

    # Matching
    custom_patterns: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    max_findings_per_repo: int = 200
    # Overrides for the lists in patterns.py, editable from the dashboard.
    # Only the lists that were actually changed are stored; anything absent or
    # empty falls back to the built-in list, so a scan file stays readable.
    wordlists: dict = field(default_factory=dict)

    # Timeouts (seconds)
    clone_timeout: int = 120
    trufflehog_timeout: int = 300
    ripgrep_timeout: int = 600

    # Pacing
    delay_between_repos: float = 1.5
    delay_between_accounts: float = 1.0

    # Scanners
    use_trufflehog: bool = True
    use_ripgrep: bool = True
    clone_depth: int = 0  # 0 = full history (TruffleHog needs it); >0 = shallow

    # Optional AI triage. Any provider: ai_base_url + ai_api pick the endpoint
    # and the wire format ("anthropic" or "openai"); empty means Anthropic.
    ai_triage: bool = False
    ai_model: str = "claude-opus-5-5"
    ai_base_url: str = ""
    ai_api: str = ""  # "" = infer from ai_base_url
    ai_key_env: str = ""  # "" = the provider's usual variable
    ai_timeout: int = 120
    ai_system_prompt: str = ""  # "" = the built-in triage prompt
    ai_batch_size: int = 15
    ai_max_findings: int = 150
    ai_redact: bool = True

    label: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanConfig":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in (data or {}).items() if k in known})
