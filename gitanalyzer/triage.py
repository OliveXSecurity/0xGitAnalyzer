"""Optional AI triage of findings.

Why this exists: a deep scan of a few dozen accounts produces thousands of
matches, and the expensive part of the work is not finding them, it is
deciding which twenty are real. That judgement is exactly what an LLM is
good at — and it is also why defenders need to run this kind of tooling
themselves: the same leverage is already available to whoever is scanning
them from the outside.

This step is OFF by default. When enabled it sends finding metadata
(repo, file path, pattern type and a short code excerpt) to a model API.
With --ai-redact (the default) credential values are masked before they
leave the machine. Read `redact()` below before enabling it on customer
data.

Any provider works. Two wire formats are supported:

  anthropic   the Anthropic API, or anything that speaks its shape
              (Kimi/Moonshot and DeepSeek both publish one).
              Needs:  pip install "gitanalyzer[ai]"
  openai      the /chat/completions shape, which nearly everything else
              speaks: DeepSeek, OpenRouter, Groq, vLLM, Ollama, LM Studio.
              Needs nothing — it is plain stdlib urllib.

The format is inferred from --ai-base-url and can be forced with --ai-api.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

from .config import ScanConfig
from .scoring import classify_severity

SYSTEM_PROMPT = """You are a security engineer triaging the output of a secret scanner \
that ran against public GitHub repositories belonging to an organization's employees.

For each finding decide whether it represents a real exposure of that \
organization's data or infrastructure.

Judge like a reviewer who has to defend the verdict:
- A live, org-owned credential or an internal hostname is a true positive.
- A placeholder, a public demo key, documentation, test fixture or a third-party \
  sample is a false positive.
- Anything you cannot decide from the excerpt is needs_review, not a guess.
- Credential values may be masked; judge the context, not the masked characters.

Reply with a JSON array and nothing else. One object per finding, same order:
[{"id": <int>, "verdict": "true_positive"|"false_positive"|"needs_review",
  "confidence": 0-100, "reason": "<one short sentence>"}]"""

def system_prompt(config: ScanConfig) -> str:
    """The triage instructions. Overridable from the dashboard, because what
    counts as a true positive is organisation-specific."""
    return (config.ai_system_prompt or "").strip() or SYSTEM_PROMPT


_SECRETISH = re.compile(
    r"""([A-Za-z0-9_\-]{0,24}(?:key|token|secret|password|passwd|pwd|auth)[A-Za-z0-9_\-]*\s*[:=]\s*)"""
    r"""(["']?)([^\s"']{6,})(["']?)""",
    re.IGNORECASE,
)


def mask(value: str) -> str:
    """Keep the shape of a secret, drop the secret."""
    if len(value) <= 8:
        return "*" * len(value)
    return "%s%s%s" % (value[:3], "*" * (len(value) - 6), value[-3:])


def redact(text: str) -> str:
    """Mask credential-looking values and URL passwords in an excerpt."""
    text = _SECRETISH.sub(lambda m: m.group(1) + m.group(2) + mask(m.group(3)) + m.group(4), text)
    text = re.sub(
        r"(://[^:/\s]+:)([^@\s]+)(@)",
        lambda m: m.group(1) + mask(m.group(2)) + m.group(3),
        text,
    )
    return text


# ---------------------------------------------------------------------------
# Provider resolution
# ---------------------------------------------------------------------------

# Only Anthropic's own endpoint takes the Anthropic-specific request knobs
# (`output_config`, the server-side fallback beta). A compatible third-party
# endpoint answers 400 to them, so they are sent nowhere else.
ANTHROPIC_HOSTS = ("api.anthropic.com",)

FALLBACK_BETA = "server-side-fallback-2026-07-01"


@dataclass
class Provider:
    """Where triage requests go, and in which shape."""

    api: str  # "anthropic" | "openai"
    base_url: str  # "" means the SDK default
    key: str
    key_env: str
    native: bool  # Anthropic's own endpoint

    def describe(self) -> str:
        return "%s (%s API, key from %s)" % (
            self.base_url or "https://api.anthropic.com",
            self.api,
            self.key_env,
        )


def infer_api(base_url: str) -> str:
    """Guess the wire format from the endpoint. Anthropic-compatible URLs
    conventionally say so in the path (`.../anthropic`)."""
    if not base_url:
        return "anthropic"
    return "anthropic" if "anthropic" in base_url.lower() else "openai"


def key_env_candidates(config: ScanConfig, api: str) -> list[str]:
    """Environment variables to read the API key from, in order."""
    names = []
    if config.ai_key_env:
        names.append(config.ai_key_env)
    names.append("GITANALYZER_AI_KEY")
    if api == "anthropic":
        names.append("ANTHROPIC_API_KEY")
    else:
        names += ["OPENAI_API_KEY", "AI_API_KEY", "ANTHROPIC_API_KEY"]
    seen, ordered = set(), []
    for name in names:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def resolve_provider(config: ScanConfig, api_key: str = "") -> Provider:
    """Work out the endpoint, wire format and key.

    `api_key` is a key handed over directly (the dashboard settings panel).
    It wins over the environment, because someone typed it on purpose.
    """
    base = (config.ai_base_url or os.environ.get("ANTHROPIC_BASE_URL") or "").strip().rstrip("/")
    api = (config.ai_api or "").strip().lower() or infer_api(base)
    if api not in ("anthropic", "openai"):
        raise RuntimeError("unknown --ai-api %r (use 'anthropic' or 'openai')" % api)

    names = key_env_candidates(config, api)
    key, key_env = "", names[0]
    if (api_key or "").strip():
        key, key_env = api_key.strip(), "settings"
    else:
        for name in names:
            value = os.environ.get(name)
            if value:
                key, key_env = value, name
                break

    native = api == "anthropic" and (not base or any(h in base for h in ANTHROPIC_HOSTS))
    return Provider(api=api, base_url=base, key=key, key_env=key_env, native=native)


# ---------------------------------------------------------------------------
# The two clients
# ---------------------------------------------------------------------------


def _call_anthropic(provider: Provider, config: ScanConfig, payload: str) -> tuple[str, str]:
    """Returns (text, refusal_reason). An empty reason means the model answered."""
    import anthropic

    client = anthropic.Anthropic(api_key=provider.key, base_url=provider.base_url or None)
    kwargs = dict(
        model=config.ai_model,
        max_tokens=4000,
        system=system_prompt(config),
        messages=[{"role": "user", "content": payload}],
    )

    if provider.native:
        # Triage payloads are, by construction, leaked credentials and internal
        # hostnames — exactly the shape a safety classifier may decline. A
        # server-side fallback re-runs the batch on another model instead of
        # losing it. Both knobs are Anthropic-only; see ANTHROPIC_HOSTS.
        kwargs["output_config"] = {"effort": "low"}
        try:
            response = client.beta.messages.create(
                betas=[FALLBACK_BETA], fallbacks="default", **kwargs
            )
        except (TypeError, anthropic.BadRequestError, anthropic.NotFoundError):
            response = client.messages.create(**kwargs)
    else:
        response = client.messages.create(**kwargs)

    if getattr(response, "stop_reason", None) == "refusal":
        details = getattr(response, "stop_details", None)
        return "", str(getattr(details, "category", None) or "refusal")

    return "".join(b.text for b in response.content if getattr(b, "type", "") == "text"), ""


def chat_completions_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def parse_openai_response(data: dict) -> tuple[str, str]:
    """Pull the assistant text out of a /chat/completions body."""
    choice = (data.get("choices") or [{}])[0]
    if choice.get("finish_reason") == "content_filter":
        return "", "content_filter"
    content = (choice.get("message") or {}).get("content")
    if isinstance(content, list):  # some gateways return content blocks
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content or "", ""


def _call_openai(provider: Provider, config: ScanConfig, payload: str) -> tuple[str, str]:
    """/chat/completions over stdlib urllib — no SDK, no dependency."""
    body = json.dumps(
        {
            "model": config.ai_model,
            "max_tokens": 4000,
            "messages": [
                {"role": "system", "content": system_prompt(config)},
                {"role": "user", "content": payload},
            ],
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        chat_completions_url(provider.base_url),
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % provider.key,
            "User-Agent": "gitanalyzer",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=config.ai_timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise RuntimeError("HTTP %s from %s — %s" % (exc.code, provider.base_url, detail)) from exc

    return parse_openai_response(data)


def _run_batch(provider: Provider, config: ScanConfig, payload: str) -> tuple[str, str]:
    if provider.api == "anthropic":
        return _call_anthropic(provider, config, payload)
    return _call_openai(provider, config, payload)


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------


def _candidates(findings: list[dict], limit: int) -> list[dict]:
    """Triage the findings a human would read first."""
    ranked = sorted(
        findings,
        key=lambda f: (
            0 if f.get("category") == "secret" else 1 if f.get("company_match") else 2,
            -f.get("score", 0),
        ),
    )
    return ranked[:limit]


def _payload(batch: list[dict], do_redact: bool) -> str:
    rows = []
    for index, finding in enumerate(batch):
        preview = finding.get("preview", "")[:280]
        pattern = finding.get("pattern", "")[:160]
        if do_redact:
            preview = redact(preview)
            pattern = redact(pattern)
        rows.append(
            {
                "id": index,
                "repo": finding.get("repo", ""),
                "file": finding.get("file", ""),
                "line": finding.get("line", 0),
                "scanner": finding.get("scanner", ""),
                "detector": finding.get("detector", ""),
                "live_verified": bool(finding.get("verified")),
                "type": finding.get("finding_type", ""),
                "heuristic_score": finding.get("score", 0),
                "match": pattern,
                "excerpt": preview,
            }
        )
    return json.dumps(rows, ensure_ascii=False, indent=1)


def _parse(text: str) -> list[dict]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-z]*\n|\n```$", "", text).strip()
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1:
        return []
    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def triage_findings(
    findings: list[dict],
    config: ScanConfig,
    log: Callable[[str], None],
    api_key: str = "",
) -> None:
    """Annotate findings in place with `ai_verdict`, `ai_confidence`, `ai_reason`."""
    provider = resolve_provider(config, api_key)

    if not provider.key:
        raise RuntimeError(
            "no API key — set one in the dashboard, or export one of: %s"
            % ", ".join(key_env_candidates(config, provider.api))
        )

    if provider.api == "anthropic":
        try:
            import anthropic  # noqa: F401
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                'install the extra: pip install "gitanalyzer[ai]" — '
                "or use --ai-api openai, which needs no SDK"
            ) from exc

    batch_size = max(1, config.ai_batch_size)
    targets = _candidates(findings, config.ai_max_findings)
    if not targets:
        return

    log(
        "  triaging %d findings in batches of %d (model %s via %s, redaction %s)"
        % (
            len(targets),
            batch_size,
            config.ai_model,
            provider.describe(),
            "on" if config.ai_redact else "OFF",
        )
    )

    reviewed = 0
    for offset in range(0, len(targets), batch_size):
        batch = targets[offset : offset + batch_size]
        try:
            text, refusal = _run_batch(provider, config, _payload(batch, config.ai_redact))
        except Exception as exc:  # noqa: BLE001 - never let triage kill a scan
            log("  triage batch failed: %s" % exc)
            continue

        if refusal:
            log("  triage batch declined by the model (%s); heuristic scores kept" % refusal)
            continue

        for verdict in _parse(text):
            try:
                index = int(verdict.get("id", -1))
            except (TypeError, ValueError):
                continue
            if not 0 <= index < len(batch):
                continue
            finding = batch[index]
            label = str(verdict.get("verdict", "needs_review"))
            finding["ai_verdict"] = label
            finding["ai_confidence"] = int(verdict.get("confidence", 0) or 0)
            finding["ai_reason"] = str(verdict.get("reason", ""))[:300]

            # A confident false positive drops out of the important view;
            # a confirmed one is promoted. Keep what the heuristic said first:
            # without it there is no way to see where the two signals disagree,
            # and no way to undo the model's opinion.
            finding.setdefault("heuristic_score", finding.get("score", 0))
            finding.setdefault("heuristic_severity", finding.get("severity", ""))

            if label == "false_positive" and finding["ai_confidence"] >= 70:
                finding["score"] = max(0, finding.get("score", 0) - 40)
            elif label == "true_positive" and finding["ai_confidence"] >= 70:
                finding["score"] = min(100, finding.get("score", 0) + 15)
            finding["severity"] = classify_severity(finding["score"])
            reviewed += 1

    log("  triage complete: %d findings annotated" % reviewed)
