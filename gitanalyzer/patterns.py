"""Detection patterns, file filters and false-positive heuristics.

Everything in this module is data, not logic. Tune it for your own
organization: the point of an open-source scanner is that you can see
(and change) exactly what it looks for.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Ripgrep patterns — deliberately NOT secret detectors.
#
# TruffleHog already covers ~800 credential types with live verification.
# Ripgrep's job here is everything TruffleHog ignores: internal URLs, SaaS
# links, infrastructure hostnames and config key names. That is the material
# an attacker uses to map a company before touching a single credential.
# ---------------------------------------------------------------------------
# Rust regex, not Python: no look-around, and **never backslash-escape a quote
# inside a character class**. `[^\s\"']` is accepted by Python and by ripgrep 14+,
# and rejected as an unrecognized escape by the regex crate behind ripgrep 13 —
# which is what Debian stable and Ubuntu 22.04 install. One such pattern fails the
# whole combined regex, so the scan searches for nothing. Write `[^\s"']`; a
# quote needs no escape in a class. A test pins this.
RG_PATTERNS: list[str] = [
    # Google Docs / Drive / Sheets
    r"(?i)https://docs\.google\.com/(document|spreadsheets|presentation|forms)/d/[a-zA-Z0-9_\-]+",
    r"(?i)https://drive\.google\.com/(file|open|drive/folders)/[a-zA-Z0-9_\-]+",
    # Jira / Atlassian / Confluence
    r"(?i)https://[a-zA-Z0-9.\-]+\.atlassian\.net/(browse|jira|wiki|servicedesk|wiki/spaces)",
    # Notion
    r"(?i)https://www\.notion\.so/[a-zA-Z0-9\-]+",
    # Identity providers
    r"(?i)https://[a-zA-Z0-9.\-]+\.okta\.com",
    r"(?i)https://[a-zA-Z0-9.\-]+\.auth0\.com",
    # Internal / corp / staging hostnames
    r"(?i)https?://[a-zA-Z0-9.\-]+(\.internal\.|\.corp\.|\.staging\.|\.dev\.)[a-zA-Z0-9.\-]+",
    # Slack incoming webhooks
    r"(?i)https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
    # Firebase / App Engine
    r"(?i)https://[a-zA-Z0-9_\-]+\.firebaseio\.com",
    r"(?i)[a-zA-Z0-9_\-]+\.appspot\.com",
    # Database connection strings
    r"""(?i)(mongodb\+srv|mysql|postgresql|redis)://[^\s"']+""",
    # Hardcoded secrets in config files — quoted value, broad key vocabulary
    r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|access[_-]?token"
    r"|auth[_-]?token|client[_-]?secret|private[_-]?token|credentials?)\s*[:=]\s*"
    r"""["'][^"'\s]{8,80}["']""",
    # Same thing in dotenv / properties form, where the value is NOT quoted:
    #   INTERNAL_API_TOKEN=f3a9c2b8e1d47650aa93
    # Deliberately case-sensitive: an upper-case name is what makes this shape a
    # configured value rather than a line of code.
    r"^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]{1,40}_"
    r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|PWD|CREDENTIAL|CREDENTIALS|AUTH)"
    r"""[ \t]*=[ \t]*["']?[^\s"'#]{8,120}""",
    # SharePoint / OneDrive
    r"""(?i)https://[a-zA-Z0-9.\-]+\.sharepoint\.com/[^\s"']+""",
    # Observability dashboards
    r"""(?i)https://[a-zA-Z0-9.\-]+/(grafana|kibana|dashboard)/[^\s"']+""",
    # CI
    r"""(?i)https://[a-zA-Z0-9.\-]+/jenkins/[^\s"']+""",
    # Sentry DSN
    r"(?i)https://[a-f0-9]+@[a-zA-Z0-9.\-]+\.ingest\.sentry\.io/[0-9]+",
    # Catch-all URL — noisy on purpose, filtered and down-ranked later
    r"""(?i)https?://[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}[^\s"'<>)\]},]*""",
]

# ---------------------------------------------------------------------------
# File filters for ripgrep
# ---------------------------------------------------------------------------
INCLUDE_GLOBS: list[str] = [
    "*.env*", "*.yml", "*.yaml", "*.json", "*.xml", "*.properties",
    "*.cfg", "*.conf", "*.ini",
    "*.py", "*.js", "*.ts", "*.go", "*.java", "*.rb", "*.php", "*.cs",
    "*.swift", "*.kt",
    "*.sh", "*.bash", "*.sql", "*.tf", "*.tfvars",
    "Dockerfile*", "docker-compose*", "*.toml", "*.jsx", "*.tsx", "*.vue",
    "*.config", "*.plist", "*.gradle", "*.md", "*.txt", "*.rst",
    # Credential stores that routinely ship by accident
    "rclone.conf", ".npmrc", ".netrc", ".pgpass", ".docker/config.json",
    "*.csv", "*.pem", "*.key", "*.p12", "*.pfx",
    # AI devtool configs — a new and very productive class of leak
    "CLAUDE.md", "AGENTS.md", ".cursor/*.json", ".claude/*.json", "*.mcp.json",
    "appsettings.json", "appsettings.*.json",
]

EXCLUDE_GLOBS: list[str] = [
    "node_modules/", ".git/", "vendor/", "__pycache__/", ".gradle/",
    "build/", "dist/",
    "*.min.js", "*.min.css", "package-lock.json", "yarn.lock", "*.map",
    "*.png", "*.jpg", "*.gif", "*.svg", "*.woff*", "*.ttf", "*.ico",
    "*.pyc", "*.class", "*.o", "*.so", "*.dylib",
    # High-noise, low-signal paths learned from large-scale runs
    "forge-std/", "lib/forge-std/", "lib/openzeppelin-contracts/",
    "foundry.toml",
    "*.snap", "*.snapshot", "cassettes/",
    "_posts/", "blog/", "writeups/",
    "isolate_snapshot_data", "kernel_blob.bin",
    "*.wasm", "*.pb", "*.pb.go",
    "go.sum", "Cargo.lock", "pnpm-lock.yaml", "bun.lockb",
    "*.generated.*", "*.auto.*",
]

# ---------------------------------------------------------------------------
# Placeholder detection — the single biggest source of scanner noise
# ---------------------------------------------------------------------------
PLACEHOLDER_EXACT: set[str] = {
    "change_me", "changeme", "todo", "fixme", "your_api_key",
    "your_secret", "xxx", "placeholder", "dummy",
    "insert_your", "replace_me", "your_key_here",
    "password", "123456", "secret", "admin", "root",
    "example", "sample", "test", "demo", "default",
    "none", "null", "undefined", "n/a", "na",
    "your_token", "your_password", "your_key",
    "put_your_key_here", "enter_your_key",
    "replace_with_your", "add_your",
}

PLACEHOLDER_PREFIXES: list[str] = [
    "sk_test_", "pk_test_", "test_key_", "fake_", "dummy_",
    "example_", "sample_", "demo_", "test-", "fake-",
    "my_api_", "your_", "insert_", "replace_",
]

PLACEHOLDER_CONTAINS: list[str] = [
    "<your", "<insert", "<replace", "${", "{{", "%(", "<%=", "{%",
    "your-api", "your_api", "put-your", "put_your", "your_", "your-",
    "<connection-string>", "<token>", "<key>", "<secret>",
    "...",  # an elided value: `sk-ant-...`
    # The value is a reference to a secret, not the secret itself.
    "os.environ", "os.getenv", "getenv(", "process.env", "secrets.",
    "vault.", "config.get", "settings.", "env[", "env.get",
]

# Obvious filler: a long run of one character, or a counting sequence. This is
# matched against the whole value rather than as a substring, because a random
# credential can legitimately contain "abcdef" or "123456" somewhere inside it.
FILLER_RE = re.compile(
    r"^(?:(.)\1{5,}"
    r"|(?:abcdef|0123456789|123456789|qwerty|asdfgh)[a-z0-9]*)$",
    re.IGNORECASE,
)

# Public demo credentials that match every pattern and are worth nothing
KNOWN_FP_VALUES: set[str] = {
    "ftp://demo:password@test.rebex.net",
    "http://admin:admin@the-internet.herokuapp.com",
    "http://user:password@example.com",
    "https://user:password@localhost",
    "https://username:password@www.example.com",
    "https://abc:123@example.com",
    "http://user:password@example.com:8080",
    "https://user:password@vsphere.example.com",
}

# Public Infura keys embedded in every Foundry/forge-std project
KNOWN_FP_KEYS: set[str] = {
    "16a8be88795540b9b3903d8de0f7baa5",
    "6770454bc6ea42c58aac12978531b93f",
    "7a8769b798b642f6933f2ed52042bd70",
    "b1d3925804e74152b316ca7da97060d3",
    "b9794ad1ddf84dfb8c34d6bb5dca2001",
    "f4a0bdad42674adab5fc0ac077ffab2b",
}

# Paths that reliably produce throwaway private keys
FP_PRIVATE_KEY_PATHS: list[str] = [
    "tests/keys/", "test/keys/", "testdata/", "test_data/",
    "hack-the-box", "htb-", "ctf-", "ctf/",
    "docs/system/", "examples/",
]

# ---------------------------------------------------------------------------
# Detector value tiers (TruffleHog detector names, normalized)
# ---------------------------------------------------------------------------
LOW_VALUE_DETECTORS: set[str] = {
    "discordwebhook", "discord", "pubnubpublishkey", "pubnubsubscriptionkey",
    "pixabay", "rawg", "mockaroo", "pastebin", "theoddsapi",
    "disqus", "ipinfo", "ipstack", "weatherapi", "newsapi",
    "currencyfreaks", "exchangerate", "abstract", "apilayer",
}

HIGH_VALUE_DETECTORS: set[str] = {
    "aws", "cloudflareapitokens", "cloudflareapitokenv2", "cloudflareapitoken",
    "supabasetoken", "azure", "gcp",
    "privatekey", "stripe", "squareup", "square",
    "okta", "auth0", "gitlab",
    "npm", "pypi", "nuget", "dockerhub",
    "heroku", "vercel", "netlify",
}

# ---------------------------------------------------------------------------
# Finding categories
# ---------------------------------------------------------------------------
INTERESTING_TYPES: set[str] = {
    "google_docs", "jira", "notion", "okta", "auth0", "sharepoint",
    "slack", "internal_url", "dashboard", "ci_cd", "sentry", "firebase",
}

SECRET_TYPES: set[str] = {
    "aws_key", "github_token", "api_key", "private_key", "jwt",
    "db_credential", "hardcoded_secret", "cloud_credential",
    "package_token", "bot_token", "webhook", "payment_key",
    "credential_url", "ai_api_key", "ml_key", "blockchain_key", "search_key",
}

CREDENTIAL_URL_RE = re.compile(r"://[^:]+:[^@]+@")


# ---------------------------------------------------------------------------
# Editable word lists
#
# Every list above is a *default*, not a constant. A scan carries its own
# `Wordlists`, so the dashboard (or a config file) can replace any of them
# without editing this module. An empty or missing override means "use the
# built-in list", which is what keeps `results/.settings.json` small and makes
# "reset to built-in" a matter of clearing a field.
# ---------------------------------------------------------------------------
WORDLIST_FIELDS: tuple[str, ...] = (
    "rg_patterns",
    "include_globs",
    "exclude_globs",
    "placeholder_contains",
    "placeholder_exact",
    "placeholder_prefixes",
    "high_value_detectors",
    "low_value_detectors",
)

# Short descriptions, so the panel can explain each list without duplicating
# this knowledge in JavaScript.
WORDLIST_LABELS: dict[str, tuple[str, str]] = {
    "rg_patterns": (
        "ripgrep patterns",
        "Regular expressions searched in the working tree. Rust regex syntax "
        "(no lookahead). One per line; a broken line makes the whole scan fail.",
    ),
    "include_globs": (
        "Files scanned",
        "Only paths matching one of these globs are searched at all.",
    ),
    "exclude_globs": (
        "Files skipped",
        "Applied after the include list. This is where vendored code, lock "
        "files and build output get dropped.",
    ),
    "placeholder_contains": (
        "Dropped if the value contains",
        "Substring match on the matched value — the main noise filter.",
    ),
    "placeholder_exact": (
        "Dropped if the value equals",
        "Exact match, lower-cased. Safe for short words that would be far too "
        "aggressive as substrings.",
    ),
    "placeholder_prefixes": (
        "Dropped if the value starts with",
        "Prefix match, lower-cased.",
    ),
    "high_value_detectors": (
        "Detectors scored up",
        "TruffleHog detector names. A verified hit on one of these is scored "
        "100 — reserve it for credentials that matter.",
    ),
    "low_value_detectors": (
        "Detectors scored down",
        "TruffleHog detector names worth -40. Free-tier API keys live here.",
    ),
}


def normalize_detector(detector: str) -> str:
    """Detector names are compared without case, spaces or separators."""
    return (detector or "").lower().replace(" ", "").replace("-", "").replace("_", "")


def builtin_wordlists() -> dict[str, list[str]]:
    """The shipped lists, in the order the panel should show them."""
    return {
        "rg_patterns": list(RG_PATTERNS),
        "include_globs": list(INCLUDE_GLOBS),
        "exclude_globs": list(EXCLUDE_GLOBS),
        "placeholder_contains": list(PLACEHOLDER_CONTAINS),
        "placeholder_exact": sorted(PLACEHOLDER_EXACT),
        "placeholder_prefixes": list(PLACEHOLDER_PREFIXES),
        "high_value_detectors": sorted(HIGH_VALUE_DETECTORS),
        "low_value_detectors": sorted(LOW_VALUE_DETECTORS),
    }


@dataclass
class Wordlists:
    """The lists one scan actually uses."""

    rg_patterns: list[str] = field(default_factory=lambda: list(RG_PATTERNS))
    include_globs: list[str] = field(default_factory=lambda: list(INCLUDE_GLOBS))
    exclude_globs: list[str] = field(default_factory=lambda: list(EXCLUDE_GLOBS))
    placeholder_contains: list[str] = field(default_factory=lambda: list(PLACEHOLDER_CONTAINS))
    placeholder_exact: list[str] = field(default_factory=lambda: sorted(PLACEHOLDER_EXACT))
    placeholder_prefixes: list[str] = field(default_factory=lambda: list(PLACEHOLDER_PREFIXES))
    high_value_detectors: list[str] = field(default_factory=lambda: sorted(HIGH_VALUE_DETECTORS))
    low_value_detectors: list[str] = field(default_factory=lambda: sorted(LOW_VALUE_DETECTORS))

    def __post_init__(self) -> None:
        # Pre-computed lookups. Detector names are normalized on both sides so
        # a hand-typed "Cloudflare API Token" matches "cloudflareapitoken".
        self.exact_set = {str(v).strip().lower() for v in self.placeholder_exact if str(v).strip()}
        self.prefix_list = [str(v).strip().lower() for v in self.placeholder_prefixes if str(v).strip()]
        self.contains_list = [str(v).strip().lower() for v in self.placeholder_contains if str(v).strip()]
        self.high_set = {normalize_detector(v) for v in self.high_value_detectors if str(v).strip()}
        self.low_set = {normalize_detector(v) for v in self.low_value_detectors if str(v).strip()}

    @classmethod
    def resolve(cls, overrides: dict | None = None) -> "Wordlists":
        """Built-in lists with any non-empty override applied."""
        data = builtin_wordlists()
        for name, value in (overrides or {}).items():
            if name not in WORDLIST_FIELDS or not isinstance(value, (list, tuple)):
                continue
            cleaned = [str(v) for v in value if str(v).strip()]
            if cleaned:  # an empty list means "use the built-in one"
                data[name] = cleaned
        return cls(**data)

    def diff(self) -> dict[str, list[str]]:
        """Only the lists that differ from the built-in ones."""
        builtin = builtin_wordlists()
        return {
            name: getattr(self, name)
            for name in WORDLIST_FIELDS
            if getattr(self, name) != builtin[name]
        }


DEFAULT_WORDLISTS = Wordlists()


def is_placeholder(value: str, lists: "Wordlists | None" = None) -> bool:
    """True when a match is template text rather than a real value."""
    wl = lists or DEFAULT_WORDLISTS
    v = value.strip().strip("'\"").lower()
    if len(v) < 6:
        return True
    if v in wl.exact_set:
        return True
    if any(v.startswith(p) for p in wl.prefix_list):
        return True
    if any(c in v for c in wl.contains_list):
        return True
    if v in KNOWN_FP_VALUES or v in KNOWN_FP_KEYS:
        return True
    if FILLER_RE.match(v):
        return True
    # `KEY=xxxxxxxx` style redaction, wherever the value sits on the line
    if re.search(r"(?:x{8,}|0{10,}|\*{6,}|\.{6,})", v):
        return True
    return False


def build_ripgrep_pattern(
    extra: list[str] | None = None, lists: "Wordlists | None" = None
) -> str:
    """Combine the configured and user patterns into one alternation."""
    wl = lists or DEFAULT_WORDLISTS
    patterns = list(wl.rg_patterns) + list(extra or [])
    return "|".join("(%s)" % p for p in patterns)
