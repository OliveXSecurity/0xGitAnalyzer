# Contributing

Thanks for taking a look.

## The most useful contributions

**Pattern and scoring fixes.** `patterns.py` and `scoring.py` encode what counts as a
real exposure. They were tuned on a particular set of stacks and they will be wrong on
yours. If a rule produces noise, or misses something obvious, that is a bug worth a PR:

- a placeholder format that slips through `is_placeholder()`
- a vendored dependency that fills reports with junk (add it to `EXCLUDE_GLOBS`)
- a file or detector that deserves a different score
- a SaaS or infrastructure URL shape worth matching

Please include a one-line example of the match in the PR description.

## Ground rules

- **No new runtime dependencies.** The tool runs on a fresh machine with Python, git,
  ripgrep and TruffleHog. The Anthropic SDK stays an optional extra.
- **No credentials, hostnames, company names or real findings in commits**, including
  in test fixtures and screenshots. Scrub before you push.
- **Nothing that writes.** This scanner clones and reads. A feature that posts, opens
  an issue, or contacts a discovered service does not belong here.
- Keep the dashboard build-free: plain HTML, CSS and JS in `gitanalyzer/web/`.

## Development

```bash
pip install -e ".[ai]"
gitanalyzer doctor

python -m unittest discover -s tests -v   # needs git and ripgrep; no network
python -m compileall gitanalyzer

gitanalyzer scan octocat --max-age 0 --cooldown 0   # small, public, harmless
```

A pattern or scoring PR should come with a test in `tests/`: those rules decide what a
scan reports, so a regression in them is silent. `tests/test_patterns.py` runs the real
`rg` binary — a regex that works in Python but not in Rust is worthless here.

## Reporting a security issue

See [SECURITY.md](SECURITY.md). Short version: report it privately through GitHub's
**Security → Report a vulnerability**, not as a public issue.
