# Security policy

0xGitAnalyzer is a security tool that clones untrusted repositories, runs external
binaries over them and serves the results on a local web page. A bug in any of those
three places can turn a scan into a compromise, so vulnerability reports are welcome
and taken seriously.

## Reporting a vulnerability

**Report privately. Do not open a public issue.**

Use GitHub's private reporting: the repository's **Security** tab →
**Report a vulnerability**. That opens a draft advisory only the maintainers can see,
and it is where the fix and the CVE, if any, are coordinated.

If GitHub private reporting is unavailable to you, contact OliveX Security through
<https://www.olivex.io> and ask for a private channel before sending any detail.

Please include:

- what an attacker controls (a repository they own, a pattern typed into the panel, a
  request to the local API, a crafted scan file)
- the version or commit you tested
- the smallest reproduction you have, and what you expected instead

Expect a first reply within **5 business days**. We will tell you whether the report
is accepted, what the fix looks like, and when it ships. You are credited in the
advisory unless you prefer otherwise. We do not pay bounties for this project.

Please give us a reasonable window to ship a fix before publishing — 90 days is the
usual one, shorter if the issue is already being exploited.

## Supported versions

This project is pre-1.0: only the latest commit on `main` is supported. Fixes ship in
a new release rather than as patches to an older tag.

## In scope

Anything that lets a scanned repository, a crafted scan file or a local web page reach
further than it should:

- **Command injection or argument injection** through a repository name, a clone URL,
  a file path or a user-supplied pattern reaching `git`, `rg` or `trufflehog`
- **Path traversal** — writing or deleting outside the results directory, including
  through a scan id in an API path or a file path inside a scan file
- **Credential leakage** — a stored token reaching a scan file, an export, the API
  response, a log line or a screenshot. The API must only ever return a masked hint
- **SSRF or request forgery** from the local dashboard, including DNS rebinding
  against the bound port
- **XSS or HTML injection** in the dashboard or in an exported report, where the
  injected content comes from a scanned repository — a finding's preview text is
  attacker-controlled by definition
- **Code execution** from parsing a scan file, a settings file or a scanner's output
- A **scan that silently reports nothing**: a pattern or glob override that makes the
  scan fail open while the report still says "completed" is a security bug here, not a
  cosmetic one

## Not in scope

These are documented properties of the tool, not vulnerabilities:

- **The dashboard has no authentication.** It binds to `127.0.0.1`, rejects
  non-loopback `Host` headers, and prints a warning if you bind it anywhere else.
  Anyone who can reach the port can read every finding. Use an SSH tunnel.
- **Scan files and exports contain real credential material.** That is their purpose.
  Treat the results directory like the secrets it holds.
- **The token is written to `<results>/.settings.json` with mode 0600** when you type
  it into the panel. Leave the field empty and use `GITHUB_TOKEN` if you would rather
  keep secrets out of files; the environment wins over the stored value.
- **Cloned code is executed by nothing, but it is written to a temp directory** before
  being scanned and deleted afterwards. Scanning a repository is not sandboxing it.
- Findings that are wrong — a false positive, or a secret the scanners miss. Those are
  ordinary bugs: open an issue, or better, a PR with a test.
- Anything requiring an attacker to already have local code execution as the user
  running the scan.

## Using this tool

Scanning accounts you are not authorized to assess may be illegal where you are. That
is your responsibility, not the tool's. Reports about *being scanned* by someone
else's copy of 0xGitAnalyzer belong with that person, not here.
