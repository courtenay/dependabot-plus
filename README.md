# DependabotPlus

Security analysis tool for Dependabot PRs. Detects supply chain attacks by combining static code review (via Claude) with dynamic sandbox analysis (via Docker).

## What it does

1. **Fetches** open Dependabot PRs from a GitHub repo
2. **Diffs** the library source between old and new versions
3. **Static analysis** — sends the diff to Claude to look for suspicious patterns (env var exfiltration, file scanning, obfuscated payloads, crypto miners)
4. **Dynamic analysis** — pre-downloads the package (network on, no code run), then installs/rebuilds it offline from that copy in an isolated Docker container with canary environment variables (fake AWS keys, GitHub tokens, etc.) and canary credential files (`~/.ssh/id_rsa`, `~/.aws/credentials`, etc.) watched by `inotifywait`. What the sandbox does depends on `--mode` (below).
5. **Scores** the result and **reports** it as a PR comment. `deps-vetted` is only added when risk is LOW **and** backed by deterministic evidence (see "How risk is decided").

## Sandbox modes

`--mode` is `monitor` (default) or `strict`. They are not the same thing:

| | `monitor` (default) | `strict` |
|---|---|---|
| Container network | **On** (default Docker bridge). Install scripts can reach the internet. | **Off** (`--network=none`). Nothing can leave. |
| Network detection | `tcpdump` inside the container records DNS lookups, outbound TCP connects and plaintext HTTP. Events are tagged `install` or `post_install` (after the install command exited). | None needed; a blocked attempt shows up as `EAI_AGAIN`/`ENOTFOUND`/`ECONNREFUSED` in the install log and is scored MEDIUM. |
| Exfiltration | **Not prevented.** A payload can send data out before we flag it. HTTPS bodies are not inspected (we see the DNS lookup and TCP connect only). | Prevented. |
| Canary reads, `sudo`, writes | Detected | Detected |

Use `strict` when a leak is unacceptable; use `monitor` when you want to see where a package tries to connect. Neither mode runs against real credentials: all secrets in the container are canaries.

### What the sandbox detects

- **Canary file reads** (`~/.ssh`, `~/.aws`, `~/.npmrc`, ...): HIGH.
- **`sudo` attempts**: HIGH.
- **File writes/creates outside the install dir and tmp** (shell rc files, `~/.ssh`, `~/.config`, other dotfiles, cron, `/etc`, other packages' directories): HIGH. Allowed: `/sandbox`, `/tmp`, `/var/tmp`, `/var/log`, and each ecosystem's own cache/install paths. This is implemented by an inotify detector behind the `RuntimeDetector` interface (`dependabot_plus/sandbox/detectors.py`) so a Falco-backed detector can replace it later.
- **Egress to a host outside the ecosystem's registry allowlist** (DNS lookup, TCP/HTTPS connect, or HTTP): MEDIUM during install, HIGH after install scripts finished. HTTP `POST/PUT/PATCH` anywhere: HIGH. The allowlist is explicit and fails closed: a TCP connect to an IP counts as allowed only if every hostname seen resolving to it is allowlisted. Allowlist: npm `registry.npmjs.org`; gems `rubygems.org`/`index.rubygems.org`/`api.rubygems.org`; pip `pypi.org`/`files.pythonhosted.org`; Go `proxy.golang.org`/`sum.golang.org`; apt `deb.debian.org`/`security.debian.org`. Add mirrors with `DEPENDABOT_PLUS_REGISTRY_MIRRORS=host1,host2`. Packages that legitimately download at install time (for example native-addon headers) will be flagged; that is intended.

### Limits

- `monitor` mode does not block egress and does not decrypt TLS.
- Go, Docker and GitHub Actions have no sandbox step (no install scripts), so an LLM-only LOW is **not** enough for `deps-vetted`. Go is vetted statically by default (`--static-vetted go`): it needs a completed source scan (binary and auto-run scans) **and** a clean `go mod download` verification against sum.golang.org, which is an independent check; a checksum mismatch is HIGH and a failed or incomplete download is never vetted. Docker and GitHub Actions still need a human review. Override with `--static-vetted go,docker,github_actions` to widen it, or `--static-vetted ""` to disable static vetting entirely.
- Go modules are verified against `sum.golang.org` (no `GONOSUMDB`); a checksum mismatch is HIGH.

## How risk is decided

Deterministic signals (sandbox, runtime detectors, egress, binary and auto-run scans, checksum verification) set a floor. The `claude -p` verdict can **raise** risk above that floor but never lower it. The diff is passed to Claude fenced as untrusted data, because it is attacker-controlled. `deps-vetted` requires LOW risk plus a clean sandbox run (or, for Go by default, a completed source scan plus clean sumdb verification; see `--static-vetted`); otherwise the PR comment says a human must review.

## Supported ecosystems

- npm
- Ruby gems
- Linux packages (apt)

## Usage

```bash
# Fetch Dependabot PRs into a queue file
python -m dependabot_plus.cli --repo owner/repo fetch

# Process all queued PRs through the analysis pipeline
python -m dependabot_plus.cli --repo owner/repo process

# Process a single PR
python -m dependabot_plus.cli --repo owner/repo process --pr 42

# Full pipeline (fetch + process)
python -m dependabot_plus.cli --repo owner/repo run
```

## Requirements

- Python 3.9+
- Docker
- [GitHub CLI](https://cli.github.com/) (`gh`) authenticated
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) (`claude`)

## Development

```bash
# Install dev dependencies
pip install pytest

# Run unit tests (fast, no Docker needed)
pytest -m "not integration"

# Run integration tests (requires Docker)
pytest -m integration

# Run everything
pytest
```

## Architecture

```
dependabot_plus/
├── cli.py              # CLI entrypoint (fetch/process/run subcommands)
├── queue/              # PR fetching and queue management
├── analysis/           # Source diffing and Claude static review
├── risk.py             # Risk policy: deterministic floor, LLM can only raise, vetting rule
├── sandbox/            # Docker sandbox: canary traps, egress allowlist, runtime detectors, runner
└── report/             # GitHub PR comment reporting
```
