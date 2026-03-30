# DependabotPlus

Security analysis tool for Dependabot PRs. Detects supply chain attacks by combining static code review (via Claude) with dynamic sandbox analysis (via Docker).

## What it does

1. **Fetches** open Dependabot PRs from a GitHub repo
2. **Diffs** the library source between old and new versions
3. **Static analysis** — sends the diff to Claude to look for suspicious patterns (env var exfiltration, file scanning, obfuscated payloads, crypto miners)
4. **Dynamic analysis** — installs the package in an isolated Docker container with:
   - `--network=none` (all egress blocked)
   - Canary environment variables (fake AWS keys, GitHub tokens, etc.)
   - Canary credential files (~/.ssh/id_rsa, ~/.aws/credentials, etc.) monitored by `inotifywait`
5. **Reports** findings back as a comment on the PR

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
├── sandbox/            # Docker sandbox: canary traps, Dockerfiles, runner
└── report/             # GitHub PR comment reporting
```
