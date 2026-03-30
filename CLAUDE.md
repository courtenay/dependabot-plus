# CLAUDE.md

## Project overview

DependabotPlus analyses Dependabot PRs for supply chain attacks. Two-phase pipeline: fetch a queue of PRs, then process each through static analysis (Claude) and dynamic analysis (Docker sandbox with canary traps).

## Commands

```bash
# Run unit tests (fast, no Docker)
pytest -m "not integration"

# Run integration tests (requires Docker)
pytest -m integration

# Run all tests
pytest
```

## Code layout

- `dependabot_plus/cli.py` — argparse entrypoint with fetch/process/run subcommands
- `dependabot_plus/queue/` — fetches Dependabot PRs via `gh`, parses titles, manages JSON queue
- `dependabot_plus/analysis/source_diff.py` — downloads old/new package versions and diffs them
- `dependabot_plus/analysis/claude_review.py` — sends diffs to `claude -p` for security review
- `dependabot_plus/sandbox/canary.py` — generates fake secrets (env vars + credential files)
- `dependabot_plus/sandbox/dockerfiles/` — per-ecosystem Dockerfiles with inotifywait monitoring
- `dependabot_plus/sandbox/runner.py` — runs Docker containers with `--network=none` and canary traps
- `dependabot_plus/report/github.py` — posts findings as markdown PR comments via `gh`
- `tests/fixtures/malicious_packages/` — test fixture packages (file-scanner, env-stealer, clean-pkg)

## Conventions

- Python 3.9+ compatible; use `from __future__ import annotations` in all modules
- External tools called via subprocess: `gh`, `docker`, `claude`, `npm`, `gem`, `diff`
- Tests use pytest with `unittest.mock` for subprocess mocking
- Integration tests are marked `@pytest.mark.integration` and require Docker
- Queue file is simple JSON (not a database)
- Canary tokens use `CANARY-{uuid4}` format for easy grepping
