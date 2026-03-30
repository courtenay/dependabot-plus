---
name: DependabotPlus overview
description: Project goals, architecture decisions, and supported ecosystems for the DependabotPlus supply chain security tool
type: project
---

DependabotPlus is a Claude skill/toolset that analyses Dependabot PRs for malicious supply chain attacks.

**Architecture:**
- Two-phase loop: (1) fetch queue of Dependabot PRs to a file, (2) process queued items
- Runs on a loop, dependabot runs weekly
- Fresh Docker container per dependency update

**Ecosystems:** npm, Ruby gems, Linux packages

**Analysis layers:**
- Static: diff library source between installed and updated version, Claude analyses for suspicious patterns
- Dynamic: Docker sandbox with no network egress (logged), canary env vars, canary files

**Why:** Third-party libraries are a major supply chain attack vector — malware exfiltrating secrets, scanning files, running crypto miners.

**How to apply:** All design decisions should prioritize security and isolation. Each ecosystem may need its own sandbox setup.
