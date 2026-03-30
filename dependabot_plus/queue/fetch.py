from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from dependabot_plus.queue.models import Ecosystem, QueueItem, load_queue, save_queue

# Dependabot PR title patterns:
#   "Bump lodash from 4.17.20 to 4.17.21"
#   "Bump the pip group across 1 directory with 2 updates"
#   "Update nokogiri requirement from ~> 1.13 to ~> 1.14"
#   "Bump lodash from 4.17.20 to 4.17.21 in /subdir"
_BUMP_RE = re.compile(
    r"^(?:Bump|Update)\s+(.+?)\s+(?:requirement\s+)?from\s+~?>?\s*(\S+)\s+to\s+~?>?\s*(\S+)",
    re.IGNORECASE,
)

# Ecosystem hints from the PR body or labels
_ECOSYSTEM_KEYWORDS: dict[str, Ecosystem] = {
    "npm_and_yarn": Ecosystem.NPM,
    "npm": Ecosystem.NPM,
    "bundler": Ecosystem.GEM,
    "rubygems": Ecosystem.GEM,
    "pip": Ecosystem.APT,  # close enough for now
    "docker": Ecosystem.APT,
    "github_actions": Ecosystem.APT,
    "apt": Ecosystem.APT,
}


def parse_pr_title(title: str) -> tuple[str, str, str] | None:
    """Extract (package_name, old_version, new_version) from a Dependabot PR title."""
    m = _BUMP_RE.match(title)
    if not m:
        return None
    return m.group(1).strip(), m.group(2), m.group(3)


def detect_ecosystem(pr: dict) -> Ecosystem:
    """Detect ecosystem from PR body/labels. Defaults to npm."""
    body = (pr.get("body") or "").lower()
    for keyword, eco in _ECOSYSTEM_KEYWORDS.items():
        if keyword in body:
            return eco
    labels = [l.get("name", "").lower() for l in (pr.get("labels") or [])]
    for keyword, eco in _ECOSYSTEM_KEYWORDS.items():
        if any(keyword in label for label in labels):
            return eco
    return Ecosystem.NPM


def fetch_dependabot_prs(repo: str) -> list[QueueItem]:
    """Fetch open Dependabot PRs for a repo via gh CLI."""
    result = subprocess.run(
        [
            "gh", "pr", "list",
            "--repo", repo,
            "--app", "dependabot",
            "--state", "open",
            "--json", "number,title,body,labels",
            "--limit", "100",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    prs = json.loads(result.stdout)
    items: list[QueueItem] = []
    for pr in prs:
        parsed = parse_pr_title(pr["title"])
        if not parsed:
            continue
        package_name, old_version, new_version = parsed
        ecosystem = detect_ecosystem(pr)
        items.append(
            QueueItem(
                repo=repo,
                pr_number=pr["number"],
                ecosystem=ecosystem,
                package_name=package_name,
                old_version=old_version,
                new_version=new_version,
            )
        )
    return items


def fetch_and_save(repo: str, queue_path: Path) -> list[QueueItem]:
    """Fetch Dependabot PRs and merge into existing queue."""
    existing = load_queue(queue_path)
    existing_prs = {(item.repo, item.pr_number) for item in existing}
    new_items = fetch_dependabot_prs(repo)
    added = [item for item in new_items if (item.repo, item.pr_number) not in existing_prs]
    merged = existing + added
    save_queue(merged, queue_path)
    return merged
