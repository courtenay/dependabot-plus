from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from dependabot_plus.queue.models import Ecosystem, QueueItem, Status, load_queue, save_queue

# Dependabot PR title patterns (with optional prefix like "deps(web): "):
#   "Bump lodash from 4.17.20 to 4.17.21"
#   "deps(web): bump import-in-the-middle from 2.0.6 to 3.0.0 in /web"
#   "Update nokogiri requirement from ~> 1.13 to ~> 1.14"
#   "chore(deps): bump the npm_and_yarn group across 4 directories with 1 update"
_BUMP_RE = re.compile(
    r"^(?:.*?:\s*)?(?:Bump|Update)\s+(.+?)\s+(?:requirement\s+)?from\s+~?>?\s*(\S+)\s+to\s+~?>?\s*(\S+)",
    re.IGNORECASE,
)

# Ecosystem hints from the PR body or labels
# Keywords matched against the Dependabot package-manager field in PR body.
# Ordered most-specific-first; matched via `package-manager=<keyword>` to
# avoid false positives (e.g. "docker" matching "docs.github.com/docker").
_ECOSYSTEM_KEYWORDS: dict[str, Ecosystem] = {
    "go_modules": Ecosystem.GO,
    "gomod": Ecosystem.GO,
    "npm_and_yarn": Ecosystem.NPM,
    "npm": Ecosystem.NPM,
    "bundler": Ecosystem.GEM,
    "rubygems": Ecosystem.GEM,
    "pip": Ecosystem.PIP,
    "docker": Ecosystem.DOCKER,
    "github_actions": Ecosystem.GITHUB_ACTIONS,
    "apt": Ecosystem.APT,
}


def _detect_go_from_package_name(name: str) -> bool:
    """Go modules use domain-style names like github.com/foo/bar."""
    return "/" in name and "." in name.split("/")[0]


def parse_pr_title(title: str) -> tuple[str, str, str] | None:
    """Extract (package_name, old_version, new_version) from a Dependabot PR title."""
    m = _BUMP_RE.match(title)
    if not m:
        return None
    return m.group(1).strip(), m.group(2), m.group(3)


# Grouped PRs have "Updates `pkg` from X to Y" lines in the body
_GROUPED_UPDATE_RE = re.compile(
    r"Updates\s+`(.+?)`\s+from\s+(\S+)\s+to\s+(\S+)",
    re.IGNORECASE,
)


def parse_grouped_pr_body(body: str) -> list[tuple[str, str, str]]:
    """Extract multiple (package_name, old_version, new_version) from a grouped PR body."""
    return [
        (m.group(1), m.group(2), m.group(3))
        for m in _GROUPED_UPDATE_RE.finditer(body or "")
    ]


def detect_ecosystem(pr: dict, package_name: str = "") -> Ecosystem:
    """Detect ecosystem from PR body/labels/package name."""
    body = (pr.get("body") or "").lower()

    # Best signal: Dependabot badge URL contains package-manager=<ecosystem>
    import re
    pm_match = re.search(r'package-manager=(\w+)', body)
    if pm_match:
        pm = pm_match.group(1)
        for keyword, eco in _ECOSYSTEM_KEYWORDS.items():
            if pm == keyword:
                return eco

    # Go modules have domain-style names: github.com/foo/bar — check early
    # because grouped PRs may contain misleading keywords in the body
    if package_name and _detect_go_from_package_name(package_name):
        return Ecosystem.GO

    # Fallback: keyword search in body with word boundary context
    for keyword, eco in _ECOSYSTEM_KEYWORDS.items():
        # Match keyword surrounded by non-alphanumeric chars or at boundaries
        if re.search(rf'(?:^|[\s/=&])({re.escape(keyword)})(?:[\s/=&.,;)]|$)', body):
            return eco
    labels = [lbl.get("name", "").lower() for lbl in (pr.get("labels") or [])]
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
            "--author", "app/dependabot",
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
        # Skip PRs already labeled as vetted
        labels = {lbl.get("name", "") for lbl in (pr.get("labels") or [])}
        if "deps-vetted" in labels:
            continue
        parsed = parse_pr_title(pr["title"])
        if parsed:
            # Single-package PR
            packages = [parsed]
        else:
            # Try grouped PR format: "Updates `pkg` from X to Y" in body
            packages = parse_grouped_pr_body(pr.get("body", ""))
        if not packages:
            continue
        # Deduplicate within a single PR (same package can appear
        # multiple times in multi-directory grouped PRs)
        seen = set()
        for package_name, old_version, new_version in packages:
            key = (package_name, old_version, new_version)
            if key in seen:
                continue
            seen.add(key)
            ecosystem = detect_ecosystem(pr, package_name)
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
    new_items = fetch_dependabot_prs(repo)
    fresh_keys = {
        (item.repo, item.pr_number, item.package_name) for item in new_items
    }
    # Drop stale queued items whose PRs are no longer open/eligible
    kept = [
        item for item in existing
        if (item.repo, item.pr_number, item.package_name) in fresh_keys
        or item.status != Status.QUEUED
    ]
    kept_keys = {
        (item.repo, item.pr_number, item.package_name) for item in kept
    }
    added = [
        item for item in new_items
        if (item.repo, item.pr_number, item.package_name) not in kept_keys
    ]
    merged = kept + added
    save_queue(merged, queue_path)
    return merged
