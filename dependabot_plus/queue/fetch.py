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

# Keywords that only ever appear as a Dependabot package-manager identifier.
# The loose body scan uses these first because generic words like "npm" or
# "docker" turn up constantly in bundled release notes and changelogs.
_UNAMBIGUOUS_KEYWORDS = {
    "go_modules", "gomod", "npm_and_yarn", "bundler", "rubygems", "github_actions",
}

# The manifest/lockfile a Dependabot PR touches is the most reliable signal —
# it is present on grouped PRs, which carry no package-manager badge at all.
_FILE_ECOSYSTEM_PATTERNS: list[tuple[re.Pattern, Ecosystem]] = [
    (re.compile(r"(?:^|/)\.github/(?:workflows/[^/]+\.ya?ml|actions/.+)$"),
     Ecosystem.GITHUB_ACTIONS),
    (re.compile(r"(?:^|/)(?:Gemfile|Gemfile\.lock|[^/]+\.gemspec)$"), Ecosystem.GEM),
    (re.compile(r"(?:^|/)(?:package\.json|package-lock\.json|npm-shrinkwrap\.json"
                r"|yarn\.lock|pnpm-lock\.yaml|pnpm-workspace\.yaml)$"), Ecosystem.NPM),
    (re.compile(r"(?:^|/)go\.(?:mod|sum)$"), Ecosystem.GO),
    (re.compile(r"(?:^|/)(?:requirements[^/]*\.txt|constraints\.txt|Pipfile(?:\.lock)?"
                r"|poetry\.lock|pyproject\.toml|setup\.py|setup\.cfg)$"), Ecosystem.PIP),
    (re.compile(r"(?:^|/)(?:Dockerfile[^/]*|[^/]*\.[Dd]ockerfile"
                r"|docker-compose[^/]*\.ya?ml)$"), Ecosystem.DOCKER),
]

# Label names Dependabot / repo automation attaches, normalised to underscores.
_LABEL_ECOSYSTEMS: dict[str, Ecosystem] = {
    "npm": Ecosystem.NPM,
    "npm_and_yarn": Ecosystem.NPM,
    "yarn": Ecosystem.NPM,
    "pnpm": Ecosystem.NPM,
    "javascript": Ecosystem.NPM,
    "typescript": Ecosystem.NPM,
    "bundler": Ecosystem.GEM,
    "rubygems": Ecosystem.GEM,
    "ruby": Ecosystem.GEM,
    "pip": Ecosystem.PIP,
    "python": Ecosystem.PIP,
    "go": Ecosystem.GO,
    "golang": Ecosystem.GO,
    "gomod": Ecosystem.GO,
    "go_modules": Ecosystem.GO,
    "docker": Ecosystem.DOCKER,
    "github_actions": Ecosystem.GITHUB_ACTIONS,
    "actions": Ecosystem.GITHUB_ACTIONS,
    "apt": Ecosystem.APT,
}


def _detect_go_from_package_name(name: str) -> bool:
    """Go modules use domain-style names like github.com/foo/bar."""
    return "/" in name and "." in name.split("/")[0]


def _detect_from_package_name(name: str) -> Ecosystem | None:
    """Infer the ecosystem from the shape of the package name.

    - ``@scope/pkg``        → npm (only npm uses a leading @)
    - ``github.com/foo/bar``→ go  (domain-style module path)
    - ``actions/checkout``  → github_actions (owner/repo, no domain)
    """
    if not name:
        return None
    if name.startswith("@"):
        return Ecosystem.NPM
    if "/" in name:
        if _detect_go_from_package_name(name):
            return Ecosystem.GO
        return Ecosystem.GITHUB_ACTIONS
    return None


def detect_ecosystem_from_files(files: list) -> Ecosystem | None:
    """Infer the ecosystem from the manifest files the PR changes.

    Returns None when nothing matches, or when two ecosystems match equally
    often (ambiguous), so the caller can fall back to weaker signals.
    """
    counts: dict[Ecosystem, int] = {}
    for entry in files or []:
        path = entry.get("path", "") if isinstance(entry, dict) else str(entry)
        for pattern, eco in _FILE_ECOSYSTEM_PATTERNS:
            if pattern.search(path):
                counts[eco] = counts.get(eco, 0) + 1
                break
    if not counts:
        return None
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
        return None
    return ranked[0][0]


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


def _detect_from_body(body: str, keywords: set[str]) -> Ecosystem | None:
    """Search the PR body for the given package-manager keywords."""
    for keyword, eco in _ECOSYSTEM_KEYWORDS.items():
        if keyword not in keywords:
            continue
        # Match keyword surrounded by non-alphanumeric chars or at boundaries
        if re.search(rf'(?:^|[\s/=&])({re.escape(keyword)})(?:[\s/=&.,;)]|$)', body):
            return eco
    return None


def detect_ecosystem(pr: dict, package_name: str = "") -> Ecosystem:
    """Detect ecosystem from PR files/body/labels/package name.

    Signals in descending order of reliability. Grouped PRs ("bump the X group
    with N updates") carry no package-manager badge and their bodies embed the
    release notes of every bumped package, so a loose keyword scan of the body
    is close to worthless there — the changed manifest files decide instead.
    """
    body = (pr.get("body") or "").lower()

    # 1. Best signal: Dependabot badge URL contains package-manager=<ecosystem>
    pm_match = re.search(r'package-manager=(\w+)', body)
    if pm_match:
        pm = pm_match.group(1)
        for keyword, eco in _ECOSYSTEM_KEYWORDS.items():
            if pm == keyword:
                return eco

    # 2. Manifest files touched by the PR (Gemfile.lock, go.mod, workflows, ...)
    from_files = detect_ecosystem_from_files(pr.get("files") or [])
    if from_files is not None:
        return from_files

    # 3. Package-name shape (@scope/x, github.com/foo/bar, actions/checkout).
    #    Checked before the body scan because grouped PRs bury misleading
    #    keywords in the bundled changelogs.
    from_name = _detect_from_package_name(package_name)
    if from_name is not None:
        return from_name

    # 4. Body scan for identifiers that only Dependabot emits ("npm_and_yarn")
    from_body = _detect_from_body(body, _UNAMBIGUOUS_KEYWORDS)
    if from_body is not None:
        return from_body

    # 5. Labels — split into tokens so "github-actions" and "ruby" both match
    for label in (pr.get("labels") or []):
        name = (label.get("name", "") if isinstance(label, dict) else str(label)).lower()
        candidates = [name.replace("-", "_"), *re.split(r"[^a-z0-9]+", name)]
        for candidate in candidates:
            eco = _LABEL_ECOSYSTEMS.get(candidate)
            if eco is not None:
                return eco

    # 6. Last resort: generic words ("npm", "pip", "docker") anywhere in the body
    from_body = _detect_from_body(body, set(_ECOSYSTEM_KEYWORDS))
    if from_body is not None:
        return from_body

    return Ecosystem.NPM


def fetch_dependabot_prs(repo: str) -> list[QueueItem]:
    """Fetch open Dependabot PRs for a repo via gh CLI."""
    result = subprocess.run(
        [
            "gh", "pr", "list",
            "--repo", repo,
            "--author", "app/dependabot",
            "--state", "open",
            "--json", "number,title,body,labels,files",
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
    fresh_by_key = {
        (item.repo, item.pr_number, item.package_name): item for item in new_items
    }
    fresh_keys = set(fresh_by_key)
    # Drop stale queued items whose PRs are no longer open/eligible, and
    # collapse duplicate rows for the same package (older runs could append
    # a second row; _update_status only ever updates the first match, so the
    # rest would be re-processed on every run). Later rows win.
    by_key: dict[tuple, QueueItem] = {}
    for item in existing:
        key = (item.repo, item.pr_number, item.package_name)
        if key in fresh_keys or item.status != Status.QUEUED:
            by_key[key] = item
    kept = list(by_key.values())
    # Re-detection can correct an ecosystem an earlier run got wrong (grouped
    # PRs used to fall back to npm). Anything already processed under the wrong
    # ecosystem was analysed against the wrong registry — requeue it.
    for item in kept:
        fresh = fresh_by_key.get((item.repo, item.pr_number, item.package_name))
        if fresh is not None and fresh.ecosystem != item.ecosystem:
            item.ecosystem = fresh.ecosystem
            item.status = Status.QUEUED
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
