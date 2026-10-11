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


# Dependabot states the real total in the title: "... with 19 updates".
_UPDATE_COUNT_RE = re.compile(r"with\s+(\d+)\s+updates?\b", re.IGNORECASE)


def parse_grouped_pr_body(body: str) -> list[tuple[str, str, str]]:
    """Extract multiple (package_name, old_version, new_version) from a grouped PR body.

    Kept for ecosystems with no manifest parser, and as a last resort. The body
    is NOT a reliable spec: dependabot truncates grouped bodies (soffi-main
    #3264's title says 19 updates, its body lists 8), which silently dropped 11
    gems from a derived plan. Prefer parse_grouped_pr_diff.
    """
    return [
        (m.group(1), m.group(2), m.group(3))
        for m in _GROUPED_UPDATE_RE.finditer(body or "")
    ]


def parse_declared_update_count(title: str) -> int | None:
    """The number of updates dependabot says the PR contains, if it says."""
    m = _UPDATE_COUNT_RE.search(title or "")
    return int(m.group(1)) if m else None


# --- manifest line parsers, keyed by the file a hunk belongs to -------------
# Each returns (package, version) for one changed manifest line, or None.


def _npm_manifest_line(line: str) -> tuple[str, str] | None:
    m = re.match(r'\s*"([^"]+)"\s*:\s*"[~^>=< ]*([0-9][^"]*)"', line)
    return (m.group(1), m.group(2)) if m else None


def _go_manifest_line(line: str) -> tuple[str, str] | None:
    # The optional `require ` prefix is load-bearing: go.mod holds modules both
    # as standalone `require mod vX` lines and inside a `require (...)` block,
    # and dependabot moves modules between the two. Missing the prefixed form
    # hides the removal half, making a relocation look like a brand-new
    # dependency (soffi-main #3284 moves google.golang.org/protobuf into the
    # block at an unchanged version).
    m = re.match(r"\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]+\S*)\s+v([0-9]\S*)", line)
    return (m.group(1), m.group(2)) if m else None


def _gem_lock_line(line: str) -> tuple[str, str] | None:
    # Exactly four spaces marks a top-level gem; six marks its constraints.
    m = re.match(r"    ([A-Za-z0-9_.\-]+) \(([0-9][^)\-]*)", line)
    return (m.group(1), m.group(2)) if m else None


_MANIFEST_PARSERS = (
    (re.compile(r"(^|/)package\.json$"), _npm_manifest_line),
    (re.compile(r"(^|/)go\.mod$"), _go_manifest_line),
    (re.compile(r"(^|/)Gemfile\.lock$"), _gem_lock_line),
)


def _parser_for(path: str):
    for pattern, parser in _MANIFEST_PARSERS:
        if pattern.search(path):
            return parser
    return None


def _manifest_changes(diff: str):
    """(removed, added, order) keyed by (path, package) across manifest hunks."""
    removed: dict[tuple[str, str], str] = {}
    added: dict[tuple[str, str], str] = {}
    order: list[tuple[str, str]] = []
    parser = None
    path = ""

    for line in (diff or "").splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            path = parts[2][2:] if len(parts) > 2 else ""
            parser = _parser_for(path)
            continue
        if parser is None or line.startswith(("+++", "---")):
            continue
        if line.startswith(("+", "-")):
            parsed = parser(line[1:])
            if not parsed:
                continue
            package, version = parsed
            key = (path, package)
            if key not in removed and key not in added:
                order.append(key)
            (added if line.startswith("+") else removed)[key] = version

    return removed, added, order


def parse_grouped_pr_diff(diff: str) -> list[tuple[str, str, str]]:
    """Extract (package, old_version, new_version) from a PR's manifest hunks.

    The diff is the only complete record of what a grouped PR changes. A bump
    rewrites a declared version, so a package is reported only when the same
    manifest shows both a removed and an added version for it — which also
    filters unrelated additions. Packages that are only *added* are not bumps;
    see parse_added_packages.
    """
    removed, added, order = _manifest_changes(diff)
    bumps: list[tuple[str, str, str]] = []
    for key in order:
        old, new = removed.get(key), added.get(key)
        if old and new and old != new:
            bumps.append((key[1], old, new))
    return bumps


def parse_added_packages(diff: str) -> list[tuple[str, str]]:
    """(package, version) for packages the PR ADDS, with no prior version.

    These are not bumps — they are dependencies entering the tree for the first
    time, usually pulled in transitively by one of the bumps (soffi-main #3286
    adds activeagents-telemetry 0.3.0 as a new requirement of activeagent
    1.5.2). A version-to-version diff cannot describe them, so the analysis
    pipeline has nothing to compare and they are easy to miss entirely — which
    is the worst outcome for the one category that is wholly unreviewed code.
    """
    removed, added, order = _manifest_changes(diff)
    return [(key[1], added[key]) for key in order
            if key in added and key not in removed]


def fetch_pr_diff(repo: str, pr_number: int) -> str | None:
    """The PR's diff, or None when it cannot be read.

    None means "could not tell", never "nothing changed" — the caller must not
    conflate them. Collapsing those two is how truncated body data silently
    became the spec in the first place.
    """
    try:
        result = subprocess.run(
            ["gh", "pr", "diff", str(pr_number), "--repo", repo],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return None
    return result.stdout or None


def grouped_packages(repo: str, pr: dict) -> tuple[list[tuple[str, str, str]], bool]:
    """Packages for a grouped PR, plus whether that list is known to be complete.

    Incomplete coverage is the dangerous case: analysing 7 of 10 packages and
    finding them all LOW would otherwise earn the PR a deps-vetted label that
    never covered the other 3. The title states the real total, so assert
    against it rather than trusting whatever the parser happened to return.
    """
    declared = parse_declared_update_count(pr.get("title", ""))
    diff = fetch_pr_diff(repo, pr["number"])

    if diff is None:
        print(f"  PR #{pr['number']}: diff unreadable — falling back to the "
              f"(truncatable) body; coverage NOT complete")
        return parse_grouped_pr_body(pr.get("body", "")), False

    packages = parse_grouped_pr_diff(diff)
    if not packages:
        # No manifest parser matched (docker, github_actions, ...). Those
        # bodies are short and do not truncate in practice, but completeness
        # still cannot be asserted from them.
        return parse_grouped_pr_body(pr.get("body", "")), False

    distinct = len({name for name, _, _ in packages})
    complete = declared is None or distinct >= declared
    if not complete:
        print(f"  PR #{pr['number']}: title declares {declared} updates but "
              f"{distinct} parsed from the diff — coverage incomplete")

    # A package with no prior version is unreviewed code entering the tree, and
    # a version-to-version analysis cannot say anything about it. Refusing the
    # label is the honest verdict — measured at 2 of 10 open PRs, so this
    # reports a real and rare event rather than blocking the pipeline.
    for name, version in parse_added_packages(diff):
        print(f"  PR #{pr['number']}: introduces NEW package {name} {version} "
              f"— no prior version to diff against; coverage incomplete")
        complete = False

    return packages, complete


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
            # Single-package PR: the title names the one bump in full, and
            # titles are never truncated.
            packages, coverage_complete = [parsed], True
        else:
            packages, coverage_complete = grouped_packages(repo, pr)
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
                    coverage_complete=coverage_complete,
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
