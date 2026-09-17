"""Grouped-PR packages come from the diff, not the truncatable body.

Dependabot truncates grouped PR bodies, so a body-derived package list can be
silently short: soffi-main #3284's title says 7 updates and its body yielded 6
(golang.org/x/sys missing), #3169 says 10 and yielded 7 (jest-environment-jsdom,
postcss, tailwindcss missing). Every fixture here is shaped like a real PR that
was mis-parsed.
"""
from __future__ import annotations

from unittest.mock import patch

from dependabot_plus.queue.fetch import (
    fetch_dependabot_prs,
    grouped_packages,
    parse_declared_update_count,
    parse_grouped_pr_body,
    parse_grouped_pr_diff,
)

# #3169's shape: a body listing 3 of the 4 devDependencies the diff changes.
NPM_DIFF = """diff --git a/backend/package.json b/backend/package.json
--- a/backend/package.json
+++ b/backend/package.json
@@ -10,7 +10,7 @@
-    "highlight.js": "^11.11.1",
+    "highlight.js": "^11.12.0",
-    "postcss": "^8.5.26",
+    "postcss": "^8.5.28",
-    "tailwindcss": "^4.2.2",
+    "tailwindcss": "^4.3.3",
-    "jest-environment-jsdom": "^30.3.0",
+    "jest-environment-jsdom": "^30.5.1",
"""

NPM_TRUNCATED_BODY = "Updates `highlight.js` from 11.11.1 to 11.12.0\n"

# #3284's shape: a grouped go.mod bump whose last entry the body omits.
GO_DIFF = """diff --git a/codehost/go.mod b/codehost/go.mod
--- a/codehost/go.mod
+++ b/codehost/go.mod
@@ -5,6 +5,6 @@
-	github.com/getsentry/sentry-go v0.46.2
+	github.com/getsentry/sentry-go v0.49.0
-	golang.org/x/sys v0.47.0
+	golang.org/x/sys v0.48.0
"""

MULTI_DIR_DIFF = """diff --git a/scripts/ops-bot/package.json b/scripts/ops-bot/package.json
--- a/scripts/ops-bot/package.json
+++ b/scripts/ops-bot/package.json
-    "left-pad": "1.0.0",
+    "left-pad": "1.1.0",
diff --git a/web/e2e/fixtures/dynamic-list-app/package.json b/web/e2e/fixtures/dynamic-list-app/package.json
--- a/web/e2e/fixtures/dynamic-list-app/package.json
+++ b/web/e2e/fixtures/dynamic-list-app/package.json
-    "next": "16.2.11",
+    "next": "16.3.3",
"""

GEM_DIFF = """diff --git a/backend/Gemfile.lock b/backend/Gemfile.lock
--- a/backend/Gemfile.lock
+++ b/backend/Gemfile.lock
-    activeagent (1.0.3)
+    activeagent (1.5.2)
-      connection_pool (>= 2.2.3)
+      connection_pool (>= 2.2.4)
"""


class TestParseGroupedPrDiff:
    def test_npm_finds_every_bump_the_body_omits(self):
        got = parse_grouped_pr_diff(NPM_DIFF)
        assert [name for name, _, _ in got] == [
            "highlight.js", "postcss", "tailwindcss", "jest-environment-jsdom",
        ]
        # ...and the body alone would have found only one of the four.
        assert len(parse_grouped_pr_body(NPM_TRUNCATED_BODY)) == 1

    def test_npm_strips_range_prefixes_from_both_versions(self):
        assert parse_grouped_pr_diff(NPM_DIFF)[0] == (
            "highlight.js", "11.11.1", "11.12.0",
        )

    def test_go_modules_including_the_trailing_one(self):
        assert parse_grouped_pr_diff(GO_DIFF) == [
            ("github.com/getsentry/sentry-go", "0.46.2", "0.49.0"),
            ("golang.org/x/sys", "0.47.0", "0.48.0"),
        ]

    def test_same_package_in_two_directories_is_not_collapsed(self):
        got = parse_grouped_pr_diff(MULTI_DIR_DIFF)
        assert ("left-pad", "1.0.0", "1.1.0") in got
        assert ("next", "16.2.11", "16.3.3") in got

    def test_gemfile_lock_skips_nested_constraint_lines(self):
        # Six-space constraint lines are not gems; only the four-space entry is.
        assert parse_grouped_pr_diff(GEM_DIFF) == [("activeagent", "1.0.3", "1.5.2")]

    def test_ignores_files_with_no_manifest_parser(self):
        assert parse_grouped_pr_diff(
            "diff --git a/README.md b/README.md\n-    \"a\": \"1.0.0\"\n+    \"a\": \"2.0.0\"\n"
        ) == []

    def test_addition_without_a_removal_is_not_a_bump(self):
        assert parse_grouped_pr_diff(
            'diff --git a/package.json b/package.json\n+    "brand-new": "1.0.0",\n'
        ) == []


class TestParseAddedPackages:
    """Packages entering the tree for the first time have no version to diff."""

    def test_new_transitive_gem_is_reported(self):
        # #3286: activeagent 1.5.2 pulls in a telemetry gem that was never
        # analysed, while the PR still earned a deps-vetted label.
        diff = GEM_DIFF.replace(
            "+    activeagent (1.5.2)",
            "+    activeagent (1.5.2)\n+    activeagents-telemetry (0.3.0)",
        )
        from dependabot_plus.queue.fetch import parse_added_packages
        assert parse_added_packages(diff) == [("activeagents-telemetry", "0.3.0")]

    def test_a_plain_bump_adds_nothing(self):
        from dependabot_plus.queue.fetch import parse_added_packages
        assert parse_added_packages(GO_DIFF) == []

    def test_relocation_within_go_mod_is_not_a_new_package(self):
        # #3284 moves protobuf from a standalone `require` line into the
        # require block at an unchanged version. Missing the `require ` prefix
        # hid the removal and made it look brand new.
        diff = (
            "diff --git a/codehost/go.mod b/codehost/go.mod\n"
            "-require google.golang.org/protobuf v1.36.12 // indirect\n"
            "+\tgoogle.golang.org/protobuf v1.36.12 // indirect\n"
        )
        from dependabot_plus.queue.fetch import parse_added_packages
        assert parse_added_packages(diff) == []
        assert parse_grouped_pr_diff(diff) == []   # same version: not a bump either


class TestParseDeclaredUpdateCount:
    def test_reads_the_total_from_the_title(self):
        assert parse_declared_update_count(
            "deps(codehost): bump the minor-and-patch group across 1 directory with 7 updates"
        ) == 7

    def test_singular(self):
        assert parse_declared_update_count("bump the group with 1 update") == 1

    def test_absent_when_the_title_does_not_say(self):
        assert parse_declared_update_count("Bump lodash from 4.17.20 to 4.17.21") is None


class TestCoverageCompleteness:
    """all-LOW over a partial package list must not earn a deps-vetted label."""

    PR = {
        "number": 3169,
        "title": "deps(backend-npm): bump the minor-and-patch group with 4 updates",
        "body": NPM_TRUNCATED_BODY,
    }

    def test_complete_when_the_diff_matches_the_declared_count(self):
        with patch("dependabot_plus.queue.fetch.fetch_pr_diff", return_value=NPM_DIFF):
            packages, complete = grouped_packages("o/r", self.PR)
        assert len(packages) == 4
        assert complete is True

    def test_incomplete_when_fewer_parsed_than_declared(self):
        pr = {**self.PR, "title": "bump the minor-and-patch group with 10 updates"}
        with patch("dependabot_plus.queue.fetch.fetch_pr_diff", return_value=NPM_DIFF):
            packages, complete = grouped_packages("o/r", pr)
        assert len(packages) == 4
        assert complete is False

    def test_unreadable_diff_falls_back_to_the_body_but_is_never_complete(self):
        with patch("dependabot_plus.queue.fetch.fetch_pr_diff", return_value=None):
            packages, complete = grouped_packages("o/r", self.PR)
        # The body is still used — losing the PR entirely would be worse — but
        # it can never be asserted complete, so the PR cannot be auto-labelled.
        assert [p[0] for p in packages] == ["highlight.js"]
        assert complete is False

    def test_a_new_package_makes_the_pr_unvettable(self):
        diff = NPM_DIFF + '+    "brand-new-dep": "1.0.0",\n'
        pr = {**self.PR, "title": "bump the group with 4 updates"}
        with patch("dependabot_plus.queue.fetch.fetch_pr_diff", return_value=diff):
            packages, complete = grouped_packages("o/r", pr)
        # The four bumps are still derived — the PR is not dropped — but a
        # package with no prior version cannot be diffed, so "all LOW" would
        # not be a verdict on the whole PR.
        assert len(packages) == 4
        assert complete is False

    def test_unparseable_ecosystem_falls_back_to_the_body_and_is_not_complete(self):
        pr = {
            "number": 3288,
            "title": "deps(docker): bump the all-docker group with 3 updates",
            "body": "Updates `alpine` from 3.22 to 3.24\n",
        }
        docker_diff = (
            "diff --git a/docker/monitoring.Dockerfile b/docker/monitoring.Dockerfile\n"
            "-FROM alpine:3.22\n+FROM alpine:3.24\n"
        )
        with patch("dependabot_plus.queue.fetch.fetch_pr_diff", return_value=docker_diff):
            packages, complete = grouped_packages("o/r", pr)
        assert [p[0] for p in packages] == ["alpine"]
        assert complete is False


class TestFetchMarksItems:
    def _run(self, pr, diff):
        gh_json = __import__("json").dumps([pr])
        with patch("subprocess.run") as run, \
             patch("dependabot_plus.queue.fetch.fetch_pr_diff", return_value=diff):
            run.return_value.stdout = gh_json
            return fetch_dependabot_prs("o/r")

    def test_grouped_pr_items_carry_the_coverage_flag(self):
        pr = {
            "number": 3169,
            "title": "deps(backend-npm): bump the group with 10 updates",
            "body": NPM_TRUNCATED_BODY,
            "labels": [],
            "files": [{"path": "backend/package.json"}],
        }
        items = self._run(pr, NPM_DIFF)
        assert len(items) == 4                       # not 1, as the body gave
        assert all(i.coverage_complete is False for i in items)   # 4 < 10

    def test_single_package_pr_is_always_complete(self):
        pr = {
            "number": 3285,
            "title": "deps: bump github.com/containerd/containerd/v2 from 2.3.4 to 2.3.5",
            "body": "",
            "labels": [],
            "files": [{"path": "soffi-build-service/go.mod"}],
        }
        items = self._run(pr, GO_DIFF)
        assert len(items) == 1
        assert items[0].coverage_complete is True
