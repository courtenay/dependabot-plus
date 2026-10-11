from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch


from dependabot_plus.queue.fetch import (
    detect_ecosystem,
    fetch_and_save,
    fetch_dependabot_prs,
    parse_pr_title,
)
from dependabot_plus.queue.models import Ecosystem, QueueItem, Status, save_queue


# ---------------------------------------------------------------------------
# parse_pr_title
# ---------------------------------------------------------------------------


class TestParsePrTitle:
    def test_bump_simple(self):
        result = parse_pr_title("Bump lodash from 4.17.20 to 4.17.21")
        assert result == ("lodash", "4.17.20", "4.17.21")

    def test_bump_scoped_package(self):
        result = parse_pr_title("Bump @types/node from 16.0.0 to 18.0.0")
        assert result == ("@types/node", "16.0.0", "18.0.0")

    def test_bump_in_subdir(self):
        result = parse_pr_title("Bump lodash from 4.17.20 to 4.17.21 in /subdir")
        assert result == ("lodash", "4.17.20", "4.17.21")

    def test_update_requirement_tilde(self):
        result = parse_pr_title("Update nokogiri requirement from ~> 1.13 to ~> 1.14")
        assert result == ("nokogiri", "1.13", "1.14")

    def test_update_requirement_gte(self):
        result = parse_pr_title("Update rails requirement from ~> 6.1 to ~> 7.0")
        assert result == ("rails", "6.1", "7.0")

    def test_case_insensitive(self):
        result = parse_pr_title("bump axios from 0.21.1 to 0.21.2")
        assert result is not None
        assert result[0] == "axios"

    def test_non_matching_title_returns_none(self):
        assert parse_pr_title("Fix typo in README") is None

    def test_empty_string_returns_none(self):
        assert parse_pr_title("") is None

    def test_partial_match_returns_none(self):
        assert parse_pr_title("Bump lodash") is None


# ---------------------------------------------------------------------------
# detect_ecosystem
# ---------------------------------------------------------------------------


class TestDetectEcosystem:
    def test_npm_from_body(self):
        pr = {"body": "Bumps [lodash](https://npm.js). npm_and_yarn update."}
        assert detect_ecosystem(pr) == Ecosystem.NPM

    def test_bundler_from_body(self):
        pr = {"body": "Updates bundler dependency nokogiri"}
        assert detect_ecosystem(pr) == Ecosystem.GEM

    def test_rubygems_from_body(self):
        pr = {"body": "rubygems package update"}
        assert detect_ecosystem(pr) == Ecosystem.GEM

    def test_pip_from_body(self):
        pr = {"body": "Updates pip package requests"}
        assert detect_ecosystem(pr) == Ecosystem.PIP

    def test_gomod_from_body(self):
        pr = {"body": "Bumps the gomod group in /backend"}
        assert detect_ecosystem(pr) == Ecosystem.GO

    def test_go_from_package_name(self):
        pr = {"body": "some generic body"}
        assert detect_ecosystem(pr, "github.com/foo/bar") == Ecosystem.GO

    def test_label_fallback(self):
        pr = {"body": "", "labels": [{"name": "dependencies"}, {"name": "npm"}]}
        assert detect_ecosystem(pr) == Ecosystem.NPM

    def test_defaults_to_npm(self):
        pr = {"body": "some unrelated text", "labels": []}
        assert detect_ecosystem(pr) == Ecosystem.NPM

    def test_none_body_and_labels(self):
        pr = {"body": None, "labels": None}
        assert detect_ecosystem(pr) == Ecosystem.NPM

    def test_body_keyword_takes_priority_over_labels(self):
        pr = {
            "body": "bundler update",
            "labels": [{"name": "npm"}],
        }
        assert detect_ecosystem(pr) == Ecosystem.GEM

    def test_go_package_name_takes_priority_over_body(self):
        pr = {"body": "Updates docker dependencies in grouped PR"}
        assert detect_ecosystem(pr, "github.com/aws/aws-sdk-go-v2/config") == Ecosystem.GO

    def test_docker_from_body(self):
        pr = {"body": "package-manager=docker update"}
        assert detect_ecosystem(pr) == Ecosystem.DOCKER

    def test_github_actions_from_body(self):
        pr = {"body": "package-manager=github_actions update"}
        assert detect_ecosystem(pr) == Ecosystem.GITHUB_ACTIONS


# ---------------------------------------------------------------------------
# detect_ecosystem for grouped PRs — no package-manager badge, and the body
# embeds the release notes of every bumped package (so it is full of
# misleading keywords). The changed manifest files decide instead.
# ---------------------------------------------------------------------------


def _files(*paths: str) -> list[dict]:
    return [{"path": p} for p in paths]


class TestDetectEcosystemGrouped:
    def test_grouped_gems_not_mistaken_for_npm(self):
        pr = {
            "body": "Bumps the minor-and-patch group in /backend with 5 updates. "
                    "Release notes mention npm and docker.",
            "labels": [{"name": "dependencies"}, {"name": "backend"}],
            "files": _files("backend/Gemfile", "backend/Gemfile.lock"),
        }
        assert detect_ecosystem(pr, "sentry-ruby") == Ecosystem.GEM

    def test_grouped_actions_from_workflow_files(self):
        pr = {
            "body": "Bumps the all-actions group with 6 updates. Bump flatted "
                    "from 3.3.1 to 3.4.2 (npm).",
            "labels": [{"name": "dependencies"}, {"name": "github-actions"}],
            "files": _files(".github/workflows/ci.yml", ".github/workflows/deploy.yml"),
        }
        assert detect_ecosystem(pr, "actions/labeler") == Ecosystem.GITHUB_ACTIONS

    def test_grouped_go_from_go_mod(self):
        pr = {
            "body": "Bumps the go group with 3 updates",
            "labels": [],
            "files": _files("codehost/go.mod", "codehost/go.sum"),
        }
        assert detect_ecosystem(pr, "github.com/lib/pq") == Ecosystem.GO

    def test_grouped_npm_from_lockfile(self):
        pr = {
            "body": "Bumps the frontend group with 20 updates",
            "labels": [],
            "files": _files("web/package.json", "web/pnpm-lock.yaml"),
        }
        assert detect_ecosystem(pr, "@radix-ui/react-dialog") == Ecosystem.NPM

    def test_grouped_pip_from_requirements(self):
        pr = {"body": "Bumps the deps group", "files": _files("ml/requirements.txt")}
        assert detect_ecosystem(pr, "requests") == Ecosystem.PIP

    def test_docker_from_dockerfile(self):
        pr = {"body": "Bumps node", "files": _files("web/Dockerfile")}
        assert detect_ecosystem(pr, "node") == Ecosystem.DOCKER

    def test_files_beat_misleading_body_keyword(self):
        pr = {
            "body": "This release drops bundler support",
            "files": _files("web/package-lock.json"),
        }
        assert detect_ecosystem(pr, "lodash") == Ecosystem.NPM

    def test_package_manager_badge_still_wins_over_files(self):
        pr = {
            "body": "package-manager=bundler",
            "files": _files("web/package.json"),
        }
        assert detect_ecosystem(pr, "nokogiri") == Ecosystem.GEM

    def test_ambiguous_files_fall_through(self):
        pr = {
            "body": "package-manager=npm_and_yarn",
            "files": _files("Gemfile.lock", "package-lock.json"),
        }
        assert detect_ecosystem(pr, "lodash") == Ecosystem.NPM

    def test_action_name_shape_without_files(self):
        pr = {"body": "Bumps the actions group", "files": []}
        assert detect_ecosystem(pr, "actions/checkout") == Ecosystem.GITHUB_ACTIONS

    def test_scoped_npm_name_shape(self):
        pr = {"body": "Bumps the group", "files": []}
        assert detect_ecosystem(pr, "@babel/parser") == Ecosystem.NPM

    def test_hyphenated_github_actions_label(self):
        pr = {"body": "no hints here", "labels": [{"name": "github-actions"}]}
        assert detect_ecosystem(pr) == Ecosystem.GITHUB_ACTIONS

    def test_ruby_label(self):
        pr = {"body": "no hints here", "labels": [{"name": "dependencies"}, {"name": "ruby"}]}
        assert detect_ecosystem(pr) == Ecosystem.GEM

    def test_label_beats_generic_body_keyword(self):
        pr = {
            "body": "the changelog mentions npm a lot",
            "labels": [{"name": "ruby"}],
        }
        assert detect_ecosystem(pr) == Ecosystem.GEM


# ---------------------------------------------------------------------------
# fetch_dependabot_prs (mocked subprocess)
# ---------------------------------------------------------------------------


def _gh_output(prs: list[dict]) -> str:
    return json.dumps(prs)


class TestFetchDependabotPrs:
    @patch("dependabot_plus.queue.fetch.subprocess.run")
    def test_basic_fetch(self, mock_run):
        mock_run.return_value.stdout = _gh_output(
            [
                {
                    "number": 10,
                    "title": "Bump lodash from 4.17.20 to 4.17.21",
                    "body": "npm_and_yarn",
                    "labels": [],
                }
            ]
        )
        items = fetch_dependabot_prs("owner/repo")
        assert len(items) == 1
        assert items[0].package_name == "lodash"
        assert items[0].old_version == "4.17.20"
        assert items[0].new_version == "4.17.21"
        assert items[0].ecosystem == Ecosystem.NPM
        assert items[0].pr_number == 10
        assert items[0].repo == "owner/repo"
        assert items[0].status == Status.QUEUED

    @patch("dependabot_plus.queue.fetch.subprocess.run")
    def test_skips_unparseable_titles(self, mock_run):
        mock_run.return_value.stdout = _gh_output(
            [
                {
                    "number": 1,
                    "title": "Bump lodash from 1.0 to 2.0",
                    "body": "",
                    "labels": [],
                },
                {
                    "number": 2,
                    "title": "Fix CI pipeline",
                    "body": "",
                    "labels": [],
                },
            ]
        )
        items = fetch_dependabot_prs("owner/repo")
        assert len(items) == 1
        assert items[0].pr_number == 1

    @patch("dependabot_plus.queue.fetch.subprocess.run")
    def test_empty_result(self, mock_run):
        mock_run.return_value.stdout = "[]"
        items = fetch_dependabot_prs("owner/repo")
        assert items == []

    @patch("dependabot_plus.queue.fetch.subprocess.run")
    def test_skips_deps_vetted_label(self, mock_run):
        mock_run.return_value.stdout = _gh_output(
            [
                {
                    "number": 1,
                    "title": "Bump lodash from 1.0 to 2.0",
                    "body": "",
                    "labels": [{"name": "deps-vetted"}],
                },
                {
                    "number": 2,
                    "title": "Bump axios from 0.21.1 to 0.21.2",
                    "body": "",
                    "labels": [{"name": "dependencies"}],
                },
            ]
        )
        items = fetch_dependabot_prs("owner/repo")
        assert len(items) == 1
        assert items[0].pr_number == 2

    @patch("dependabot_plus.queue.fetch.subprocess.run")
    def test_gh_cli_called_with_correct_args(self, mock_run):
        mock_run.return_value.stdout = "[]"
        fetch_dependabot_prs("octo/cat")
        args = mock_run.call_args
        cmd = args[0][0]
        assert "gh" in cmd
        assert "--repo" in cmd
        assert "octo/cat" in cmd
        assert "--author" in cmd
        assert "app/dependabot" in cmd


# ---------------------------------------------------------------------------
# fetch_and_save (merge / dedup logic)
# ---------------------------------------------------------------------------


class TestFetchAndSave:
    @patch("dependabot_plus.queue.fetch.fetch_dependabot_prs")
    def test_adds_new_prs(self, mock_fetch, tmp_path: Path):
        queue_path = tmp_path / "queue.json"
        mock_fetch.return_value = [
            QueueItem(
                repo="o/r",
                pr_number=1,
                ecosystem=Ecosystem.NPM,
                package_name="a",
                old_version="1.0",
                new_version="2.0",
            )
        ]
        merged = fetch_and_save("o/r", queue_path)
        assert len(merged) == 1
        assert merged[0].pr_number == 1

    @patch("dependabot_plus.queue.fetch.fetch_dependabot_prs")
    def test_does_not_duplicate_existing(self, mock_fetch, tmp_path: Path):
        queue_path = tmp_path / "queue.json"
        existing = QueueItem(
            repo="o/r",
            pr_number=5,
            ecosystem=Ecosystem.NPM,
            package_name="x",
            old_version="1.0",
            new_version="2.0",
            status=Status.PROCESSING,
        )
        save_queue([existing], queue_path)

        mock_fetch.return_value = [
            QueueItem(
                repo="o/r",
                pr_number=5,
                ecosystem=Ecosystem.NPM,
                package_name="x",
                old_version="1.0",
                new_version="2.0",
            ),
            QueueItem(
                repo="o/r",
                pr_number=6,
                ecosystem=Ecosystem.GEM,
                package_name="y",
                old_version="3.0",
                new_version="4.0",
            ),
        ]
        merged = fetch_and_save("o/r", queue_path)
        assert len(merged) == 2
        # The existing item keeps its original status (PROCESSING).
        assert merged[0].status == Status.PROCESSING
        assert merged[1].pr_number == 6

    @patch("dependabot_plus.queue.fetch.fetch_dependabot_prs")
    def test_persists_to_disk(self, mock_fetch, tmp_path: Path):
        queue_path = tmp_path / "queue.json"
        mock_fetch.return_value = [
            QueueItem(
                repo="o/r",
                pr_number=1,
                ecosystem=Ecosystem.NPM,
                package_name="a",
                old_version="1.0",
                new_version="2.0",
            )
        ]
        fetch_and_save("o/r", queue_path)
        assert queue_path.exists()
        data = json.loads(queue_path.read_text())
        assert len(data) == 1

    @patch("dependabot_plus.queue.fetch.fetch_dependabot_prs")
    def test_prunes_stale_queued_items(self, mock_fetch, tmp_path: Path):
        """Items still QUEUED but no longer returned by fetch (merged/closed/vetted) are dropped."""
        queue_path = tmp_path / "queue.json"
        stale = QueueItem(
            repo="o/r",
            pr_number=950,
            ecosystem=Ecosystem.NPM,
            package_name="stale-pkg",
            old_version="1.0",
            new_version="2.0",
            status=Status.QUEUED,
        )
        save_queue([stale], queue_path)

        mock_fetch.return_value = [
            QueueItem(
                repo="o/r",
                pr_number=7,
                ecosystem=Ecosystem.NPM,
                package_name="fresh-pkg",
                old_version="1.0",
                new_version="2.0",
            )
        ]
        merged = fetch_and_save("o/r", queue_path)
        assert len(merged) == 1
        assert merged[0].pr_number == 7

    @patch("dependabot_plus.queue.fetch.fetch_dependabot_prs")
    def test_keeps_processing_items_even_if_stale(self, mock_fetch, tmp_path: Path):
        """Items mid-processing are kept even if the PR is no longer fetched."""
        queue_path = tmp_path / "queue.json"
        in_progress = QueueItem(
            repo="o/r",
            pr_number=950,
            ecosystem=Ecosystem.NPM,
            package_name="busy-pkg",
            old_version="1.0",
            new_version="2.0",
            status=Status.PROCESSING,
        )
        save_queue([in_progress], queue_path)

        mock_fetch.return_value = []
        merged = fetch_and_save("o/r", queue_path)
        assert len(merged) == 1
        assert merged[0].pr_number == 950
        assert merged[0].status == Status.PROCESSING

    @patch("dependabot_plus.queue.fetch.fetch_dependabot_prs")
    def test_works_with_no_existing_file(self, mock_fetch, tmp_path: Path):
        queue_path = tmp_path / "nonexistent.json"
        mock_fetch.return_value = []
        merged = fetch_and_save("o/r", queue_path)
        assert merged == []

    @patch("dependabot_plus.queue.fetch.fetch_dependabot_prs")
    def test_corrected_ecosystem_requeues_item(self, mock_fetch, tmp_path: Path):
        """An item analysed under a wrong ecosystem is fixed and re-queued."""
        queue_path = tmp_path / "queue.json"
        save_queue(
            [
                QueueItem(
                    repo="o/r",
                    pr_number=5,
                    ecosystem=Ecosystem.NPM,
                    package_name="sentry-ruby",
                    old_version="6.6.2",
                    new_version="6.7.0",
                    status=Status.FAILED,
                )
            ],
            queue_path,
        )
        mock_fetch.return_value = [
            QueueItem(
                repo="o/r",
                pr_number=5,
                ecosystem=Ecosystem.GEM,
                package_name="sentry-ruby",
                old_version="6.6.2",
                new_version="6.7.0",
            )
        ]
        merged = fetch_and_save("o/r", queue_path)
        assert len(merged) == 1
        assert merged[0].ecosystem == Ecosystem.GEM
        assert merged[0].status == Status.QUEUED

    @patch("dependabot_plus.queue.fetch.fetch_dependabot_prs")
    def test_unchanged_ecosystem_keeps_done_status(self, mock_fetch, tmp_path: Path):
        queue_path = tmp_path / "queue.json"
        save_queue(
            [
                QueueItem(
                    repo="o/r",
                    pr_number=5,
                    ecosystem=Ecosystem.GEM,
                    package_name="nokogiri",
                    old_version="1.0",
                    new_version="2.0",
                    status=Status.DONE,
                )
            ],
            queue_path,
        )
        mock_fetch.return_value = [
            QueueItem(
                repo="o/r",
                pr_number=5,
                ecosystem=Ecosystem.GEM,
                package_name="nokogiri",
                old_version="1.0",
                new_version="2.0",
            )
        ]
        merged = fetch_and_save("o/r", queue_path)
        assert merged[0].status == Status.DONE

    @patch("dependabot_plus.queue.fetch.fetch_dependabot_prs")
    def test_collapses_duplicate_rows(self, mock_fetch, tmp_path: Path):
        """Duplicate (pr, package) rows from older runs are collapsed —
        _update_status only updates the first match, so the rest would be
        re-processed forever."""
        queue_path = tmp_path / "queue.json"
        save_queue(
            [
                QueueItem(
                    repo="o/r", pr_number=9, ecosystem=Ecosystem.APT,
                    package_name="github.com/foo/bar", old_version="1.0",
                    new_version="2.0", status=Status.FAILED,
                ),
                QueueItem(
                    repo="o/r", pr_number=9, ecosystem=Ecosystem.GO,
                    package_name="github.com/foo/bar", old_version="1.0",
                    new_version="2.0", status=Status.DONE,
                ),
            ],
            queue_path,
        )
        mock_fetch.return_value = []
        merged = fetch_and_save("o/r", queue_path)
        assert len(merged) == 1
        assert merged[0].ecosystem == Ecosystem.GO
        assert merged[0].status == Status.DONE
