from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

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
        assert detect_ecosystem(pr) == Ecosystem.APT

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
    def test_gh_cli_called_with_correct_args(self, mock_run):
        mock_run.return_value.stdout = "[]"
        fetch_dependabot_prs("octo/cat")
        args = mock_run.call_args
        cmd = args[0][0]
        assert "gh" in cmd
        assert "--repo" in cmd
        assert "octo/cat" in cmd
        assert "--app" in cmd
        assert "dependabot" in cmd


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
    def test_works_with_no_existing_file(self, mock_fetch, tmp_path: Path):
        queue_path = tmp_path / "nonexistent.json"
        mock_fetch.return_value = []
        merged = fetch_and_save("o/r", queue_path)
        assert merged == []
