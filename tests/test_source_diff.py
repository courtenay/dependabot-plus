from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from dependabot_plus.analysis.source_diff import (
    _diff_dirs,
    _fetch_npm_diff,
    fetch_source_diff,
)
from dependabot_plus.queue.models import Ecosystem, QueueItem


# ---------------------------------------------------------------------------
# _diff_dirs
# ---------------------------------------------------------------------------


class TestDiffDirs:
    def test_identical_directories(self, tmp_path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        (dir_a / "file.txt").write_text("hello\n")
        (dir_b / "file.txt").write_text("hello\n")

        result = _diff_dirs(str(dir_a), str(dir_b))
        assert result == ""

    def test_directories_with_changes(self, tmp_path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        (dir_a / "file.txt").write_text("old content\n")
        (dir_b / "file.txt").write_text("new content\n")

        result = _diff_dirs(str(dir_a), str(dir_b))
        assert "old content" in result
        assert "new content" in result
        assert result != ""

    def test_added_file(self, tmp_path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        (dir_b / "new_file.txt").write_text("added\n")

        result = _diff_dirs(str(dir_a), str(dir_b))
        assert "new_file.txt" in result

    def test_diff_error_raises(self, tmp_path):
        """Return code 2 from diff should raise RuntimeError."""
        with patch("dependabot_plus.analysis.source_diff.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=2, stderr="binary file issue"
            )
            with pytest.raises(RuntimeError, match="diff error"):
                _diff_dirs("/fake/a", "/fake/b")


# ---------------------------------------------------------------------------
# _fetch_npm_diff (mocked subprocess)
# ---------------------------------------------------------------------------


class TestFetchNpmDiff:
    def test_packs_and_extracts_both_versions(self, tmp_path):
        workdir = str(tmp_path)

        call_count = {"n": 0}

        def fake_run(cmd, *, capture_output=True, text=True, cwd=None, check=True):
            call_count["n"] += 1
            # npm pack: create a fake tarball
            if cmd[0] == "npm" and cmd[1] == "pack":
                tarball_name = "fake-pkg-1.0.0.tgz"
                open(os.path.join(cwd, tarball_name), "w").close()
                return MagicMock(returncode=0)
            # tar xzf: create a fake package directory
            if cmd[0] == "tar":
                pkg_dir = os.path.join(cwd, "package")
                os.makedirs(pkg_dir, exist_ok=True)
                (open(os.path.join(pkg_dir, "index.js"), "w")).write("// code\n")
                return MagicMock(returncode=0)
            return MagicMock(returncode=0)

        with patch("dependabot_plus.analysis.source_diff._run", side_effect=fake_run):
            with patch(
                "dependabot_plus.analysis.source_diff._diff_dirs", return_value=""
            ) as mock_diff:
                result = _fetch_npm_diff("fake-pkg", "1.0.0", "2.0.0", workdir)

        assert result == ""
        # Should have called _diff_dirs with old/package and new/package
        args = mock_diff.call_args[0]
        assert args[0].endswith(os.path.join("old", "package"))
        assert args[1].endswith(os.path.join("new", "package"))

    def test_raises_when_no_tarball(self, tmp_path):
        workdir = str(tmp_path)

        def fake_run(cmd, *, capture_output=True, text=True, cwd=None, check=True):
            # npm pack succeeds but creates no .tgz file
            return MagicMock(returncode=0)

        with patch("dependabot_plus.analysis.source_diff._run", side_effect=fake_run):
            with pytest.raises(RuntimeError, match="no tarball"):
                _fetch_npm_diff("fake-pkg", "1.0.0", "2.0.0", workdir)


# ---------------------------------------------------------------------------
# fetch_source_diff — dispatch and cleanup
# ---------------------------------------------------------------------------


class TestFetchSourceDiff:
    def _make_item(self, ecosystem: Ecosystem) -> QueueItem:
        return QueueItem(
            repo="owner/repo",
            pr_number=42,
            ecosystem=ecosystem,
            package_name="some-pkg",
            old_version="1.0.0",
            new_version="2.0.0",
        )

    def test_dispatches_to_npm_fetcher(self):
        item = self._make_item(Ecosystem.NPM)
        with patch(
            "dependabot_plus.analysis.source_diff._fetch_npm_diff",
            return_value="diff output",
        ) as mock_fetcher:
            result = fetch_source_diff(item)

        assert result == "diff output"
        mock_fetcher.assert_called_once()
        args = mock_fetcher.call_args[0]
        assert args[0] == "some-pkg"
        assert args[1] == "1.0.0"
        assert args[2] == "2.0.0"

    def test_dispatches_to_gem_fetcher(self):
        item = self._make_item(Ecosystem.GEM)
        with patch(
            "dependabot_plus.analysis.source_diff._fetch_gem_diff",
            return_value="gem diff",
        ) as mock_fetcher:
            result = fetch_source_diff(item)

        assert result == "gem diff"
        mock_fetcher.assert_called_once()

    def test_dispatches_to_apt_fetcher(self):
        item = self._make_item(Ecosystem.APT)
        with patch(
            "dependabot_plus.analysis.source_diff._fetch_apt_diff",
            return_value="apt diff",
        ) as mock_fetcher:
            result = fetch_source_diff(item)

        assert result == "apt diff"
        mock_fetcher.assert_called_once()

    def test_dispatches_to_pip_fetcher(self):
        item = self._make_item(Ecosystem.PIP)
        with patch(
            "dependabot_plus.analysis.source_diff._fetch_pip_diff",
            return_value="pip diff",
        ) as mock_fetcher:
            result = fetch_source_diff(item)

        assert result == "pip diff"
        mock_fetcher.assert_called_once()

    def test_dispatches_to_docker_fetcher(self):
        item = self._make_item(Ecosystem.DOCKER)
        with patch(
            "dependabot_plus.analysis.source_diff._fetch_docker_diff",
            return_value="docker diff",
        ) as mock_fetcher:
            result = fetch_source_diff(item)

        assert result == "docker diff"
        mock_fetcher.assert_called_once()

    def test_dispatches_to_github_actions_fetcher(self):
        item = self._make_item(Ecosystem.GITHUB_ACTIONS)
        with patch(
            "dependabot_plus.analysis.source_diff._fetch_github_actions_diff",
            return_value="actions diff",
        ) as mock_fetcher:
            result = fetch_source_diff(item)

        assert result == "actions diff"
        mock_fetcher.assert_called_once()

    def test_temp_directory_cleaned_up_on_success(self):
        item = self._make_item(Ecosystem.NPM)
        captured_workdir = {}

        def spy_fetcher(package, old_ver, new_ver, workdir):
            captured_workdir["path"] = workdir
            return "diff"

        with patch(
            "dependabot_plus.analysis.source_diff._fetch_npm_diff",
            side_effect=spy_fetcher,
        ):
            fetch_source_diff(item)

        assert not os.path.exists(captured_workdir["path"])

    def test_temp_directory_cleaned_up_on_error(self):
        item = self._make_item(Ecosystem.NPM)
        captured_workdir = {}

        def failing_fetcher(package, old_ver, new_ver, workdir):
            captured_workdir["path"] = workdir
            raise RuntimeError("boom")

        with patch(
            "dependabot_plus.analysis.source_diff._fetch_npm_diff",
            side_effect=failing_fetcher,
        ):
            with pytest.raises(RuntimeError, match="boom"):
                fetch_source_diff(item)

        assert not os.path.exists(captured_workdir["path"])
