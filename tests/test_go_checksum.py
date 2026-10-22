"""Gap 4: GONOSUMDB removed; a Go checksum mismatch is raised (and scored HIGH)."""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from dependabot_plus.analysis import source_diff
from dependabot_plus.analysis.source_diff import ChecksumMismatch, GoDownloadFailed, _fetch_go_diff

MISMATCH = (
    "verifying github.com/foo/bar@v1.2.3: checksum mismatch\n"
    "\tdownloaded: h1:AAAA\n\tsum.golang.org: h1:BBBB\n\nSECURITY ERROR\n"
    "This download does NOT match the one reported by the checksum server.\n"
)


def test_script_does_not_disable_checksum_database():
    script = source_diff._go_download_script("github.com/foo/bar", "v1.2.3")
    assert "GONOSUMDB" not in script
    assert "GONOSUMCHECK" not in script
    assert "|| exit 1" in script  # a failed download must not look like an empty success
    assert "GOFLAGS=-insecure" not in script


def test_no_gonosumdb_anywhere_in_package():
    root = os.path.dirname(source_diff.__file__)
    for dirpath, _, files in os.walk(os.path.dirname(root)):
        for f in files:
            if f.endswith((".py", ".sh", ".Dockerfile")):
                assert "GONOSUMDB" not in open(os.path.join(dirpath, f)).read(), f


def test_checksum_mismatch_raises(tmp_path):
    proc = MagicMock(returncode=1, stdout="", stderr=MISMATCH)
    with patch("dependabot_plus.analysis.source_diff.subprocess.run", return_value=proc):
        with pytest.raises(ChecksumMismatch):
            _fetch_go_diff("github.com/foo/bar", "1.2.2", "1.2.3", str(tmp_path))


def test_other_download_failure_is_not_a_mismatch(tmp_path):
    proc = MagicMock(returncode=1, stdout="", stderr="dial tcp: lookup proxy.golang.org: no such host")
    with patch("dependabot_plus.analysis.source_diff.subprocess.run", return_value=proc):
        with pytest.raises(GoDownloadFailed):
            _fetch_go_diff("github.com/foo/bar", "1.2.2", "1.2.3", str(tmp_path))
