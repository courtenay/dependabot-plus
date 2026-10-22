"""Gap 2: writes/creates outside the install dir and tmp are detected and HIGH."""
from __future__ import annotations

import pytest

from dependabot_plus.queue.models import Ecosystem, RiskLevel
from dependabot_plus.sandbox.detectors import (
    InotifyWriteDetector,
    RuntimeDetector,
    default_detectors,
)

HOME = "/home/sandbox"


def _evaluate(lines, ecosystem=Ecosystem.NPM):
    det = InotifyWriteDetector(home=HOME)
    return det.evaluate({"file_writes": lines}, ecosystem)


def test_write_to_bashrc_is_high():
    findings = _evaluate([f"MODIFY|{HOME}/.bashrc"])
    assert len(findings) == 1
    assert findings[0].risk == RiskLevel.HIGH
    assert findings[0].category == "shell_rc"
    assert findings[0].path == f"{HOME}/.bashrc"


@pytest.mark.parametrize("path,category", [
    (f"{HOME}/.ssh/authorized_keys", "ssh"),
    (f"{HOME}/.config/autostart/x.desktop", "config"),
    ("/var/spool/cron/crontabs/sandbox", "cron"),
    ("/etc/cron.d/evil", "cron"),
    ("/etc/profile.d/evil.sh", "shell_rc"),
    (f"{HOME}/.profile", "shell_rc"),
    ("/usr/local/lib/node_modules/other-pkg/index.js", "other_package"),
    (f"{HOME}/.hidden-thing", "home_dotfile"),
])
def test_persistence_locations_are_high(path, category):
    findings = _evaluate([f"CREATE|{path}"])
    assert [f.risk for f in findings] == [RiskLevel.HIGH]
    assert findings[0].category == category


@pytest.mark.parametrize("path", [
    "/sandbox/node_modules/foo/build/out.node",
    "/tmp/npm-12345/x",
    "/var/tmp/y",
    f"{HOME}/.npm/_cacache/index-v5/aa",
])
def test_install_dir_tmp_and_tool_cache_are_allowed(path):
    assert _evaluate([f"CREATE|{path}"]) == []


def test_allowed_prefix_matches_on_path_boundary():
    # /tmpevil is not /tmp; /sandbox-evil is not /sandbox
    assert len(_evaluate(["CREATE|/tmpevil/x", "CREATE|/sandbox-evil/y"])) == 2


def test_path_traversal_is_normalised():
    assert len(_evaluate(["CREATE|/sandbox/../etc/cron.d/x"])) == 1


def test_ecosystem_specific_cache_is_not_allowed_for_other_ecosystems():
    path = f"{HOME}/.npm/_cacache/x"
    assert _evaluate([f"CREATE|{path}"], Ecosystem.NPM) == []
    assert len(_evaluate([f"CREATE|{path}"], Ecosystem.GEM)) == 1


def test_noise_lines_ignored_but_garbage_fails_closed():
    assert _evaluate(["Setting up watches.  Beware: since -r was given", "Watches established."]) == []
    findings = _evaluate(["???garbage"])
    assert len(findings) == 1 and findings[0].risk == RiskLevel.HIGH


def test_findings_are_deduplicated_by_path():
    findings = _evaluate([f"MODIFY|{HOME}/.bashrc", f"CLOSE_WRITE,CLOSE|{HOME}/.bashrc"])
    assert len(findings) == 1


def test_container_env_lists_watch_roots():
    env = InotifyWriteDetector(home=HOME).container_env()
    roots = env["WRITE_WATCH_PATHS"].splitlines()
    assert "/root" in roots and "/etc" in roots and "/var/spool" in roots


def test_detector_satisfies_the_interface_a_falco_backend_would_implement():
    class FakeFalco:
        name = "falco"

        def container_env(self):
            return {}

        def evaluate(self, output, ecosystem):
            return []

    assert isinstance(InotifyWriteDetector(home=HOME), RuntimeDetector)
    assert isinstance(FakeFalco(), RuntimeDetector)
    assert [d.name for d in default_detectors()] == ["inotify-writes"]
