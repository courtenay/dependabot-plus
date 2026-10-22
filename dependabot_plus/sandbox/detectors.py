"""Runtime detectors: the seam between the sandbox and whatever watches it.

A detector has two halves:
  * ``container_env()`` - env vars handed to the sandbox container so the
    in-container collector knows what to watch.
  * ``evaluate(output, ecosystem)`` - turns the container's JSON output into
    ``DetectorFinding``s that the risk policy scores.

``InotifyWriteDetector`` is the minimal implementation. ``FalcoDetector``
(sandbox/falco.py) implements the same protocol in shadow mode: its findings
carry ``shadow=True`` and the risk policy ignores them.
"""
from __future__ import annotations

import posixpath
from dataclasses import asdict, dataclass
from typing import Protocol, runtime_checkable

from dependabot_plus.queue.models import Ecosystem, RiskLevel


@dataclass(frozen=True)
class DetectorFinding:
    kind: str
    path: str
    risk: RiskLevel
    category: str
    detail: str
    # Shadow findings are recorded and reported but never scored (see risk.assess).
    shadow: bool = False
    # "install" / "post_install" when the detector can tell; "" otherwise.
    phase: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk"] = self.risk.value
        return d


@runtime_checkable
class RuntimeDetector(Protocol):
    name: str

    def container_env(self) -> dict[str, str]: ...

    def evaluate(self, output: dict, ecosystem: Ecosystem) -> list[DetectorFinding]: ...


# Writes anywhere under these are expected during an install.
_ALWAYS_ALLOWED = ("/sandbox", "/tmp", "/var/tmp", "/var/log", "/dev", "/proc")

# Home-relative tool caches/install targets, per ecosystem.
_HOME_ALLOWED: dict[Ecosystem, tuple[str, ...]] = {
    Ecosystem.NPM: (".npm", ".node-gyp", ".cache/node-gyp"),
    Ecosystem.GEM: (".gem/ruby", ".local/share/gem", ".bundle"),
    Ecosystem.PIP: (".local/lib", ".local/bin", ".cache/pip", ".pip"),
}
# Non-home install targets, per ecosystem.
_SYSTEM_ALLOWED: dict[Ecosystem, tuple[str, ...]] = {
    Ecosystem.GEM: ("/usr/local/bundle",),
}

_WATCH_ROOTS = ("/root", "/etc", "/var/spool", "/usr/local", "/usr/lib", "/opt", "/srv")

_SHELL_RC = {
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
    ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".inputrc",
}


def write_allowlist(ecosystem: Ecosystem, home: str = "/home/sandbox") -> list[str]:
    """Path prefixes where writes are expected for ``ecosystem`` (shared with the Falco rules)."""
    allowed = list(_ALWAYS_ALLOWED)
    allowed.extend(_SYSTEM_ALLOWED.get(ecosystem, ()))
    allowed.extend(f"{home}/{rel}" for rel in _HOME_ALLOWED.get(ecosystem, ()))
    return allowed


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


class InotifyWriteDetector:
    """Flags create/modify/move events outside the install dir and tmp."""

    name = "inotify-writes"

    def __init__(self, home: str = "/home/sandbox") -> None:
        self.home = home

    def container_env(self) -> dict[str, str]:
        return {"WRITE_WATCH_PATHS": "\n".join(_WATCH_ROOTS)}

    def _allowed(self, path: str, ecosystem: Ecosystem) -> bool:
        if any(_under(path, p) for p in _ALWAYS_ALLOWED):
            return True
        if any(_under(path, p) for p in _SYSTEM_ALLOWED.get(ecosystem, ())):
            return True
        return any(_under(path, f"{self.home}/{rel}") for rel in _HOME_ALLOWED.get(ecosystem, ()))

    def _category(self, path: str) -> str:
        home = self.home
        base = posixpath.basename(path)
        if _under(path, f"{home}/.ssh") or _under(path, "/root/.ssh"):
            return "ssh"
        if (path.startswith("/etc/cron") or _under(path, "/var/spool/cron")
                or _under(path, "/var/spool/anacron") or path == "/etc/crontab"):
            return "cron"
        if _under(path, f"{home}/.config") or _under(path, "/root/.config"):
            return "config"
        if (base in _SHELL_RC and posixpath.dirname(path) in (home, "/root")) or path in (
                "/etc/profile", "/etc/bash.bashrc", "/etc/environment") or _under(path, "/etc/profile.d"):
            return "shell_rc"
        if any(_under(path, p) for p in (
                "/usr/local/lib", "/usr/lib", "/usr/local/bin", "/usr/local/bundle", "/opt", "/srv")):
            return "other_package"
        if path.startswith(("/etc/", "/etc")):
            return "system_config"
        if path.startswith((home + "/", "/root/")) and base.startswith("."):
            return "home_dotfile"
        if path.startswith((home + "/", "/root/")):
            return "home"
        return "other"

    def evaluate(self, output: dict, ecosystem: Ecosystem) -> list[DetectorFinding]:
        findings: dict[str, DetectorFinding] = {}
        for raw in output.get("file_writes", []):
            line = str(raw).strip()
            if not line or "Setting up watches" in line or "Watches established" in line:
                continue
            events, sep, path = line.partition("|")
            if not sep or not path.startswith("/"):
                # Unparseable: fail closed rather than drop it.
                findings.setdefault(line, DetectorFinding(
                    "file_write", line, RiskLevel.HIGH, "unparsed",
                    f"unparseable write event: {line[:200]}"))
                continue
            path = posixpath.normpath(path)
            if self._allowed(path, ecosystem) or path in findings:
                continue
            category = self._category(path)
            findings[path] = DetectorFinding(
                "file_write", path, RiskLevel.HIGH, category,
                f"{events or 'WRITE'} outside install dir/tmp ({category}): {path}")
        return list(findings.values())


def default_detectors() -> list[RuntimeDetector]:
    return [InotifyWriteDetector()]
