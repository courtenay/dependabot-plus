"""Falco shadow-mode detector and per-run sidecar.

Falco watches the sandbox from outside (modern eBPF, privileged sidecar) and
records findings. In shadow mode those findings are flagged ``shadow=True`` and
``risk.assess`` ignores them, so Falco can be compared against the built-in
detectors without changing any score or the deps-vetted label.

Fail closed for the shadow signal: no heartbeat seen, or any dropped events,
marks the Falco section "unverified" in the report; a sidecar that cannot start
is "unavailable" and the vet continues without it.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from dependabot_plus.queue.models import Ecosystem, RiskLevel
from dependabot_plus.sandbox.canary import CANARY_FILE_PATHS
from dependabot_plus.sandbox.detectors import DetectorFinding, write_allowlist

log = logging.getLogger("dependabot_plus")

FALCO_IMAGE = (
    "falcosecurity/falco:0.43.0"
    "@sha256:88c01fa17bcc03c990a2691d08e7d43d746e32b07dbe9c6eb77bfdb3646cec41"
)
RULES_TEMPLATE = Path(__file__).parent / "falco_rules" / "rules.yaml"

SANDBOX_HOME = "/home/sandbox"
RUN_LABEL = "dp_run"   # dot-free: a dotted label key breaks Falco rule parsing
HEARTBEAT_LABEL = "dp_hb"

STATE_OK = "ok"
STATE_UNVERIFIED = "unverified"
STATE_UNAVAILABLE = "unavailable"

# rule name -> (finding kind, risk, category)
_RULES: dict[str, tuple[str, RiskLevel, str]] = {
    "DP Canary read": ("canary_read", RiskLevel.HIGH, "canary"),
    "DP Write outside allowed": ("write_outside", RiskLevel.HIGH, "write"),
    "DP Suspicious exec": ("exec", RiskLevel.HIGH, "exec"),
    "DP Outbound connect": ("connect", RiskLevel.MEDIUM, "network"),
}
_HEARTBEAT_RULE = "DP Heartbeat"
_METRICS_RULE_PREFIX = "Falco internal: metrics"
# Cumulative loss counters in Falco's metrics snapshots: kernel event drops and
# alerts lost between the engine and the output queue.
_DROP_FIELDS = ("scap.n_drops", "falco.outputs_queue_num_drops")


class FalcoUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class FalcoStatus:
    state: str
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --- rules --------------------------------------------------------------

def label_fragment(run_id: str) -> str:
    """What Falco shows in ``container.labels`` for ``docker run --label dp_run=<id>``."""
    return f"{RUN_LABEL}:{run_id}"


def _remap_home(path: str) -> list[str]:
    # The entrypoint lays canary files under the sandbox user's home, not /root.
    paths = [path]
    if path.startswith("/root/"):
        paths.append(SANDBOX_HOME + path[len("/root"):])
    return paths


def render_rules(run_id: str, ecosystem: Ecosystem) -> str:
    canary = [p for c in CANARY_FILE_PATHS for p in _remap_home(c)]
    text = RULES_TEMPLATE.read_text()
    return (
        text.replace("__DP_RUN_ID__", run_id)
        .replace("__DP_CANARY_PATHS__", json.dumps(canary))
        .replace("__DP_WRITE_ALLOWED__", json.dumps(write_allowlist(ecosystem, SANDBOX_HOME)))
    )


# --- event parsing ------------------------------------------------------

def parse_events(text: str) -> list[dict]:
    """Parse Falco JSON-lines output; skips blank or truncated lines."""
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if isinstance(ev, dict):
            events.append(ev)
    return events


def event_time(ev: dict) -> float | None:
    """Event time as epoch seconds (output_fields evt.time.iso8601 is epoch ns)."""
    fields = ev.get("output_fields") or {}
    ns = fields.get("evt.time.iso8601")
    if isinstance(ns, (int, float)):
        return ns / 1e9
    return None


def phase_of(ev: dict, install_end: float | None) -> str:
    t = event_time(ev)
    if t is None or not install_end:
        return "install"
    return "post_install" if t > install_end else "install"


def _in_run(ev: dict, run_id: str) -> bool:
    labels = str((ev.get("output_fields") or {}).get("container.labels", ""))
    return label_fragment(run_id) in labels


def drop_count(events: list[dict]) -> int | None:
    """Highest cumulative drop counter in Falco's metrics snapshots; None if none seen."""
    seen = False
    worst = 0
    for ev in events:
        if not str(ev.get("rule", "")).startswith(_METRICS_RULE_PREFIX):
            continue
        for key, val in (ev.get("output_fields") or {}).items():
            if key in _DROP_FIELDS:
                try:
                    worst = max(worst, int(float(val)))
                    seen = True
                except (TypeError, ValueError):
                    continue
    return worst if seen else None


# --- detector -----------------------------------------------------------

class FalcoDetector:
    """RuntimeDetector reading the Falco events merged into the sandbox report."""

    name = "falco-shadow"

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id

    def container_env(self) -> dict[str, str]:
        return {}

    def _events(self, output: dict) -> list[dict]:
        return [e for e in output.get("falco_events", []) if isinstance(e, dict)]

    def evaluate(self, output: dict, ecosystem: Ecosystem) -> list[DetectorFinding]:
        install_end = output.get("install_end")
        findings: dict[tuple, DetectorFinding] = {}
        for ev in self._events(output):
            spec = _RULES.get(ev.get("rule", ""))
            if spec is None or not _in_run(ev, self.run_id):
                continue
            kind, risk, category = spec
            fields = ev.get("output_fields") or {}
            if kind == "exec":
                path = str(fields.get("proc.cmdline") or fields.get("proc.name") or "?")
            else:
                path = str(fields.get("fd.name") or fields.get("proc.name") or "?")
            phase = phase_of(ev, install_end)
            key = (kind, path, phase)
            if key in findings:
                continue
            proc = fields.get("proc.name", "?")
            findings[key] = DetectorFinding(
                kind=f"falco_{kind}", path=path, risk=risk, category=category,
                detail=f"falco {kind} by {proc} ({phase}): {path}",
                shadow=True, phase=phase,
            )
        return list(findings.values())

    def status(self, output: dict) -> FalcoStatus:
        unavailable = output.get("falco_unavailable")
        if unavailable:
            return FalcoStatus(STATE_UNAVAILABLE, f"Falco unavailable: {unavailable}")
        events = self._events(output)
        if not any(e.get("rule") == _HEARTBEAT_RULE for e in events):
            return FalcoStatus(STATE_UNVERIFIED, "no heartbeat event seen")
        drops = drop_count(events)
        if drops is None:
            return FalcoStatus(STATE_UNVERIFIED, "no drop-counter snapshot seen")
        if drops > 0:
            return FalcoStatus(STATE_UNVERIFIED, f"Falco dropped {drops} event(s)")
        return FalcoStatus(STATE_OK)


# --- sidecar ------------------------------------------------------------

Runner = Callable[..., "subprocess.CompletedProcess"]


def _docker(*args: str, timeout: int = 120, **kw) -> "subprocess.CompletedProcess":
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, **kw)


class FalcoSidecar:
    """One Falco container per vet run: start, wait for heartbeat, collect, remove."""

    def __init__(
        self, run_id: str, ecosystem: Ecosystem, *, docker: Runner = _docker,
        ready_timeout: float = 60.0, flush_wait: float = 3.0, poll: float = 3.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.run_id = run_id
        self.ecosystem = ecosystem
        self.name = f"dp-falco-{run_id}"
        self._docker = docker
        self._ready_timeout = ready_timeout
        self._flush_wait = flush_wait
        self._poll = poll
        self._sleep = sleep
        self._tmp: str | None = None
        self.heartbeat_seen = False

    @property
    def events_path(self) -> str:
        assert self._tmp
        return os.path.join(self._tmp, "out", "events.json")

    def _read_events(self) -> list[dict]:
        try:
            return parse_events(Path(self.events_path).read_text(errors="replace"))
        except OSError:
            return []

    def start(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="depbot_falco_")
        rules_dir = os.path.join(self._tmp, "rules")
        out_dir = os.path.join(self._tmp, "out")
        os.makedirs(rules_dir)
        os.makedirs(out_dir)
        Path(rules_dir, "rules.yaml").write_text(render_rules(self.run_id, self.ecosystem))
        Path(self.events_path).touch()
        os.chmod(out_dir, 0o777)
        os.chmod(self.events_path, 0o666)

        res = self._docker(
            "run", "-d", "--name", self.name, "--privileged",
            "-v", "/var/run/docker.sock:/host/var/run/docker.sock",
            "-v", "/proc:/host/proc:ro", "-v", "/etc:/host/etc:ro",
            "-v", f"{rules_dir}:/etc/dp:ro", "-v", f"{out_dir}:/out",
            FALCO_IMAGE, "falco",
            "-r", "/etc/dp/rules.yaml",
            "-o", "engine.kind=modern_ebpf",
            "-o", "json_output=true", "-o", "json_include_output_property=true",
            "-o", "json_include_output_fields_property=true",
            "-o", "stdout_output.enabled=false",
            "-o", "file_output.enabled=true", "-o", "file_output.keep_alive=false",
            "-o", "file_output.filename=/out/events.json",
            "-o", "metrics.enabled=true", "-o", "metrics.interval=2s",
            "-o", "metrics.output_rule=true",
            "-o", "metrics.kernel_event_counters_enabled=true",
            "-o", "metrics.rules_counters_enabled=false",
            "-o", "metrics.resource_utilization_enabled=false",
            "-o", "metrics.state_counters_enabled=false",
            "-o", "metrics.libbpf_stats_enabled=false",
        )
        if res.returncode != 0:
            raise FalcoUnavailable((res.stderr or res.stdout or "docker run failed").strip()[-300:])
        self._wait_ready()

    def _running(self) -> bool:
        res = self._docker("inspect", "-f", "{{.State.Running}}", self.name)
        return res.returncode == 0 and res.stdout.strip() == "true"

    def _fail_reason(self) -> str:
        res = self._docker("logs", "--tail", "5", self.name)
        text = ((res.stdout or "") + (res.stderr or "")).strip()
        return text[-300:] or "Falco container exited"

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + self._ready_timeout
        while True:
            if not self._running():
                raise FalcoUnavailable(self._fail_reason())
            # Probe: open a known file from a labelled sibling container.
            self._docker(
                "run", "--rm", "--label", f"{HEARTBEAT_LABEL}={self.run_id}",
                "--entrypoint", "cat", FALCO_IMAGE, "/etc/os-release",
            )
            self._sleep(self._poll)
            if any(e.get("rule") == _HEARTBEAT_RULE for e in self._read_events()):
                self.heartbeat_seen = True
                return
            if time.monotonic() >= deadline:
                # Running but silent: the install proceeds; the section is marked unverified.
                log.warning("  Falco: no heartbeat within %.0fs; results will be unverified",
                            self._ready_timeout)
                return

    def finish(self) -> list[dict]:
        """Let Falco's file output catch up, stop it (flushes), and return all events."""
        self._sleep(self._flush_wait)
        self._docker("stop", "-t", "10", self.name, timeout=30)
        return self._read_events()

    def close(self) -> None:
        """Always remove the container and temp dir; never raises."""
        try:
            self._docker("rm", "-f", self.name, timeout=30)
        except Exception:
            log.exception("  Falco: failed to remove container %s", self.name)
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None
