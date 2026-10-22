from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from dependabot_plus.queue.models import Ecosystem, RiskLevel, SandboxResult, Verdict, StaticFindings, QueueItem
from dependabot_plus.report.github import format_report
from dependabot_plus.risk import assess
from dependabot_plus.sandbox import falco as F
from dependabot_plus.sandbox.canary import CANARY_FILE_PATHS
from dependabot_plus.sandbox.detectors import RuntimeDetector, write_allowlist
from dependabot_plus.sandbox.runner import _run_container

FIXTURE = Path(__file__).parent / "fixtures" / "falco_events.jsonl"
RUN = "abc123def456"
INSTALL_END = 1792710295.5  # between the first connect and the canary reads


def _events() -> list[dict]:
    return F.parse_events(FIXTURE.read_text())


def _output(events=None, **extra) -> dict:
    out = {"falco_events": _events() if events is None else events, "install_end": INSTALL_END}
    out.update(extra)
    return out


def _by_kind(findings):
    return {(f.kind, f.path, f.phase) for f in findings}


# --- parsing / detector -------------------------------------------------

def test_parse_events_skips_truncated_last_line():
    text = FIXTURE.read_text()
    assert text.splitlines()[-1].startswith('{"hostname"')  # the fixture ends mid-line, as in the spike
    events = F.parse_events(text)
    assert len(events) == 10
    assert all("rule" in e for e in events)


def test_detector_is_a_runtime_detector_with_no_container_env():
    d = F.FalcoDetector(RUN)
    assert isinstance(d, RuntimeDetector)
    assert d.container_env() == {}


def test_findings_are_shadow_and_dedupe():
    findings = F.FalcoDetector(RUN).evaluate(_output(), Ecosystem.NPM)
    assert findings and all(f.shadow for f in findings)
    kinds = {f.kind for f in findings}
    assert kinds == {"falco_connect", "falco_canary_read", "falco_write_outside", "falco_exec"}
    # two identical id_rsa reads collapse to one finding
    assert sum(1 for f in findings if f.kind == "falco_canary_read") == 1
    assert all(f.to_dict()["shadow"] is True for f in findings)


def test_phase_tagging_against_install_end():
    findings = F.FalcoDetector(RUN).evaluate(_output(), Ecosystem.NPM)
    got = _by_kind(findings)
    assert ("falco_connect", "172.17.0.8:33790->146.75.38.132:443", "install") in got
    assert ("falco_canary_read", "/root/.ssh/id_rsa", "post_install") in got
    assert ("falco_exec", "curl -sS https://example.com -o /dev/null", "post_install") in got


def test_phase_defaults_to_install_without_marker():
    out = _output()
    del out["install_end"]
    assert {f.phase for f in F.FalcoDetector(RUN).evaluate(out, Ecosystem.NPM)} == {"install"}


def test_events_from_other_runs_are_ignored():
    assert F.FalcoDetector("ffffffffffff").evaluate(_output(), Ecosystem.NPM) == []


# --- label scoping / rules ----------------------------------------------

def test_rendered_rules_scope_to_run_label_and_use_dot_free_key():
    text = F.render_rules(RUN, Ecosystem.NPM)
    assert f'container.labels contains "dp_run:{RUN}"' in text
    assert "__DP_" not in text
    assert "evt.dir" not in text
    assert "container.label." not in text  # dotted label keys break rule parsing


def test_rendered_rules_reuse_canary_and_allowlist_paths():
    text = F.render_rules(RUN, Ecosystem.GEM)
    for p in CANARY_FILE_PATHS:
        assert f'"{p}"' in text
        assert f'"/home/sandbox{p[len("/root"):]}"' in text  # entrypoint remaps /root to the sandbox home
    for p in write_allowlist(Ecosystem.GEM):
        assert f'"{p}"' in text
    assert "/usr/local/bundle" in text
    assert "/usr/local/bundle" not in F.render_rules(RUN, Ecosystem.NPM)


def test_rendered_rules_are_valid_yaml_when_pyyaml_available():
    yaml = pytest.importorskip("yaml")
    docs = yaml.safe_load(F.render_rules(RUN, Ecosystem.NPM))
    assert {d["rule"] for d in docs if "rule" in d} >= set(F._RULES) | {"DP Heartbeat"}


def test_sandbox_container_gets_label_only_in_shadow_mode(tmp_path):
    seen = []

    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "run"]:
            seen.append(cmd)
        return SimpleNamespace(returncode=0, stdout=json.dumps({"install_exit_code": 0}), stderr="")

    class FakeSidecar:
        def __init__(self, run_id, eco): self.run_id = run_id
        def start(self): pass
        def finish(self): return []
        def close(self): pass

    with patch("dependabot_plus.sandbox.runner.subprocess.run", fake_run), \
         patch("dependabot_plus.sandbox.runner.FalcoSidecar", FakeSidecar):
        _run_container("img", "true", Ecosystem.NPM, falco="shadow")
        _run_container("img", "true", Ecosystem.NPM)
    shadow_cmd, plain_cmd = seen
    labels = [shadow_cmd[i + 1] for i, a in enumerate(shadow_cmd) if a == "--label"]
    assert len(labels) == 1 and labels[0].startswith("dp_run=") and "." not in labels[0].split("=")[0]
    assert "--label" not in plain_cmd


# --- shadow findings never score ----------------------------------------

def _dynamic(shadow_findings):
    return SandboxResult(
        install_exit_code=0, install_logs="",
        detector_findings=[f.to_dict() for f in shadow_findings],
    )


def test_shadow_findings_do_not_change_risk_or_vetting():
    shadow = F.FalcoDetector(RUN).evaluate(_output(), Ecosystem.NPM)
    assert any(f.risk == RiskLevel.HIGH for f in shadow)
    clean = assess(Ecosystem.NPM, RiskLevel.LOW, _dynamic([]), sandbox_ran=True)
    with_shadow = assess(Ecosystem.NPM, RiskLevel.LOW, _dynamic(shadow), sandbox_ran=True)
    assert clean.risk == with_shadow.risk == RiskLevel.LOW
    assert clean.vetted and with_shadow.vetted
    assert with_shadow.reasons == clean.reasons == []


def test_non_shadow_detector_findings_still_score():
    f = F.DetectorFinding("file_write", "/etc/x", RiskLevel.HIGH, "system_config", "bad")
    a = assess(Ecosystem.NPM, RiskLevel.LOW, _dynamic([f]), sandbox_ran=True)
    assert a.risk == RiskLevel.HIGH and not a.vetted


# --- status: fail closed -------------------------------------------------

def test_status_ok():
    assert F.FalcoDetector(RUN).status(_output()).state == F.STATE_OK


def test_status_unverified_without_heartbeat():
    events = [e for e in _events() if e["rule"] != "DP Heartbeat"]
    st = F.FalcoDetector(RUN).status(_output(events))
    assert st.state == F.STATE_UNVERIFIED and "heartbeat" in st.reason


@pytest.mark.parametrize("field", ["scap.n_drops", "falco.outputs_queue_num_drops"])
def test_status_unverified_when_drops(field):
    events = _events()
    for e in events:
        if e["rule"].startswith("Falco internal"):
            e["output_fields"][field] = 7
    st = F.FalcoDetector(RUN).status(_output(events))
    assert st.state == F.STATE_UNVERIFIED and "7" in st.reason


def test_status_unverified_without_metrics_snapshot():
    events = [e for e in _events() if not e["rule"].startswith("Falco internal")]
    assert F.FalcoDetector(RUN).status(_output(events)).state == F.STATE_UNVERIFIED


def test_unverified_still_emits_shadow_findings():
    events = [e for e in _events() if e["rule"] != "DP Heartbeat"]
    assert F.FalcoDetector(RUN).evaluate(_output(events), Ecosystem.NPM)


# --- sidecar lifecycle ---------------------------------------------------

class FakeDocker:
    """Records docker calls; the Falco container 'runs' unless told otherwise."""

    def __init__(self, *, run_rc=0, running=True, emit_heartbeat=True, logs="probe failed"):
        self.calls, self.run_rc, self.running = [], run_rc, running
        self.emit_heartbeat, self.logs = emit_heartbeat, logs
        self.sidecar = None

    def __call__(self, *args, **kw):
        self.calls.append(args)
        if args[0] == "run" and args[1] == "-d":
            return SimpleNamespace(returncode=self.run_rc, stdout="", stderr="no such image")
        if args[0] == "inspect":
            return SimpleNamespace(returncode=0, stdout="true\n" if self.running else "false\n", stderr="")
        if args[0] == "logs":
            return SimpleNamespace(returncode=0, stdout=self.logs, stderr="")
        if args[0] == "run" and "--entrypoint" in args and self.emit_heartbeat:
            Path(self.sidecar.events_path).write_text(FIXTURE.read_text())
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def _sidecar(docker):
    sc = F.FalcoSidecar(RUN, Ecosystem.NPM, docker=docker, ready_timeout=0, flush_wait=0, poll=0,
                        sleep=lambda s: None)
    docker.sidecar = sc
    return sc


def test_sidecar_start_pins_digest_and_flags_then_close_removes():
    docker = FakeDocker()
    sc = _sidecar(docker)
    sc.start()
    run = next(c for c in docker.calls if c[:2] == ("run", "-d"))
    digest = "sha256:88c01fa17bcc03c990a2691d08e7d43d746e32b07dbe9c6eb77bfdb3646cec41"
    assert F.FALCO_IMAGE in run and F.FALCO_IMAGE.endswith("@" + digest)
    assert "--privileged" in run and "engine.kind=modern_ebpf" in run and "metrics.enabled=true" in run
    assert sc.heartbeat_seen
    tmp = sc._tmp
    sc.finish()
    sc.close()
    assert ("stop", "-t", "10", f"dp-falco-{RUN}") in docker.calls
    assert ("rm", "-f", f"dp-falco-{RUN}") in docker.calls
    assert tmp and not Path(tmp).exists()


def test_sidecar_start_failure_raises_unavailable_with_reason():
    sc = _sidecar(FakeDocker(run_rc=1))
    with pytest.raises(F.FalcoUnavailable, match="no such image"):
        sc.start()
    sc.close()


def test_sidecar_that_exits_during_readiness_is_unavailable():
    sc = _sidecar(FakeDocker(running=False, logs="Error: unable to load the BPF probe"))
    with pytest.raises(F.FalcoUnavailable, match="BPF probe"):
        sc.start()
    sc.close()


def test_runner_records_unavailable_and_continues_the_vet():
    class Boom:
        def __init__(self, run_id, eco): pass
        def start(self): raise F.FalcoUnavailable("probe failed")
        def close(self): pass

    def fake_run(cmd, **kw):
        assert not any(a == "--label" for a in cmd)  # no sidecar, no label
        return SimpleNamespace(returncode=0, stdout=json.dumps({"install_exit_code": 0}), stderr="")

    with patch("dependabot_plus.sandbox.runner.subprocess.run", fake_run), \
         patch("dependabot_plus.sandbox.runner.FalcoSidecar", Boom):
        res = _run_container("img", "true", Ecosystem.NPM, falco="shadow")
    assert res.install_exit_code == 0
    assert res.falco == {"state": "unavailable", "reason": "Falco unavailable: probe failed"}
    assert res.detector_findings == []


def test_runner_always_closes_sidecar_even_when_the_container_run_raises():
    closed = []

    class Sc:
        def __init__(self, run_id, eco): pass
        def start(self): pass
        def finish(self): return []
        def close(self): closed.append(True)

    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)

    with patch("dependabot_plus.sandbox.runner.subprocess.run", fake_run), \
         patch("dependabot_plus.sandbox.runner.FalcoSidecar", Sc), pytest.raises(subprocess.TimeoutExpired):
        _run_container("img", "true", Ecosystem.NPM, falco="shadow")
    assert closed == [True]


def test_runner_merges_events_into_result():
    class Sc:
        def __init__(self, run_id, eco): self.run_id = run_id
        def start(self): pass
        def finish(self):
            return F.parse_events(FIXTURE.read_text().replace(RUN, self.run_id))
        def close(self): pass

    def fake_run(cmd, **kw):
        return SimpleNamespace(
            returncode=0, stderr="",
            stdout=json.dumps({"install_exit_code": 0, "install_end": INSTALL_END}))

    with patch("dependabot_plus.sandbox.runner.subprocess.run", fake_run), \
         patch("dependabot_plus.sandbox.runner.FalcoSidecar", Sc):
        res = _run_container("img", "true", Ecosystem.NPM, falco="shadow")
    assert res.falco["state"] == "ok"
    assert res.detector_findings and all(f["shadow"] for f in res.detector_findings)


# --- report ---------------------------------------------------------------

def _verdict(dynamic):
    return Verdict(RiskLevel.LOW, StaticFindings(), dynamic, "ok", vetted=True)


def _item():
    return QueueItem("o/r", 1, Ecosystem.NPM, "is-number", "6.0.0", "7.0.0")


def test_report_has_collapsed_falco_section_beside_scored_findings():
    scored = F.DetectorFinding("file_write", "/etc/evil", RiskLevel.HIGH, "system_config", "wrote /etc/evil")
    shadow = F.FalcoDetector(RUN).evaluate(_output(), Ecosystem.NPM)
    dyn = _dynamic([scored, *shadow])
    dyn.falco = {"state": "unverified", "reason": "no heartbeat event seen"}
    md = format_report(_item(), _verdict(dyn))
    assert "<details><summary>Falco (shadow, not scored): UNVERIFIED," in md
    falco_part = md.split("<details><summary>Falco (shadow")[1]
    assert "/etc/evil" in falco_part                          # current detectors' finding, for comparison
    assert "[post_install]" in falco_part and "/root/.ssh/id_rsa" in falco_part
    assert "no heartbeat event seen" in falco_part
    scored_part = md.split("<details><summary>Falco")[0]
    assert "/root/.ssh/id_rsa" not in scored_part             # shadow findings are not in the scored section


def test_report_has_no_falco_section_when_off():
    md = format_report(_item(), _verdict(_dynamic([])))
    assert "Falco" not in md


# --- cli -------------------------------------------------------------------

def test_cli_flag_defaults_off_and_accepts_shadow():
    from dependabot_plus.cli import build_parser
    p = build_parser()
    assert p.parse_args(["--repo", "o/r", "process"]).falco == "off"
    assert p.parse_args(["--repo", "o/r", "run", "--falco", "shadow"]).falco == "shadow"
    with pytest.raises(SystemExit):
        p.parse_args(["--repo", "o/r", "process", "--falco", "on"])


# --- integration (needs Docker; deselect with -m "not integration") -------

@pytest.mark.integration
@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_rules_validate_with_falco_v(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(F.render_rules(RUN, Ecosystem.NPM))
    res = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{tmp_path}:/r:ro", F.FALCO_IMAGE, "falco", "-V", "/r/rules.yaml"],
        capture_output=True, text=True, timeout=300,
    )
    assert res.returncode == 0, res.stdout + res.stderr
