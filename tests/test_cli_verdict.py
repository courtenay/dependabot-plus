"""Gaps 1-4 wired through cli._analyse / cmd_process."""
from __future__ import annotations

import argparse
from unittest.mock import patch

from dependabot_plus import cli
from dependabot_plus.analysis.source_diff import ChecksumMismatch, GoDownloadFailed
from dependabot_plus.queue.models import (
    Ecosystem, QueueItem, RiskLevel, SandboxResult, StaticFindings, Status, Verdict, load_queue, save_queue,
)


def _item(eco, pr=1):
    return QueueItem("o/r", pr, eco, "pkg", "1.0.0", "1.0.1")


def _analyse(item, static_risk=RiskLevel.LOW, sandbox=None, fetch=None, **kw):
    fetch = fetch or ("diff", "/nonexistent-workdir", "/nonexistent/old", "/nonexistent/new")
    with patch.object(cli, "fetch_source_with_dirs", return_value=fetch) as f, \
            patch.object(cli, "scan_diff_for_new_binaries") as b, \
            patch.object(cli, "scan_diff_for_autorun") as a, \
            patch.object(cli, "review_diff", return_value=StaticFindings(risk_level=static_risk, summary="s")), \
            patch.object(cli, "run_sandbox", return_value=sandbox):
        b.return_value.binary_count = 0
        b.return_value.suspicious_count = 0
        b.return_value.findings = []
        a.return_value.has_findings = False
        a.return_value.has_high = False
        a.return_value.findings = []
        if isinstance(fetch, Exception):
            f.side_effect = fetch
        return cli._analyse(item, **kw)


def test_low_llm_verdict_with_high_sandbox_signal_is_high():
    sb = SandboxResult(0, "", detector_findings=[
        {"kind": "file_write", "path": "/home/sandbox/.bashrc", "risk": "high", "category": "shell_rc", "detail": ""}])
    v = _analyse(_item(Ecosystem.NPM), RiskLevel.LOW, sb)
    assert v.risk_level == RiskLevel.HIGH and not v.vetted


def test_low_llm_verdict_on_no_sandbox_ecosystem_is_not_vetted():
    v = _analyse(_item(Ecosystem.GO), RiskLevel.LOW)
    assert v.risk_level == RiskLevel.LOW and not v.vetted


def _default_vetted(eco_value=None):
    return cli.parse_static_vetted(eco_value)


def test_go_vetted_by_default_with_sumdb_ok():
    v = _analyse(_item(Ecosystem.GO), RiskLevel.LOW, static_vetted_ecosystems=_default_vetted())
    assert v.risk_level == RiskLevel.LOW and v.vetted


def test_go_not_vetted_on_checksum_mismatch_by_default():
    v = _analyse(_item(Ecosystem.GO), RiskLevel.LOW, fetch=ChecksumMismatch("mismatch"),
                 static_vetted_ecosystems=_default_vetted())
    assert v.risk_level == RiskLevel.HIGH and not v.vetted


def test_go_not_vetted_when_download_never_verified():
    v = _analyse(_item(Ecosystem.GO), RiskLevel.LOW, fetch=GoDownloadFailed("offline"),
                 static_vetted_ecosystems=_default_vetted())
    assert not v.vetted


def test_docker_and_actions_not_vetted_by_default():
    for eco in (Ecosystem.DOCKER, Ecosystem.GITHUB_ACTIONS):
        v = _analyse(_item(eco), RiskLevel.LOW, static_vetted_ecosystems=_default_vetted())
        assert v.risk_level == RiskLevel.LOW and not v.vetted, eco


def test_empty_static_vetted_disables_go():
    assert _default_vetted("") == frozenset()
    v = _analyse(_item(Ecosystem.GO), RiskLevel.LOW, static_vetted_ecosystems=_default_vetted(""))
    assert not v.vetted


def test_static_vetted_default_is_go_only_and_overridable():
    assert _default_vetted() == frozenset({Ecosystem.GO})
    assert _default_vetted("go,docker") == frozenset({Ecosystem.GO, Ecosystem.DOCKER})


def test_go_checksum_mismatch_is_high():
    v = _analyse(_item(Ecosystem.GO), RiskLevel.LOW, fetch=ChecksumMismatch("mismatch"),
                 static_vetted_ecosystems=frozenset({Ecosystem.GO}))
    assert v.risk_level == RiskLevel.HIGH and not v.vetted


def test_non_allowlisted_dns_in_monitor_mode_is_medium():
    sb = SandboxResult(0, "", network_attempts=[{"type": "dns", "query": "A? evil.example"}])
    v = _analyse(_item(Ecosystem.NPM), RiskLevel.LOW, sb)
    assert v.risk_level == RiskLevel.MEDIUM


def _run_process(tmp_path, verdicts):
    q = tmp_path / "q.json"
    items = [_item(Ecosystem.NPM, pr=7)]
    save_queue(items, q)
    args = argparse.Namespace(queue_file=str(q), pr=None, mode="monitor", static_vetted=None)
    with patch.object(cli, "_analyse", return_value=verdicts), patch.object(cli, "post_report"), \
            patch.object(cli, "add_label") as label:
        cli.cmd_process(args)
    assert load_queue(q)[0].status == Status.DONE
    return label


def _verdict(risk, vetted):
    return Verdict(risk, StaticFindings(), SandboxResult(0, ""), "s", vetted=vetted)


def test_label_added_only_when_low_and_vetted(tmp_path):
    assert _run_process(tmp_path, _verdict(RiskLevel.LOW, True)).called


def test_label_not_added_for_low_but_unvetted(tmp_path):
    assert not _run_process(tmp_path, _verdict(RiskLevel.LOW, False)).called
