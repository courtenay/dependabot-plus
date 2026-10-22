"""Gap 3: LLM verdict can raise risk but never lower it; no-evidence LOW is not 'vetted'."""
from __future__ import annotations

from dependabot_plus.queue.models import Ecosystem, RiskLevel, SandboxResult
from dependabot_plus.risk import assess

CLEAN = SandboxResult(install_exit_code=0, install_logs="ok")


def test_low_llm_with_high_sandbox_signal_stays_high():
    dyn = SandboxResult(install_exit_code=0, install_logs="", file_accesses=[{"raw": "/home/sandbox/.ssh/id_rsa OPEN"}])
    a = assess(Ecosystem.NPM, RiskLevel.LOW, dyn, sandbox_ran=True)
    assert a.risk == RiskLevel.HIGH
    assert not a.vetted


def test_low_llm_with_detector_write_finding_stays_high():
    dyn = SandboxResult(
        install_exit_code=0, install_logs="",
        detector_findings=[{"kind": "file_write", "path": "/home/sandbox/.bashrc", "risk": "high",
                            "category": "shell_rc", "detail": "x"}],
    )
    assert assess(Ecosystem.NPM, RiskLevel.LOW, dyn, sandbox_ran=True).risk == RiskLevel.HIGH


def test_low_llm_with_non_allowlisted_dns_is_at_least_medium():
    dyn = SandboxResult(install_exit_code=0, install_logs="",
                        network_attempts=[{"type": "dns", "query": "A? evil.example"}])
    assert assess(Ecosystem.NPM, RiskLevel.LOW, dyn, sandbox_ran=True).risk == RiskLevel.MEDIUM


def test_low_llm_with_binary_or_autorun_findings_not_lowered():
    assert assess(Ecosystem.NPM, RiskLevel.LOW, CLEAN, sandbox_ran=True, binary_findings=True).risk == RiskLevel.MEDIUM
    assert assess(Ecosystem.NPM, RiskLevel.LOW, CLEAN, sandbox_ran=True, autorun_high=True).risk == RiskLevel.HIGH


def test_llm_can_raise_risk():
    assert assess(Ecosystem.NPM, RiskLevel.HIGH, CLEAN, sandbox_ran=True).risk == RiskLevel.HIGH
    assert assess(Ecosystem.NPM, RiskLevel.MEDIUM, CLEAN, sandbox_ran=True).risk == RiskLevel.MEDIUM


def test_low_llm_plus_clean_sandbox_is_vetted():
    a = assess(Ecosystem.NPM, RiskLevel.LOW, CLEAN, sandbox_ran=True)
    assert a.risk == RiskLevel.LOW and a.vetted


def test_low_llm_on_no_sandbox_ecosystem_is_not_vetted():
    dyn = SandboxResult(install_exit_code=0, install_logs="N/A (go)")
    a = assess(Ecosystem.GO, RiskLevel.LOW, dyn, sandbox_ran=False)
    assert a.risk == RiskLevel.LOW
    assert not a.vetted
    assert "human" in a.note.lower()


def test_explicit_per_ecosystem_rule_can_vet_without_sandbox():
    dyn = SandboxResult(install_exit_code=0, install_logs="N/A (go)")
    a = assess(Ecosystem.GO, RiskLevel.LOW, dyn, sandbox_ran=False,
               static_vetted_ecosystems=frozenset({Ecosystem.GO}))
    assert a.vetted


def test_explicit_rule_still_needs_source_scan_to_have_run():
    dyn = SandboxResult(install_exit_code=0, install_logs="N/A (go)")
    a = assess(Ecosystem.GO, RiskLevel.LOW, dyn, sandbox_ran=False, source_scanned=False,
               static_vetted_ecosystems=frozenset({Ecosystem.GO}))
    assert not a.vetted


def test_failed_install_or_skipped_sandbox_is_not_evidence():
    failed = SandboxResult(install_exit_code=1, install_logs="boom")
    assert not assess(Ecosystem.NPM, RiskLevel.LOW, failed, sandbox_ran=True).vetted
    skipped = SandboxResult(install_exit_code=-1, install_logs="unsupported")
    assert not assess(Ecosystem.NPM, RiskLevel.LOW, skipped, sandbox_ran=False).vetted


def test_unknown_static_with_clean_signals_stays_unknown_and_unvetted():
    a = assess(Ecosystem.NPM, RiskLevel.UNKNOWN, CLEAN, sandbox_ran=True)
    assert a.risk == RiskLevel.UNKNOWN and not a.vetted


def test_unknown_static_does_not_mask_deterministic_signal():
    dyn = SandboxResult(install_exit_code=0, install_logs="", sudo_attempts=["SUDO_ATTEMPT"])
    assert assess(Ecosystem.NPM, RiskLevel.UNKNOWN, dyn, sandbox_ran=True).risk == RiskLevel.HIGH


def test_post_to_registry_host_still_high():
    dyn = SandboxResult(install_exit_code=0, install_logs="", network_attempts=[
        {"type": "http", "method": "POST", "host": "registry.npmjs.org", "path": "/x"}])
    assert assess(Ecosystem.NPM, RiskLevel.LOW, dyn, sandbox_ran=True).risk == RiskLevel.HIGH


def test_go_integrity_failure_is_high():
    dyn = SandboxResult(install_exit_code=0, install_logs="N/A")
    a = assess(Ecosystem.GO, RiskLevel.LOW, dyn, sandbox_ran=False, integrity_failure=True,
               static_vetted_ecosystems=frozenset({Ecosystem.GO}))
    assert a.risk == RiskLevel.HIGH and not a.vetted
