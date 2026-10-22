"""Risk policy: combine deterministic signals with the (untrusted) LLM verdict.

Invariants:
  * The LLM verdict can raise risk but never lower it below what deterministic
    signals (sandbox, detectors, egress, binary/autorun scans, checksums) say.
  * ``vetted`` (eligible for the ``deps-vetted`` label) needs deterministic
    evidence of safety: a clean sandbox run, or an explicit per-ecosystem rule
    (``static_vetted_ecosystems``) backed by a completed source scan. An LLM
    LOW alone never vets.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from dependabot_plus.queue.models import Ecosystem, RiskLevel, SandboxResult
from dependabot_plus.sandbox.egress import assess_egress

_RANK = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}


def _max(*levels: RiskLevel) -> RiskLevel:
    return max(levels, key=lambda r: _RANK.get(r, 0))


@dataclass
class Assessment:
    risk: RiskLevel
    deterministic_risk: RiskLevel
    vetted: bool
    note: str = ""
    reasons: list[str] = field(default_factory=list)


def assess(
    ecosystem: Ecosystem,
    static_risk: RiskLevel,
    dynamic: SandboxResult,
    *,
    sandbox_ran: bool,
    binary_findings: bool = False,
    autorun: bool = False,
    autorun_high: bool = False,
    blocked_network: bool = False,
    integrity_failure: bool = False,
    source_scanned: bool = True,
    static_vetted_ecosystems: frozenset = frozenset(),
) -> Assessment:
    det = RiskLevel.LOW
    reasons: list[str] = []

    def bump(level: RiskLevel, why: str) -> None:
        nonlocal det
        det = _max(det, level)
        reasons.append(f"{level.value}: {why}")

    if dynamic.file_accesses:
        bump(RiskLevel.HIGH, "canary file accessed")
    if dynamic.sudo_attempts:
        bump(RiskLevel.HIGH, "sudo attempted")
    if integrity_failure:
        bump(RiskLevel.HIGH, "module checksum verification failed")
    if autorun_high:
        bump(RiskLevel.HIGH, "high-severity editor/agent auto-run config")
    elif autorun:
        bump(RiskLevel.MEDIUM, "editor/agent auto-run config")
    for f in dynamic.detector_findings:
        try:
            level = RiskLevel(f.get("risk", "high"))
        except ValueError:
            level = RiskLevel.HIGH
        bump(_max(level, RiskLevel.LOW), f.get("detail") or f"{f.get('kind')} {f.get('path')}")

    http = [a for a in dynamic.network_attempts if a.get("type") == "http"]
    if any(r.get("method") in ("POST", "PUT", "PATCH") for r in http):
        bump(RiskLevel.HIGH, "HTTP write method (possible exfiltration)")
    resolved = {ip: set(hosts) for ip, hosts in dynamic.dns_answers.items()}
    for ef in assess_egress(ecosystem, dynamic.network_attempts, resolved_ips=resolved):
        bump(ef.risk, ef.detail)
    if blocked_network:
        bump(RiskLevel.MEDIUM, "install attempted network access that was blocked")
    if binary_findings:
        bump(RiskLevel.MEDIUM, "suspicious binary files")

    # The LLM may only raise. UNKNOWN (LLM failed) never masks a real signal,
    # and with no signal it stays UNKNOWN so nothing gets vetted by accident.
    if det == RiskLevel.LOW:
        risk = static_risk
    elif static_risk == RiskLevel.UNKNOWN:
        risk = det
    else:
        risk = _max(det, static_risk)

    sandbox_clean = sandbox_ran and dynamic.install_exit_code == 0
    rule_based = ecosystem in static_vetted_ecosystems and source_scanned
    vetted = risk == RiskLevel.LOW and (sandbox_clean or rule_based)

    note = ""
    if risk == RiskLevel.LOW and not vetted:
        note = (
            "LLM review found nothing, but there is no deterministic evidence of safety "
            f"for {ecosystem.value} (sandbox did not run cleanly and no per-ecosystem "
            "rule applies). Needs human review before it is labelled deps-vetted."
        )
    return Assessment(risk=risk, deterministic_risk=det, vetted=vetted, note=note, reasons=reasons)
