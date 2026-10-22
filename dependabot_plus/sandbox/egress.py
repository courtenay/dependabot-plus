"""Egress policy: which hosts a package install may contact.

Explicit allowlist, fail closed: anything not provably an allowlisted registry
host (unparseable, bare IP with no DNS attribution, shared IP) is not allowed.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from dependabot_plus.queue.models import Ecosystem, RiskLevel

MIRRORS_ENV = "DEPENDABOT_PLUS_REGISTRY_MIRRORS"

_REGISTRY_HOSTS: dict[Ecosystem, frozenset[str]] = {
    Ecosystem.NPM: frozenset({"registry.npmjs.org"}),
    Ecosystem.GEM: frozenset({"rubygems.org", "index.rubygems.org", "api.rubygems.org"}),
    Ecosystem.PIP: frozenset({"pypi.org", "files.pythonhosted.org"}),
    Ecosystem.GO: frozenset({"proxy.golang.org", "sum.golang.org"}),
    Ecosystem.APT: frozenset({"deb.debian.org", "security.debian.org"}),
}


@dataclass(frozen=True)
class EgressFinding:
    host: str
    kind: str          # dns | tcp | http
    phase: str         # install | post_install
    risk: RiskLevel
    detail: str


def _normalise(host: str) -> str:
    return host.strip().lower().rstrip(".")


def configured_mirrors() -> frozenset[str]:
    raw = os.environ.get(MIRRORS_ENV, "")
    return frozenset(_normalise(h) for h in raw.split(",") if h.strip())


def allowed_hosts(ecosystem: Ecosystem, extra_hosts=None) -> frozenset[str]:
    extra = frozenset(_normalise(h) for h in (extra_hosts or ()))
    return _REGISTRY_HOSTS.get(ecosystem, frozenset()) | configured_mirrors() | extra


def _strip_port(host: str) -> str:
    host = host.strip()
    if host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host


def _split_ip_port(dest: str) -> tuple[str, str]:
    """tcpdump prints IPv4 endpoints as a.b.c.d.port."""
    ip, _, port = dest.strip().rpartition(".")
    return ip, port


def assess_egress(
    ecosystem: Ecosystem,
    network_attempts: list[dict],
    resolved_ips: dict[str, set[str]] | dict[str, list[str]] | None = None,
    extra_hosts=None,
) -> list[EgressFinding]:
    """Return one finding per contact with a non-allowlisted host.

    Install/rebuild phase: MEDIUM. After install scripts ran: HIGH.
    """
    allowed = allowed_hosts(ecosystem, extra_hosts)
    resolved = {ip: {_normalise(h) for h in hosts} for ip, hosts in (resolved_ips or {}).items()}
    findings: list[EgressFinding] = []
    seen: set[tuple[str, str, str]] = set()

    for attempt in network_attempts:
        kind = attempt.get("type")
        phase = attempt.get("phase", "install")
        if kind == "dns":
            query = str(attempt.get("query", ""))
            host = _normalise(query.split()[-1]) if query.split() else ""
            ok = host in allowed
            label = host or query or "unknown"
        elif kind == "http":
            host = _normalise(_strip_port(str(attempt.get("host", ""))))
            ok = host in allowed
            label = host or "unknown"
        elif kind == "tcp":
            ip, _port = _split_ip_port(str(attempt.get("destination", "")))
            hosts = resolved.get(ip, set())
            ok = bool(hosts) and hosts <= allowed
            label = ", ".join(sorted(hosts)) if hosts else (ip or "unknown")
            host = label
        else:
            continue
        if ok:
            continue
        key = (kind, label, phase)
        if key in seen:
            continue
        seen.add(key)
        risk = RiskLevel.HIGH if phase == "post_install" else RiskLevel.MEDIUM
        when = "after install scripts ran" if phase == "post_install" else "during install"
        findings.append(EgressFinding(
            host=label, kind=kind, phase=phase, risk=risk,
            detail=f"{kind} to non-allowlisted host {label} {when}",
        ))
    return findings
