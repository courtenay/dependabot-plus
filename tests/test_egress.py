"""Gap 1: HTTPS / DNS / TCP egress to non-allowlisted hosts is scored."""
from __future__ import annotations

from dependabot_plus.queue.models import Ecosystem, RiskLevel
from dependabot_plus.sandbox.egress import allowed_hosts, assess_egress


def _worst(findings):
    order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]
    return max((f.risk for f in findings), key=order.index, default=RiskLevel.LOW)


def test_https_connect_to_non_registry_host_install_phase_is_medium():
    # HTTPS shows up as a TCP connect to :443; the host is known via DNS answers.
    attempts = [{"type": "tcp", "destination": "203.0.113.5.443", "phase": "install"}]
    resolved = {"203.0.113.5": {"evil.example"}}
    findings = assess_egress(Ecosystem.NPM, attempts, resolved_ips=resolved)
    assert _worst(findings) == RiskLevel.MEDIUM
    assert findings[0].host == "evil.example"


def test_https_connect_to_non_registry_host_post_install_is_high():
    attempts = [{"type": "tcp", "destination": "203.0.113.5.443", "phase": "post_install"}]
    findings = assess_egress(Ecosystem.NPM, attempts, resolved_ips={"203.0.113.5": {"evil.example"}})
    assert _worst(findings) == RiskLevel.HIGH


def test_dns_lookup_to_non_registry_host_is_medium():
    attempts = [{"type": "dns", "query": "A? exfil.evil.example"}]
    assert _worst(assess_egress(Ecosystem.NPM, attempts)) == RiskLevel.MEDIUM


def test_dns_lookup_post_install_is_high():
    attempts = [{"type": "dns", "query": "TXT? c2.evil.example", "phase": "post_install"}]
    assert _worst(assess_egress(Ecosystem.GEM, attempts)) == RiskLevel.HIGH


def test_registry_dns_is_allowed_for_matching_ecosystem():
    attempts = [{"type": "dns", "query": "A? registry.npmjs.org."}]
    assert assess_egress(Ecosystem.NPM, attempts) == []


def test_registry_of_other_ecosystem_is_not_allowed():
    # A gem install has no business talking to the npm registry.
    attempts = [{"type": "dns", "query": "A? registry.npmjs.org"}]
    assert _worst(assess_egress(Ecosystem.GEM, attempts)) == RiskLevel.MEDIUM


def test_subdomain_and_lookalike_hosts_are_not_allowed():
    for host in ("registry.npmjs.org.evil.example", "evil-registry.npmjs.org", "npmjs.org"):
        attempts = [{"type": "dns", "query": f"A? {host}"}]
        assert _worst(assess_egress(Ecosystem.NPM, attempts)) == RiskLevel.MEDIUM, host


def test_tcp_to_unresolved_ip_fails_closed():
    attempts = [{"type": "tcp", "destination": "198.51.100.7.443"}]
    assert _worst(assess_egress(Ecosystem.NPM, attempts)) == RiskLevel.MEDIUM


def test_tcp_to_ip_resolved_only_from_registry_is_allowed():
    attempts = [{"type": "tcp", "destination": "104.16.1.35.443"}]
    resolved = {"104.16.1.35": {"registry.npmjs.org"}}
    assert assess_egress(Ecosystem.NPM, attempts, resolved_ips=resolved) == []


def test_tcp_to_ip_shared_with_non_allowlisted_host_fails_closed():
    attempts = [{"type": "tcp", "destination": "104.16.1.35.443"}]
    resolved = {"104.16.1.35": {"registry.npmjs.org", "evil.example"}}
    assert _worst(assess_egress(Ecosystem.NPM, attempts, resolved_ips=resolved)) == RiskLevel.MEDIUM


def test_unknown_ecosystem_allowlist_is_empty():
    assert allowed_hosts(Ecosystem.DOCKER) == frozenset()


def test_configured_mirrors_are_allowed(monkeypatch):
    monkeypatch.setenv("DEPENDABOT_PLUS_REGISTRY_MIRRORS", "npm.corp.example, pypi.corp.example")
    attempts = [{"type": "dns", "query": "A? npm.corp.example"}]
    assert assess_egress(Ecosystem.NPM, attempts) == []


def test_extra_hosts_argument_is_allowed():
    attempts = [{"type": "dns", "query": "A? mirror.example"}]
    assert assess_egress(Ecosystem.NPM, attempts, extra_hosts={"mirror.example"}) == []


def test_http_without_host_fails_closed():
    attempts = [{"type": "http", "method": "GET", "host": "unknown", "path": "/"}]
    assert _worst(assess_egress(Ecosystem.NPM, attempts)) == RiskLevel.MEDIUM
