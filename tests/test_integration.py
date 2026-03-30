"""Integration tests that run real Docker containers with test fixture packages.

These tests require Docker to be running and will build images on first run.
Mark with pytest.mark.integration so they can be skipped in CI or fast runs:

    pytest -m integration          # run only these
    pytest -m "not integration"    # skip these
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from dependabot_plus.queue.models import Ecosystem
from dependabot_plus.sandbox.runner import run_sandbox_local

FIXTURES = Path(__file__).parent / "fixtures" / "malicious_packages"

pytestmark = pytest.mark.integration


def _docker_available() -> bool:
    import subprocess
    try:
        subprocess.run(
            ["docker", "info"], capture_output=True, check=True, timeout=10,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


skip_no_docker = pytest.mark.skipif(
    not _docker_available(), reason="Docker not available"
)


@skip_no_docker
class TestFileScanner:
    """The file-scanner package reads all canary file paths during postinstall."""

    def test_detects_canary_file_access(self):
        result = run_sandbox_local(
            ecosystem=Ecosystem.NPM,
            local_package_path=str(FIXTURES / "file-scanner"),
        )

        assert result.install_exit_code == 0, (
            f"Install failed: {result.install_logs}"
        )

        # The postinstall script reads ~/.ssh/id_rsa, ~/.aws/credentials, etc.
        # inotifywait should have logged these accesses
        assert len(result.file_accesses) > 0, (
            "Expected canary file accesses but got none. "
            f"Install logs: {result.install_logs}"
        )

        # Check that specific high-value files were accessed
        raw_entries = " ".join(
            entry.get("raw", str(entry)) for entry in result.file_accesses
        )
        assert ".ssh" in raw_entries or "id_rsa" in raw_entries, (
            f"Expected SSH key access in: {raw_entries}"
        )

    def test_multiple_files_accessed(self):
        result = run_sandbox_local(
            ecosystem=Ecosystem.NPM,
            local_package_path=str(FIXTURES / "file-scanner"),
        )

        # The scanner targets 8 files — we should see accesses to several
        assert len(result.file_accesses) >= 3, (
            f"Expected multiple file accesses, got {len(result.file_accesses)}: "
            f"{result.file_accesses}"
        )


@skip_no_docker
class TestEnvStealer:
    """The env-stealer package reads env vars and writes them + reads SSH key."""

    def test_detects_ssh_key_access(self):
        result = run_sandbox_local(
            ecosystem=Ecosystem.NPM,
            local_package_path=str(FIXTURES / "env-stealer"),
        )

        assert result.install_exit_code == 0, (
            f"Install failed: {result.install_logs}"
        )

        # Should detect the SSH key read
        assert len(result.file_accesses) > 0, (
            "Expected canary file access (SSH key) but got none. "
            f"Install logs: {result.install_logs}"
        )

        raw_entries = " ".join(
            entry.get("raw", str(entry)) for entry in result.file_accesses
        )
        assert "ssh" in raw_entries.lower() or "id_rsa" in raw_entries, (
            f"Expected SSH key access in: {raw_entries}"
        )


@skip_no_docker
class TestCleanPackage:
    """The clean-pkg has no postinstall and does nothing suspicious."""

    def test_no_canary_file_access(self):
        result = run_sandbox_local(
            ecosystem=Ecosystem.NPM,
            local_package_path=str(FIXTURES / "clean-pkg"),
        )

        assert result.install_exit_code == 0, (
            f"Install failed: {result.install_logs}"
        )

        # A clean package should trigger zero canary accesses
        assert len(result.file_accesses) == 0, (
            f"Clean package triggered canary alerts: {result.file_accesses}"
        )

    def test_no_network_attempts(self):
        result = run_sandbox_local(
            ecosystem=Ecosystem.NPM,
            local_package_path=str(FIXTURES / "clean-pkg"),
        )

        assert len(result.network_attempts) == 0


@skip_no_docker
class TestPhoneHome:
    """The phone-home package does DNS lookups and HTTP requests during install."""

    def test_detects_dns_exfiltration(self):
        result = run_sandbox_local(
            ecosystem=Ecosystem.NPM,
            local_package_path=str(FIXTURES / "phone-home"),
            mode="monitor",
        )

        assert result.install_exit_code == 0, (
            f"Install failed: {result.install_logs}"
        )

        # Should have captured DNS queries (port 53 traffic)
        dns_events = [
            a for a in result.network_attempts if a.get("type") == "dns"
        ]
        assert len(dns_events) > 0, (
            f"Expected DNS activity but got none. "
            f"All network events: {result.network_attempts}"
        )

    def test_detects_http_phone_home(self):
        result = run_sandbox_local(
            ecosystem=Ecosystem.NPM,
            local_package_path=str(FIXTURES / "phone-home"),
            mode="monitor",
        )

        # Should have captured TCP connections or HTTP requests
        tcp_events = [
            a for a in result.network_attempts
            if a.get("type") in ("tcp", "http")
        ]
        assert len(tcp_events) > 0, (
            f"Expected TCP/HTTP activity but got none. "
            f"All network events: {result.network_attempts}"
        )

    def test_also_detects_file_access(self):
        """phone-home also reads ~/.ssh/id_rsa — both vectors should fire."""
        result = run_sandbox_local(
            ecosystem=Ecosystem.NPM,
            local_package_path=str(FIXTURES / "phone-home"),
            mode="monitor",
        )

        assert len(result.file_accesses) > 0, (
            "phone-home reads SSH key but no canary triggered"
        )
        assert len(result.network_attempts) > 0, (
            "phone-home phones home but no network events captured"
        )


@skip_no_docker
class TestCleanPackageMonitorMode:
    """Clean package in monitor mode should have no suspicious network activity."""

    def test_clean_in_monitor_mode(self):
        result = run_sandbox_local(
            ecosystem=Ecosystem.NPM,
            local_package_path=str(FIXTURES / "clean-pkg"),
            mode="monitor",
        )

        assert result.install_exit_code == 0
        assert len(result.file_accesses) == 0
        # npm install itself might do some DNS for telemetry, but no TCP to
        # our canary domains
        canary_network = [
            a for a in result.network_attempts
            if "depbot-canary" in str(a)
        ]
        assert len(canary_network) == 0, (
            f"Clean package contacted canary domains: {canary_network}"
        )
