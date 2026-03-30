from __future__ import annotations

import subprocess


def create_monitored_network(name: str = "depbot_sandbox") -> str:
    """Create a Docker network with no external access.
    For MVP, we use --internal which prevents outbound traffic.
    Returns the network name."""
    # Remove stale network if it exists
    subprocess.run(
        ["docker", "network", "rm", name],
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["docker", "network", "create", "--internal", name],
        capture_output=True,
        text=True,
        check=True,
    )
    return name


def teardown_network(name: str = "depbot_sandbox") -> None:
    """Remove the sandbox network."""
    subprocess.run(
        ["docker", "network", "rm", name],
        capture_output=True,
        text=True,
    )
