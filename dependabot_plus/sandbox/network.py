from __future__ import annotations

import json
import logging
import subprocess
import time

log = logging.getLogger("dependabot_plus")

MONITOR_IMAGE = "depbot-monitor:latest"


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def create_network(name: str) -> str:
    """Create a Docker bridge network for sandbox + monitor.
    Not --internal so traffic can flow (and be captured)."""
    _run(["docker", "network", "rm", name])
    _run(["docker", "network", "create", name], check=True)
    return name


def teardown_network(name: str) -> None:
    """Remove the sandbox network."""
    _run(["docker", "network", "rm", name])


def build_monitor_image() -> str:
    """Build the tcpdump monitor sidecar image."""
    from pathlib import Path
    dockerfile_dir = Path(__file__).parent / "dockerfiles"
    log.info("  Building monitor image ...")
    _run([
        "docker", "build",
        "-f", str(dockerfile_dir / "monitor.Dockerfile"),
        "-t", MONITOR_IMAGE,
        str(dockerfile_dir),
    ], check=True)
    return MONITOR_IMAGE


def ensure_monitor_image() -> str:
    """Ensure monitor image exists, build if needed."""
    result = _run(["docker", "image", "inspect", MONITOR_IMAGE])
    if result.returncode != 0:
        return build_monitor_image()
    return MONITOR_IMAGE


def start_monitor(network: str, capture_dir: str) -> str:
    """Start the monitor sidecar container. Returns container ID."""
    ensure_monitor_image()
    result = _run([
        "docker", "run", "-d",
        "--network", network,
        "--cap-add", "NET_RAW",       # needed for tcpdump
        "--cap-add", "NET_ADMIN",
        "-v", f"{capture_dir}:/capture",
        MONITOR_IMAGE,
    ], check=True)
    container_id = result.stdout.strip()
    # Give tcpdump a moment to start
    time.sleep(0.5)
    return container_id


def stop_monitor(container_id: str) -> dict:
    """Stop the monitor, triggering pcap parsing. Returns network summary."""
    # Send SIGTERM so the entrypoint parses the pcap
    _run(["docker", "stop", "-t", "5", container_id])

    # Grab the logs (which contain the JSON summary)
    result = _run(["docker", "logs", container_id])
    _run(["docker", "rm", "-f", container_id])

    # Parse the JSON summary from the last line of output
    for line in reversed(result.stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {"dns_queries": [], "tcp_connections": [], "http_requests": [], "raw_packets": 0}
