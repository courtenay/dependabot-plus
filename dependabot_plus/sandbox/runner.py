from __future__ import annotations

import json
import subprocess

from dependabot_plus.queue.models import Ecosystem, QueueItem, SandboxResult
from dependabot_plus.sandbox.builder import build_sandbox_image, image_tag
from dependabot_plus.sandbox.canary import (
    CANARY_FILE_PATHS,
    generate_canary_env,
    generate_canary_files,
)

_INSTALL_COMMANDS = {
    Ecosystem.NPM: lambda pkg, ver: f"npm install {pkg}@{ver}",
    Ecosystem.GEM: lambda pkg, ver: f"gem install {pkg} -v {ver}",
    Ecosystem.APT: lambda pkg, ver: f"apt-get update -qq && apt-get install -y {pkg}={ver}",
}

_LOCAL_INSTALL_COMMANDS = {
    Ecosystem.NPM: "/test-pkg",
    Ecosystem.GEM: "gem install /test-pkg/*.gem",
    Ecosystem.APT: "dpkg -i /test-pkg/*.deb",
}

# Known-benign file accesses by ecosystem tools (not malware)
_BENIGN_ACCESS_PATTERNS = {
    Ecosystem.NPM: {".npmrc"},
    Ecosystem.GEM: {".gem/credentials"},
    Ecosystem.APT: set(),
}


def _parse_container_output(stdout: str) -> dict:
    """Parse the JSON output from the container entrypoint."""
    # The entrypoint prints JSON as the last line
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    return {}


def _parse_file_accesses(
    raw_accesses: list, ecosystem: Ecosystem,
) -> list[dict]:
    """Parse and filter file access entries, removing inotifywait noise
    and known-benign accesses from ecosystem tools."""
    benign = _BENIGN_ACCESS_PATTERNS.get(ecosystem, set())
    result = []
    for entry in raw_accesses:
        raw = entry if isinstance(entry, str) else str(entry)
        # Skip inotifywait setup messages
        if "Setting up watches" in raw or "Watches established" in raw:
            continue
        # Skip known-benign tool accesses
        if any(pattern in raw for pattern in benign):
            continue
        if isinstance(entry, str):
            result.append({"raw": entry})
        else:
            result.append(entry)
    return result


def run_sandbox(item: QueueItem) -> SandboxResult:
    """Build and run a sandboxed install of the package. Returns results."""
    tag = image_tag(item.ecosystem)

    # Ensure image is built
    try:
        subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, check=True,
        )
    except subprocess.CalledProcessError:
        build_sandbox_image(item.ecosystem)

    canary_env = generate_canary_env()
    canary_files = generate_canary_files()

    install_cmd = _INSTALL_COMMANDS[item.ecosystem](
        item.package_name, item.new_version,
    )

    # Build docker run command
    cmd = [
        "docker", "run", "--rm",
        "--network=none",
        # Set the install command
        "-e", f"INSTALL_CMD={install_cmd}",
        # Pass canary files as JSON
        "-e", f"CANARY_FILES_JSON={json.dumps(canary_files)}",
        # Pass canary watch paths
        "-e", f"CANARY_WATCH_PATHS={chr(10).join(CANARY_FILE_PATHS)}",
    ]

    # Add canary environment variables
    for key, value in canary_env.items():
        cmd.extend(["-e", f"{key}={value}"])

    cmd.append(tag)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
    )

    # Parse output even if install failed
    output = _parse_container_output(result.stdout)
    access_dicts = _parse_file_accesses(
        output.get("file_accesses", []), item.ecosystem,
    )

    return SandboxResult(
        install_exit_code=output.get("install_exit_code", result.returncode),
        install_logs=output.get("install_log", result.stderr[-5000:]),
        file_accesses=access_dicts,
        network_attempts=[],  # --network=none blocks all; future: iptables logging
    )


def run_sandbox_local(
    ecosystem: Ecosystem,
    local_package_path: str,
    install_cmd: str | None = None,
) -> SandboxResult:
    """Run a sandbox install from a local package directory.

    This is used for integration testing with fixture packages.
    The local_package_path is volume-mounted into the container at /test-pkg.
    """
    tag = image_tag(ecosystem)

    # Ensure image is built
    try:
        subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, check=True,
        )
    except subprocess.CalledProcessError:
        build_sandbox_image(ecosystem)

    canary_env = generate_canary_env()
    canary_files = generate_canary_files()

    if install_cmd is None:
        install_cmd = f"npm install {_LOCAL_INSTALL_COMMANDS[ecosystem]}"

    cmd = [
        "docker", "run", "--rm",
        "--network=none",
        "-v", f"{local_package_path}:/test-pkg:ro",
        "-e", f"INSTALL_CMD={install_cmd}",
        "-e", f"CANARY_FILES_JSON={json.dumps(canary_files)}",
        "-e", f"CANARY_WATCH_PATHS={chr(10).join(CANARY_FILE_PATHS)}",
    ]

    for key, value in canary_env.items():
        cmd.extend(["-e", f"{key}={value}"])

    cmd.append(tag)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
    )

    output = _parse_container_output(result.stdout)
    access_dicts = _parse_file_accesses(
        output.get("file_accesses", []), ecosystem,
    )

    return SandboxResult(
        install_exit_code=output.get("install_exit_code", result.returncode),
        install_logs=output.get("install_log", result.stderr[-5000:]),
        file_accesses=access_dicts,
        network_attempts=[],
    )
