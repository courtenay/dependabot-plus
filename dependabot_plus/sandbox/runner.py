from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile

from dependabot_plus.queue.models import Ecosystem, QueueItem, SandboxResult
from dependabot_plus.sandbox.builder import build_sandbox_image, image_tag

log = logging.getLogger("dependabot_plus")
from dependabot_plus.sandbox.canary import (
    CANARY_FILE_PATHS,
    generate_canary_env,
    generate_canary_files,
)

_INSTALL_COMMANDS = {
    Ecosystem.NPM: lambda pkg, ver: f"npm install {pkg}@{ver}",
    Ecosystem.GEM: lambda pkg, ver: f"gem install {pkg} -v {ver}",
    Ecosystem.APT: lambda pkg, ver: f"apt-get update -qq && apt-get install -y {pkg}={ver}",
    Ecosystem.PIP: lambda pkg, ver: f"pip install {pkg}=={ver}",
}

_LOCAL_INSTALL_COMMANDS = {
    Ecosystem.NPM: "/test-pkg",
    Ecosystem.GEM: "gem install /test-pkg/*.gem",
    Ecosystem.APT: "dpkg -i /test-pkg/*.deb",
    Ecosystem.PIP: "pip install /test-pkg/*",
}

# Known-benign file accesses by ecosystem tools (not malware)
_BENIGN_ACCESS_PATTERNS = {
    Ecosystem.NPM: {".npmrc"},
    Ecosystem.GEM: {".gem/credentials"},
    Ecosystem.APT: set(),
    Ecosystem.PIP: {".pip", ".cache/pip"},
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


def _pre_download_npm(package: str, version: str, dest: str) -> None:
    """Download an npm package and all its dependencies inside a container.

    Uses a network-enabled but filesystem-isolated Docker container to run
    `npm install --ignore-scripts`, then copies the result to dest via a
    bind mount. This avoids running any untrusted code or exposing host
    credentials during the fetch.
    """
    tag = image_tag(Ecosystem.NPM)
    # Ensure image exists
    try:
        subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, check=True,
        )
    except subprocess.CalledProcessError:
        build_sandbox_image(Ecosystem.NPM)

    # The container writes to /out which is bind-mounted to dest
    fetch_script = (
        "cd /out && "
        f'echo \'{json.dumps({"name": "depbot-sandbox", "dependencies": {package: version}})}\' > package.json && '
        "npm install --ignore-scripts 2>&1"
    )
    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{dest}:/out",
            "--entrypoint", "bash",
            tag,
            "-c", fetch_script,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"npm pre-download failed: {result.stdout}\n{result.stderr}")


def _pre_download_gem(package: str, version: str, dest: str) -> None:
    """Download a gem file inside a container (network-enabled, host-isolated)."""
    tag = image_tag(Ecosystem.GEM)
    try:
        subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, check=True,
        )
    except subprocess.CalledProcessError:
        build_sandbox_image(Ecosystem.GEM)

    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{dest}:/out",
            "--entrypoint", "bash",
            tag,
            "-c", f"cd /out && gem fetch {package} -v {version} 2>&1",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gem pre-download failed: {result.stdout}\n{result.stderr}")


def _pre_download_apt(package: str, version: str, dest: str) -> None:
    """Download a .deb inside a container (network-enabled, host-isolated)."""
    tag = image_tag(Ecosystem.APT)
    try:
        subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, check=True,
        )
    except subprocess.CalledProcessError:
        build_sandbox_image(Ecosystem.APT)

    # apt-get download fetches the .deb without installing
    script = (
        f"cd /out && apt-get update -qq && "
        f"apt-get download {package}={version} 2>&1 || "
        f"apt-get download {package} 2>&1"
    )
    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{dest}:/out",
            "--entrypoint", "bash",
            tag,
            "-c", script,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"apt pre-download failed: {result.stdout}\n{result.stderr}")


def _pre_download_pip(package: str, version: str, dest: str) -> None:
    """Download a pip package inside a container (network-enabled, host-isolated)."""
    tag = image_tag(Ecosystem.PIP)
    try:
        subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, check=True,
        )
    except subprocess.CalledProcessError:
        build_sandbox_image(Ecosystem.PIP)

    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{dest}:/out",
            "--entrypoint", "bash",
            tag,
            "-c", f"cd /out && pip download --no-deps '{package}=={version}' 2>&1",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"pip pre-download failed: {result.stdout}\n{result.stderr}")


_PRE_DOWNLOADERS = {
    Ecosystem.NPM: _pre_download_npm,
    Ecosystem.GEM: _pre_download_gem,
    Ecosystem.APT: _pre_download_apt,
    Ecosystem.PIP: _pre_download_pip,
    # Go/Docker/GitHub Actions have no install scripts — dynamic analysis skipped
}

# Install commands for offline/local installs inside the sandbox.
_OFFLINE_INSTALL_COMMANDS = {
    Ecosystem.NPM: "cp -r /pkg/node_modules . && cp /pkg/package.json . && npm rebuild",
    Ecosystem.GEM: "gem install --local /pkg/*.gem",
    Ecosystem.APT: "dpkg -i /pkg/*.deb 2>&1 || true",
    Ecosystem.PIP: "pip install --no-index --find-links /pkg/ /pkg/* 2>&1",
}


def _run_container(
    tag: str,
    install_cmd: str,
    ecosystem: Ecosystem,
    extra_volumes: list[tuple[str, str]] | None = None,
    mode: str = "monitor",
) -> SandboxResult:
    """Core container execution with canary traps.

    mode="strict": --network=none, no network logging
    mode="monitor": network enabled, tcpdump runs inside the container
                    capturing DNS lookups and TCP connections
    """
    canary_env = generate_canary_env()
    canary_files = generate_canary_files()

    cmd = ["docker", "run", "--rm"]

    if mode == "monitor":
        # Network enabled — tcpdump inside the container captures traffic
        cmd.extend(["--cap-add", "NET_RAW"])
        cmd.extend(["-e", "MONITOR_NETWORK=1"])
    else:
        cmd.append("--network=none")

    for host_path, container_path in (extra_volumes or []):
        cmd.extend(["-v", f"{host_path}:{container_path}"])

    cmd.extend([
        "-e", f"INSTALL_CMD={install_cmd}",
        "-e", f"CANARY_FILES_JSON={json.dumps(canary_files)}",
        "-e", f"CANARY_WATCH_PATHS={chr(10).join(CANARY_FILE_PATHS)}",
    ])

    for key, value in canary_env.items():
        cmd.extend(["-e", f"{key}={value}"])

    cmd.append(tag)

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=600,
    )

    output = _parse_container_output(result.stdout)
    access_dicts = _parse_file_accesses(
        output.get("file_accesses", []), ecosystem,
    )

    # Parse network capture — all traffic logged, HTTP requests are high signal
    network_attempts = []
    for req in output.get("http_requests", []):
        network_attempts.append({"type": "http", **req})
    for query in output.get("dns_queries", []):
        network_attempts.append({"type": "dns", "query": query})
    for conn in output.get("tcp_connections", []):
        network_attempts.append({"type": "tcp", "destination": conn})

    sudo_attempts = output.get("sudo_attempts", [])

    exit_code = output.get("install_exit_code", result.returncode)
    log.info(
        "  Sandbox finished: exit_code=%d, canary_accesses=%d, "
        "network_events=%d, sudo_attempts=%d",
        exit_code, len(access_dicts), len(network_attempts), len(sudo_attempts),
    )

    return SandboxResult(
        install_exit_code=exit_code,
        install_logs=output.get("install_log", result.stderr[-5000:]),
        file_accesses=access_dicts,
        network_attempts=network_attempts,
        sudo_attempts=sudo_attempts,
    )


def run_sandbox(item: QueueItem, mode: str = "monitor") -> SandboxResult:
    """Pre-download the package, then install it in a monitored sandbox.

    mode="monitor": network enabled with tcpdump sidecar (default)
    mode="strict": --network=none, no network logging
    """
    tag = image_tag(item.ecosystem)

    # Ensure image is built
    try:
        subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, check=True,
        )
    except subprocess.CalledProcessError:
        build_sandbox_image(item.ecosystem)

    # Pre-download the package (with network) into a temp directory
    pkg_dir = tempfile.mkdtemp(prefix="depbot_pkg_")
    try:
        downloader = _PRE_DOWNLOADERS.get(item.ecosystem)
        if downloader is None:
            log.info("  Skipping dynamic analysis: %s not supported yet", item.ecosystem.value)
            return SandboxResult(
                install_exit_code=-1,
                install_logs=f"Dynamic analysis not yet supported for {item.ecosystem.value}",
                file_accesses=[],
                network_attempts=[],
            )
        log.info("  Downloading %s@%s ...", item.package_name, item.new_version)
        downloader(item.package_name, item.new_version, pkg_dir)
        log.info("  Package downloaded, starting sandboxed install ...")

        return _run_container(
            tag=tag,
            install_cmd=_OFFLINE_INSTALL_COMMANDS[item.ecosystem],
            ecosystem=item.ecosystem,
            extra_volumes=[(pkg_dir, "/pkg:ro")],
            mode=mode,
        )
    finally:
        shutil.rmtree(pkg_dir, ignore_errors=True)


def run_sandbox_local(
    ecosystem: Ecosystem,
    local_package_path: str,
    install_cmd: str | None = None,
    mode: str = "strict",
) -> SandboxResult:
    """Run a sandbox install from a local package directory.

    Used for integration testing with fixture packages.
    Default mode is strict (no network) for test isolation.
    """
    tag = image_tag(ecosystem)

    try:
        subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, check=True,
        )
    except subprocess.CalledProcessError:
        build_sandbox_image(ecosystem)

    if install_cmd is None:
        install_cmd = f"npm install {_LOCAL_INSTALL_COMMANDS[ecosystem]}"

    return _run_container(
        tag=tag,
        install_cmd=install_cmd,
        ecosystem=ecosystem,
        extra_volumes=[(local_package_path, "/test-pkg:ro")],
        mode=mode,
    )
