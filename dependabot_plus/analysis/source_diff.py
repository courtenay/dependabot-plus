from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from dependabot_plus.queue.models import Ecosystem, QueueItem


def _run(cmd: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=True)


def _diff_dirs(dir_a: str, dir_b: str) -> str:
    """Unified diff between two directories. Returns empty string if identical."""
    result = subprocess.run(
        ["diff", "-ruN", dir_a, dir_b],
        capture_output=True,
        text=True,
    )
    # diff exits 1 when files differ, 2 on error
    if result.returncode == 2:
        raise RuntimeError(f"diff error: {result.stderr}")
    return result.stdout


def _fetch_npm_diff(package: str, old_ver: str, new_ver: str, workdir: str) -> str:
    old_dir = os.path.join(workdir, "old")
    new_dir = os.path.join(workdir, "new")
    os.makedirs(old_dir)
    os.makedirs(new_dir)

    _run(["npm", "pack", f"{package}@{old_ver}"], cwd=old_dir)
    _run(["npm", "pack", f"{package}@{new_ver}"], cwd=new_dir)

    # npm pack creates a tarball — extract each
    for d in [old_dir, new_dir]:
        tarballs = [f for f in os.listdir(d) if f.endswith(".tgz")]
        if not tarballs:
            raise RuntimeError(f"npm pack produced no tarball in {d}")
        _run(["tar", "xzf", tarballs[0]], cwd=d)

    return _diff_dirs(
        os.path.join(old_dir, "package"),
        os.path.join(new_dir, "package"),
    )


def _fetch_gem_diff(package: str, old_ver: str, new_ver: str, workdir: str) -> str:
    old_dir = os.path.join(workdir, "old")
    new_dir = os.path.join(workdir, "new")
    os.makedirs(old_dir)
    os.makedirs(new_dir)

    _run(["gem", "fetch", package, "-v", old_ver], cwd=old_dir)
    _run(["gem", "fetch", package, "-v", new_ver], cwd=new_dir)

    # gem fetch creates a .gem file — it's a tar containing data.tar.gz
    for d, ver in [(old_dir, old_ver), (new_dir, new_ver)]:
        gem_files = [f for f in os.listdir(d) if f.endswith(".gem")]
        if not gem_files:
            raise RuntimeError(f"gem fetch produced no .gem file in {d}")
        _run(["tar", "xf", gem_files[0]], cwd=d)
        src_dir = os.path.join(d, "src")
        os.makedirs(src_dir, exist_ok=True)
        data_tar = os.path.join(d, "data.tar.gz")
        if os.path.exists(data_tar):
            _run(["tar", "xzf", data_tar], cwd=src_dir)

    return _diff_dirs(
        os.path.join(old_dir, "src"),
        os.path.join(new_dir, "src"),
    )


def _fetch_apt_diff(package: str, old_ver: str, new_ver: str, workdir: str) -> str:
    """Apt source diffing — runs inside a Docker container since apt source
    requires the right sources list and architecture."""
    old_dir = os.path.join(workdir, "old")
    new_dir = os.path.join(workdir, "new")
    os.makedirs(old_dir)
    os.makedirs(new_dir)

    # Use a debian container to fetch sources
    for d, ver in [(old_dir, old_ver), (new_dir, new_ver)]:
        script = (
            f"apt-get update -qq && "
            f"cd /work && apt-get source --download-only {package}={ver} 2>/dev/null || "
            f"apt-get source --download-only {package} 2>/dev/null; "
            f"dpkg-source -x *.dsc src 2>/dev/null || true"
        )
        _run([
            "docker", "run", "--rm",
            "-v", f"{d}:/work",
            "debian:bookworm",
            "bash", "-c", script,
        ])

    old_src = os.path.join(old_dir, "src")
    new_src = os.path.join(new_dir, "src")
    if os.path.isdir(old_src) and os.path.isdir(new_src):
        return _diff_dirs(old_src, new_src)
    return "(apt source diff unavailable — source packages could not be fetched)"


_FETCHER_NAMES = {
    Ecosystem.NPM: "_fetch_npm_diff",
    Ecosystem.GEM: "_fetch_gem_diff",
    Ecosystem.APT: "_fetch_apt_diff",
}


def fetch_source_diff(item: QueueItem) -> str:
    """Fetch source for old and new versions and return a unified diff."""
    import sys
    mod = sys.modules[__name__]
    workdir = tempfile.mkdtemp(prefix="depbot_diff_")
    try:
        fetcher = getattr(mod, _FETCHER_NAMES[item.ecosystem])
        return fetcher(item.package_name, item.old_version, item.new_version, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
