from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from dependabot_plus.queue.models import Ecosystem, QueueItem


# __file__ is dependabot_plus/analysis/source_diff.py → repo root is three levels up
_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _tool_versions_env() -> dict[str, str]:
    """Parse .tool-versions and set ASDF_<TOOL>_VERSION env vars so asdf shims
    work even when cwd is a temp directory outside the project tree."""
    env: dict[str, str] = {}
    tool_versions = os.path.join(_PROJECT_DIR, ".tool-versions")
    if not os.path.exists(tool_versions):
        return env
    with open(tool_versions) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                tool = parts[0].upper()
                env.setdefault(f"ASDF_{tool}_VERSION", parts[1])
    return env


_ASDF_ENV = _tool_versions_env()


def _run(cmd: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    # When cwd is a temp directory, asdf shims fail because there is no
    # .tool-versions file.  Propagate explicit version env vars so shims
    # resolve correctly regardless of working directory.
    for k, v in _ASDF_ENV.items():
        env.setdefault(k, v)
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=True, env=env)


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


def _fetch_go_diff(package: str, old_ver: str, new_ver: str, workdir: str) -> str:
    """Go module diffing — uses a Go container to download module source."""
    old_dir = os.path.join(workdir, "old", "src")
    new_dir = os.path.join(workdir, "new", "src")
    os.makedirs(old_dir)
    os.makedirs(new_dir)

    # Normalise version: add v prefix if missing
    for d, ver in [(old_dir, old_ver), (new_dir, new_ver)]:
        v = ver if ver.startswith("v") else f"v{ver}"
        # Download module, then find and copy the cached source
        script = (
            f"export GOPATH=/tmp/gopath GONOSUMCHECK=* GONOSUMDB=* GOTOOLCHAIN=auto && "
            f"go mod download {package}@{v} 2>/dev/null; "
            # Find the cached module directory and copy contents to /work
            f"moddir=$(find /tmp/gopath/pkg/mod -maxdepth 4 -type d -name '*@{v}*' | head -1) && "
            f"if [ -n \"$moddir\" ]; then cp -r \"$moddir\"/* /work/ 2>/dev/null; fi"
        )
        subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{d}:/work",
                "golang:1.24-bookworm",
                "bash", "-c", script,
            ],
            capture_output=True, text=True, timeout=120,
        )

    # Check if we got anything
    old_has_files = os.path.isdir(old_dir) and os.listdir(old_dir)
    new_has_files = os.path.isdir(new_dir) and os.listdir(new_dir)
    if old_has_files and new_has_files:
        return _diff_dirs(old_dir, new_dir)
    return "(go module diff unavailable — source could not be fetched)"


def _fetch_pip_diff(package: str, old_ver: str, new_ver: str, workdir: str) -> str:
    """Download sdist tarballs from PyPI for both versions and diff."""
    old_dir = os.path.join(workdir, "old")
    new_dir = os.path.join(workdir, "new")
    os.makedirs(old_dir)
    os.makedirs(new_dir)

    for d, ver in [(old_dir, old_ver), (new_dir, new_ver)]:
        result = subprocess.run(
            ["pip", "download", "--no-binary", ":all:", "--no-deps",
             "-d", d, f"{package}=={ver}"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return f"(pip source diff unavailable — could not download {package}=={ver})"
        # Extract the sdist tarball
        src_dir = os.path.join(d, "src")
        os.makedirs(src_dir, exist_ok=True)
        tarballs = [f for f in os.listdir(d) if f.endswith((".tar.gz", ".zip"))]
        if not tarballs:
            return f"(pip source diff unavailable — no sdist for {package}=={ver})"
        if tarballs[0].endswith(".tar.gz"):
            _run(["tar", "xzf", os.path.join(d, tarballs[0])], cwd=src_dir)
        else:
            _run(["unzip", "-q", os.path.join(d, tarballs[0])], cwd=src_dir)

    return _diff_dirs(
        os.path.join(old_dir, "src"),
        os.path.join(new_dir, "src"),
    )


def _fetch_docker_diff(package: str, old_ver: str, new_ver: str, workdir: str) -> str:
    """Pull two Docker image tags and diff their exported filesystems."""
    old_dir = os.path.join(workdir, "old", "rootfs")
    new_dir = os.path.join(workdir, "new", "rootfs")
    os.makedirs(old_dir)
    os.makedirs(new_dir)

    for d, ver in [(old_dir, old_ver), (new_dir, new_ver)]:
        image = f"{package}:{ver}"
        result = subprocess.run(
            ["docker", "pull", image], capture_output=True, text=True,
        )
        if result.returncode != 0:
            return f"(docker diff unavailable — could not pull {image})"
        # Create a container (not started) and export its filesystem
        cid_result = subprocess.run(
            ["docker", "create", image], capture_output=True, text=True,
        )
        if cid_result.returncode != 0:
            return f"(docker diff unavailable — could not create container for {image})"
        cid = cid_result.stdout.strip()
        try:
            export = subprocess.run(
                ["docker", "export", cid],
                capture_output=True, timeout=300,
            )
            tar_path = os.path.join(d, "..", "image.tar")
            with open(tar_path, "wb") as f:
                f.write(export.stdout)
            _run(["tar", "xf", tar_path], cwd=d)
        finally:
            subprocess.run(["docker", "rm", cid], capture_output=True)

    return _diff_dirs(old_dir, new_dir)


def _fetch_github_actions_diff(package: str, old_ver: str, new_ver: str, workdir: str) -> str:
    """Clone a GitHub Action at two version tags and diff."""
    old_dir = os.path.join(workdir, "old", "src")
    new_dir = os.path.join(workdir, "new", "src")

    for d, ver in [(old_dir, old_ver), (new_dir, new_ver)]:
        url = f"https://github.com/{package}.git"
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ver, url, d],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            return f"(github actions diff unavailable — could not clone {package}@{ver})"
        # Remove .git directory to avoid noisy diff
        git_dir = os.path.join(d, ".git")
        if os.path.isdir(git_dir):
            shutil.rmtree(git_dir)

    return _diff_dirs(old_dir, new_dir)


_FETCHER_NAMES = {
    Ecosystem.NPM: "_fetch_npm_diff",
    Ecosystem.GEM: "_fetch_gem_diff",
    Ecosystem.APT: "_fetch_apt_diff",
    Ecosystem.GO: "_fetch_go_diff",
    Ecosystem.PIP: "_fetch_pip_diff",
    Ecosystem.DOCKER: "_fetch_docker_diff",
    Ecosystem.GITHUB_ACTIONS: "_fetch_github_actions_diff",
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


_SOURCE_SUBDIRS = {
    Ecosystem.NPM: "package",        # npm pack extracts to package/
    Ecosystem.GEM: "src",            # gem untar extracts data.tar.gz to src/
    Ecosystem.APT: "src",            # dpkg-source extracts to src/
    Ecosystem.GO: "src",             # go mod download copies to src/
    Ecosystem.PIP: "src",            # pip sdist extracts to src/
    Ecosystem.DOCKER: "rootfs",      # docker export extracts to rootfs/
    Ecosystem.GITHUB_ACTIONS: "src", # git clone into src/
}


def fetch_source_with_dirs(item: QueueItem) -> tuple[str, str, str, str]:
    """Fetch source and return (diff, workdir, old_src_dir, new_src_dir).

    Returns the extracted source directories (not the parent dirs that
    contain download artifacts like .tgz files). This ensures binary
    scanning only sees actual package contents.

    Caller is responsible for cleaning up workdir via shutil.rmtree.
    """
    import sys
    mod = sys.modules[__name__]
    workdir = tempfile.mkdtemp(prefix="depbot_diff_")
    fetcher = getattr(mod, _FETCHER_NAMES[item.ecosystem])
    diff = fetcher(item.package_name, item.old_version, item.new_version, workdir)
    subdir = _SOURCE_SUBDIRS.get(item.ecosystem, "")
    old_dir = os.path.join(workdir, "old", subdir)
    new_dir = os.path.join(workdir, "new", subdir)
    return diff, workdir, old_dir, new_dir
