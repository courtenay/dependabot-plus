from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch


from dependabot_plus.queue.models import Ecosystem, QueueItem, SandboxResult
from dependabot_plus.sandbox.runner import (
    DOWNLOAD_FAILED,
    _parse_container_output,
    _pre_download_gem,
    _pre_download_pip,
    run_sandbox,
)


# ---------------------------------------------------------------------------
# _parse_container_output
# ---------------------------------------------------------------------------

def test_parse_container_output_valid_json_last_line():
    payload = {"install_exit_code": 0, "install_log": "ok"}
    stdout = json.dumps(payload) + "\n"
    assert _parse_container_output(stdout) == payload


def test_parse_container_output_mixed_output():
    lines = [
        "Downloading package...",
        "Extracting...",
        "Done.",
        json.dumps({"install_exit_code": 0, "file_accesses": []}),
    ]
    stdout = "\n".join(lines) + "\n"
    result = _parse_container_output(stdout)
    assert result["install_exit_code"] == 0
    assert result["file_accesses"] == []


def test_parse_container_output_empty():
    assert _parse_container_output("") == {}


def test_parse_container_output_no_json():
    assert _parse_container_output("just some text\nno json here\n") == {}


def test_parse_container_output_json_not_on_last_line():
    """JSON on an earlier line should still be found (reverse scan)."""
    lines = [
        "Starting install...",
        json.dumps({"install_exit_code": 1}),
        "some trailing log text",
    ]
    stdout = "\n".join(lines) + "\n"
    result = _parse_container_output(stdout)
    assert result["install_exit_code"] == 1


# ---------------------------------------------------------------------------
# run_sandbox (with containerised pre-download)
# ---------------------------------------------------------------------------

def _make_item(**overrides) -> QueueItem:
    defaults = dict(
        repo="owner/repo",
        pr_number=42,
        ecosystem=Ecosystem.NPM,
        package_name="left-pad",
        old_version="1.0.0",
        new_version="1.1.0",
    )
    defaults.update(overrides)
    return QueueItem(**defaults)


def _mock_subprocess_side_effects(container_output_json, sandbox_image_exists=True):
    """Build side_effect list for the 4 subprocess.run calls in run_sandbox:
    1. docker image inspect (sandbox image) — in run_sandbox
    2. docker image inspect (pre-download image) — in _pre_download_npm
    3. docker run (pre-download container) — in _pre_download_npm
    4. docker run (sandbox container) — in run_sandbox
    """
    effects = []
    if sandbox_image_exists:
        effects.append(MagicMock(returncode=0))  # 1: image exists
    else:
        effects.append(subprocess.CalledProcessError(1, "docker"))  # 1: trigger build
    effects.append(MagicMock(returncode=0))  # 2: pre-download image exists
    effects.append(MagicMock(returncode=0, stdout="", stderr=""))  # 3: pre-download run
    effects.append(MagicMock(
        stdout=container_output_json + "\n", stderr="", returncode=0,
    ))  # 4: sandbox run
    return effects


@patch("dependabot_plus.sandbox.runner.generate_canary_files")
@patch("dependabot_plus.sandbox.runner.generate_canary_env")
@patch("dependabot_plus.sandbox.runner.subprocess.run")
@patch("dependabot_plus.sandbox.runner.build_sandbox_image")
def test_run_sandbox_returns_sandbox_result(
    mock_build, mock_subprocess_run, mock_canary_env, mock_canary_files,
):
    mock_canary_env.return_value = {"AWS_ACCESS_KEY_ID": "CANARY-fake"}
    mock_canary_files.return_value = {"/root/.ssh/id_rsa": "fake-key"}

    container_output = json.dumps({
        "install_exit_code": 0,
        "install_log": "installed ok",
        "file_accesses": [],
    })

    mock_subprocess_run.side_effect = _mock_subprocess_side_effects(
        container_output, sandbox_image_exists=False,
    )

    result = run_sandbox(_make_item(), mode="strict")

    assert isinstance(result, SandboxResult)
    assert result.install_exit_code == 0
    assert result.install_logs == "installed ok"
    mock_build.assert_called_once()


@patch("dependabot_plus.sandbox.runner.generate_canary_files")
@patch("dependabot_plus.sandbox.runner.generate_canary_env")
@patch("dependabot_plus.sandbox.runner.subprocess.run")
def test_docker_command_includes_network_none(
    mock_subprocess_run, mock_canary_env, mock_canary_files,
):
    mock_canary_env.return_value = {"TOK": "val"}
    mock_canary_files.return_value = {}

    mock_subprocess_run.side_effect = _mock_subprocess_side_effects("{}")

    run_sandbox(_make_item(), mode="strict")

    # The sandbox docker run is the last call
    docker_run_call = mock_subprocess_run.call_args_list[-1]
    cmd = docker_run_call.args[0]
    assert "--network=none" in cmd


@patch("dependabot_plus.sandbox.runner.generate_canary_files")
@patch("dependabot_plus.sandbox.runner.generate_canary_env")
@patch("dependabot_plus.sandbox.runner.subprocess.run")
def test_canary_env_vars_passed_as_e_flags(
    mock_subprocess_run, mock_canary_env, mock_canary_files,
):
    canary_env = {
        "AWS_ACCESS_KEY_ID": "CANARY-aaa",
        "GITHUB_TOKEN": "ghp_CANARY-bbb",
    }
    mock_canary_env.return_value = canary_env
    mock_canary_files.return_value = {}

    mock_subprocess_run.side_effect = _mock_subprocess_side_effects("{}")

    run_sandbox(_make_item(), mode="strict")

    docker_run_call = mock_subprocess_run.call_args_list[-1]
    cmd = docker_run_call.args[0]

    for key, value in canary_env.items():
        flag = f"{key}={value}"
        idx = cmd.index("-e", cmd.index(flag) - 1)
        assert cmd[idx] == "-e"
        assert cmd[idx + 1] == flag


@patch("dependabot_plus.sandbox.runner.subprocess.run")
def test_pre_download_gem_resolves_dependency_closure(mock_subprocess_run):
    """gem fetch alone misses dependencies (e.g. jbuilder needs actionview),
    so the offline install would fail. The pre-download must resolve and fetch
    the full closure without executing gem code."""
    mock_subprocess_run.side_effect = [
        MagicMock(returncode=0),  # docker image inspect
        MagicMock(returncode=0, stdout="", stderr=""),  # docker run
    ]

    _pre_download_gem("jbuilder", "2.15.1", "/tmp/dest")

    docker_run_call = mock_subprocess_run.call_args_list[-1]
    script = docker_run_call.args[0][-1]
    # Resolves the full closure code-free, then fetches each at its version.
    assert "gem install --explain jbuilder -v 2.15.1" in script
    assert "gem fetch" in script
    # Must not install/build during pre-download — code only runs in the sandbox.
    assert "gem install --explain" in script and "gem install /" not in script


@patch("dependabot_plus.sandbox.runner.subprocess.run")
def test_pre_download_pip_resolves_dependency_closure(mock_subprocess_run):
    """pip download --no-deps misses dependencies, so the offline
    --no-index install would fail. The pre-download must fetch the full
    closure (no --no-deps) without running install hooks."""
    mock_subprocess_run.side_effect = [
        MagicMock(returncode=0),  # docker image inspect
        MagicMock(returncode=0, stdout="", stderr=""),  # docker run
    ]

    _pre_download_pip("requests", "2.31.0", "/tmp/dest")

    docker_run_call = mock_subprocess_run.call_args_list[-1]
    script = docker_run_call.args[0][-1]
    assert "pip download 'requests==2.31.0'" in script
    # Must download the full closure, not just the named package.
    assert "--no-deps" not in script


@patch("dependabot_plus.sandbox.runner.generate_canary_files")
@patch("dependabot_plus.sandbox.runner.generate_canary_env")
@patch("dependabot_plus.sandbox.runner.subprocess.run")
def test_run_sandbox_handles_string_file_accesses(
    mock_subprocess_run, mock_canary_env, mock_canary_files,
):
    mock_canary_env.return_value = {}
    mock_canary_files.return_value = {}

    container_output = json.dumps({
        "install_exit_code": 0,
        "install_log": "",
        "file_accesses": ["/root/.ssh/id_rsa", {"path": "/root/.env"}],
    })

    mock_subprocess_run.side_effect = _mock_subprocess_side_effects(container_output)

    result = run_sandbox(_make_item(), mode="strict")

    assert result.file_accesses == [
        {"raw": "/root/.ssh/id_rsa"},
        {"path": "/root/.env"},
    ]


# ---------------------------------------------------------------------------
# Pre-download failures (404 / yanked version / private registry)
# ---------------------------------------------------------------------------

@patch("dependabot_plus.sandbox.runner.subprocess.run")
def test_run_sandbox_download_failure_is_not_fatal(mock_subprocess_run):
    """A package that cannot be fetched must not abort the whole item —
    static analysis has already run and still needs reporting."""
    mock_subprocess_run.side_effect = [
        MagicMock(returncode=0),  # sandbox image exists
        MagicMock(returncode=0),  # pre-download image exists
        MagicMock(returncode=1, stdout="npm error code E404", stderr=""),
    ]

    result = run_sandbox(_make_item(package_name="sentry-ruby"), mode="strict")

    assert result.install_exit_code == DOWNLOAD_FAILED
    assert "sentry-ruby" in result.install_logs
    assert result.file_accesses == []
    # The sandbox container must never be started without a package
    assert mock_subprocess_run.call_count == 3
