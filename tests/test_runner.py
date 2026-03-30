from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from dependabot_plus.queue.models import Ecosystem, QueueItem, SandboxResult
from dependabot_plus.sandbox.runner import _parse_container_output, run_sandbox


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
# run_sandbox
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

    # First call: docker image inspect (raise to trigger build)
    # Second call: docker run
    mock_subprocess_run.side_effect = [
        subprocess.CalledProcessError(1, "docker"),
        MagicMock(stdout=container_output + "\n", stderr="", returncode=0),
    ]

    result = run_sandbox(_make_item())

    assert isinstance(result, SandboxResult)
    assert result.install_exit_code == 0
    assert result.install_logs == "installed ok"
    mock_build.assert_called_once()


import subprocess  # noqa: E402 (needed for CalledProcessError in side_effect)


@patch("dependabot_plus.sandbox.runner.generate_canary_files")
@patch("dependabot_plus.sandbox.runner.generate_canary_env")
@patch("dependabot_plus.sandbox.runner.subprocess.run")
def test_docker_command_includes_network_none(
    mock_subprocess_run, mock_canary_env, mock_canary_files,
):
    mock_canary_env.return_value = {"TOK": "val"}
    mock_canary_files.return_value = {}

    # First call succeeds (image exists), second is docker run
    mock_subprocess_run.side_effect = [
        MagicMock(),  # docker image inspect
        MagicMock(stdout="{}\n", stderr="", returncode=0),  # docker run
    ]

    run_sandbox(_make_item())

    # The docker run call is the second one
    docker_run_call = mock_subprocess_run.call_args_list[1]
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

    mock_subprocess_run.side_effect = [
        MagicMock(),  # docker image inspect
        MagicMock(stdout="{}\n", stderr="", returncode=0),  # docker run
    ]

    run_sandbox(_make_item())

    docker_run_call = mock_subprocess_run.call_args_list[1]
    cmd = docker_run_call.args[0]

    # Each canary env var should appear as -e KEY=VALUE
    for key, value in canary_env.items():
        flag = f"{key}={value}"
        idx = cmd.index("-e", cmd.index(flag) - 1)
        assert cmd[idx] == "-e"
        assert cmd[idx + 1] == flag


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

    mock_subprocess_run.side_effect = [
        MagicMock(),
        MagicMock(stdout=container_output + "\n", stderr="", returncode=0),
    ]

    result = run_sandbox(_make_item())

    assert result.file_accesses == [
        {"raw": "/root/.ssh/id_rsa"},
        {"path": "/root/.env"},
    ]
