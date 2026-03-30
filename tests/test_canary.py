from __future__ import annotations

import re

from dependabot_plus.sandbox.canary import (
    CANARY_FILE_PATHS,
    generate_canary_env,
    generate_canary_files,
)

EXPECTED_ENV_KEYS = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "DATABASE_URL",
    "SLACK_WEBHOOK_URL",
    "STRIPE_SECRET_KEY",
    "SENDGRID_API_KEY",
    "NPM_TOKEN",
    "GEM_HOST_API_KEY",
    "SECRET_KEY_BASE",
}

CANARY_TOKEN_RE = re.compile(r"CANARY-[0-9a-f\-]{36}")


# ---------------------------------------------------------------------------
# generate_canary_env
# ---------------------------------------------------------------------------

def test_generate_canary_env_returns_all_expected_keys():
    env = generate_canary_env()
    assert set(env.keys()) == EXPECTED_ENV_KEYS


def test_generate_canary_env_values_contain_canary_tokens():
    env = generate_canary_env()
    for key, value in env.items():
        assert CANARY_TOKEN_RE.search(value), (
            f"Value for {key!r} does not contain a CANARY token: {value!r}"
        )


def test_generate_canary_env_tokens_are_unique():
    env = generate_canary_env()
    tokens = []
    for value in env.values():
        tokens.extend(CANARY_TOKEN_RE.findall(value))
    assert len(tokens) == len(set(tokens)), "Duplicate tokens found in env vars"


# ---------------------------------------------------------------------------
# generate_canary_files
# ---------------------------------------------------------------------------

def test_generate_canary_files_returns_all_expected_paths():
    files = generate_canary_files()
    assert set(files.keys()) == set(CANARY_FILE_PATHS)


def test_generate_canary_files_values_contain_canary_tokens():
    files = generate_canary_files()
    for path, content in files.items():
        assert CANARY_TOKEN_RE.search(content), (
            f"Content for {path!r} does not contain a CANARY token"
        )


def test_ssh_key_has_begin_end_markers():
    files = generate_canary_files()
    ssh_content = files["/root/.ssh/id_rsa"]
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" in ssh_content
    assert "-----END OPENSSH PRIVATE KEY-----" in ssh_content


def test_aws_credentials_has_default_section():
    files = generate_canary_files()
    aws_content = files["/root/.aws/credentials"]
    assert "[default]" in aws_content
    assert "aws_access_key_id" in aws_content
    assert "aws_secret_access_key" in aws_content


def test_npmrc_has_auth_token():
    files = generate_canary_files()
    content = files["/root/.npmrc"]
    assert "//registry.npmjs.org/:_authToken=" in content


def test_gem_credentials_has_yaml_format():
    files = generate_canary_files()
    content = files["/root/.gem/credentials"]
    assert content.startswith("---\n")
    assert ":rubygems_api_key:" in content


def test_docker_config_has_auths():
    files = generate_canary_files()
    content = files["/root/.docker/config.json"]
    assert '"auths"' in content
    assert '"auth"' in content


def test_git_credentials_has_url_format():
    files = generate_canary_files()
    content = files["/root/.git-credentials"]
    assert content.startswith("https://user:")
    assert "@github.com" in content


def test_env_file_has_key_value_pairs():
    files = generate_canary_files()
    content = files["/root/.env"]
    assert "DATABASE_URL=" in content
    assert "SECRET_KEY=" in content


def test_kube_config_has_apiversion():
    files = generate_canary_files()
    content = files["/root/.kube/config"]
    assert "apiVersion: v1" in content
    assert "certificate-authority-data:" in content


def test_no_duplicate_tokens_across_files_and_env():
    env = generate_canary_env()
    files = generate_canary_files()

    all_tokens = []
    for value in env.values():
        all_tokens.extend(CANARY_TOKEN_RE.findall(value))
    for content in files.values():
        all_tokens.extend(CANARY_TOKEN_RE.findall(content))

    assert len(all_tokens) == len(set(all_tokens)), (
        "Duplicate CANARY tokens found across env vars and files"
    )
