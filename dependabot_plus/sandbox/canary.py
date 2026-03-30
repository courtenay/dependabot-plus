from __future__ import annotations

import uuid


def _token() -> str:
    return f"CANARY-{uuid.uuid4()}"


def generate_canary_env() -> dict[str, str]:
    """Generate fake environment variables that look like real secrets.
    Each value contains a unique token so we can detect if it leaks."""
    return {
        "AWS_ACCESS_KEY_ID": f"AKIAIOSFODNN7{_token()}",
        "AWS_SECRET_ACCESS_KEY": _token(),
        "GITHUB_TOKEN": f"ghp_{_token()}",
        "DATABASE_URL": f"postgres://admin:{_token()}@db.internal:5432/prod",
        "SLACK_WEBHOOK_URL": f"https://hooks.slack.com/services/{_token()}",
        "STRIPE_SECRET_KEY": f"sk_live_{_token()}",
        "SENDGRID_API_KEY": f"SG.{_token()}",
        "NPM_TOKEN": _token(),
        "GEM_HOST_API_KEY": _token(),
        "SECRET_KEY_BASE": _token(),
    }


# Canary files: path -> content
# These mimic common credential files that malware scans for.
CANARY_FILE_PATHS: list[str] = [
    "/root/.ssh/id_rsa",
    "/root/.aws/credentials",
    "/root/.npmrc",
    "/root/.gem/credentials",
    "/root/.docker/config.json",
    "/root/.git-credentials",
    "/root/.env",
    "/root/.kube/config",
]


def generate_canary_files() -> dict[str, str]:
    """Generate canary files with unique tokens as content.
    Returns {file_path: file_content}."""
    files: dict[str, str] = {}
    for path in CANARY_FILE_PATHS:
        token = _token()
        if "ssh" in path:
            files[path] = (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                f"{token}\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            )
        elif "aws" in path:
            files[path] = (
                "[default]\n"
                f"aws_access_key_id = AKIAIOSFODNN7{token}\n"
                f"aws_secret_access_key = {_token()}\n"
            )
        elif "npmrc" in path:
            files[path] = f"//registry.npmjs.org/:_authToken={token}\n"
        elif "gem" in path:
            files[path] = f"---\n:rubygems_api_key: {token}\n"
        elif "docker" in path:
            files[path] = (
                '{"auths":{"https://index.docker.io/v1/":'
                f'{{"auth":"{token}"}}}}}}\n'
            )
        elif "git-credentials" in path:
            files[path] = f"https://user:{token}@github.com\n"
        elif ".env" in path:
            files[path] = (
                f"DATABASE_URL=postgres://admin:{token}@db:5432/prod\n"
                f"SECRET_KEY={_token()}\n"
            )
        elif "kube" in path:
            files[path] = (
                "apiVersion: v1\n"
                "clusters:\n"
                "- cluster:\n"
                f"    certificate-authority-data: {token}\n"
                "    server: https://k8s.internal:6443\n"
            )
        else:
            files[path] = f"{token}\n"
    return files
