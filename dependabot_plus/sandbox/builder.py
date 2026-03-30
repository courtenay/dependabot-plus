from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from dependabot_plus.queue.models import Ecosystem

log = logging.getLogger("dependabot_plus")

_DOCKERFILE_DIR = Path(__file__).parent / "dockerfiles"

_DOCKERFILE_MAP = {
    Ecosystem.NPM: "npm.Dockerfile",
    Ecosystem.GEM: "gem.Dockerfile",
    Ecosystem.APT: "apt.Dockerfile",
}

_IMAGE_PREFIX = "depbot-sandbox"


def image_tag(ecosystem: Ecosystem) -> str:
    return f"{_IMAGE_PREFIX}-{ecosystem.value}:latest"


def build_sandbox_image(ecosystem: Ecosystem) -> str:
    """Build the Docker sandbox image for an ecosystem. Returns the image tag."""
    dockerfile = _DOCKERFILE_MAP[ecosystem]
    tag = image_tag(ecosystem)
    log.info("  Building Docker image %s ...", tag)
    subprocess.run(
        [
            "docker", "build",
            "-f", str(_DOCKERFILE_DIR / dockerfile),
            "-t", tag,
            str(_DOCKERFILE_DIR),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    log.info("  Docker image %s built", tag)
    return tag
