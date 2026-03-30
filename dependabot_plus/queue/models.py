from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path


class Ecosystem(str, Enum):
    NPM = "npm"
    GEM = "gem"
    APT = "apt"


class Status(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    DONE = "done"
    FAILED = "failed"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


@dataclass
class QueueItem:
    repo: str
    pr_number: int
    ecosystem: Ecosystem
    package_name: str
    old_version: str
    new_version: str
    status: Status = Status.QUEUED

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ecosystem"] = self.ecosystem.value
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> QueueItem:
        return cls(
            repo=d["repo"],
            pr_number=d["pr_number"],
            ecosystem=Ecosystem(d["ecosystem"]),
            package_name=d["package_name"],
            old_version=d["old_version"],
            new_version=d["new_version"],
            status=Status(d.get("status", "queued")),
        )


@dataclass
class SandboxResult:
    install_exit_code: int
    install_logs: str
    file_accesses: list[dict] = field(default_factory=list)
    network_attempts: list[dict] = field(default_factory=list)
    sudo_attempts: list[str] = field(default_factory=list)


@dataclass
class StaticFindings:
    suspicious_patterns: list[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    summary: str = ""


@dataclass
class Verdict:
    risk_level: RiskLevel
    static_findings: StaticFindings
    dynamic_findings: SandboxResult
    summary: str


def load_queue(path: Path) -> list[QueueItem]:
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    return [QueueItem.from_dict(item) for item in data]


def save_queue(items: list[QueueItem], path: Path) -> None:
    data = [item.to_dict() for item in items]
    path.write_text(json.dumps(data, indent=2) + "\n")
