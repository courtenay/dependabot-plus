from __future__ import annotations

import json
from pathlib import Path


from dependabot_plus.queue.models import (
    Ecosystem,
    QueueItem,
    RiskLevel,
    Status,
    load_queue,
    save_queue,
)


# ---------------------------------------------------------------------------
# Enum values
# ---------------------------------------------------------------------------


class TestEnums:
    def test_ecosystem_values(self):
        assert Ecosystem.NPM.value == "npm"
        assert Ecosystem.GEM.value == "gem"
        assert Ecosystem.APT.value == "apt"

    def test_status_values(self):
        assert Status.QUEUED.value == "queued"
        assert Status.PROCESSING.value == "processing"
        assert Status.DONE.value == "done"
        assert Status.FAILED.value == "failed"

    def test_risk_level_values(self):
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.UNKNOWN.value == "unknown"

    def test_ecosystem_is_str(self):
        assert isinstance(Ecosystem.NPM, str)
        assert Ecosystem.NPM == "npm"

    def test_status_is_str(self):
        assert isinstance(Status.QUEUED, str)
        assert Status.QUEUED == "queued"


# ---------------------------------------------------------------------------
# QueueItem.to_dict / from_dict
# ---------------------------------------------------------------------------


def _make_item(**overrides) -> QueueItem:
    defaults = dict(
        repo="owner/repo",
        pr_number=42,
        ecosystem=Ecosystem.NPM,
        package_name="lodash",
        old_version="4.17.20",
        new_version="4.17.21",
        status=Status.QUEUED,
    )
    defaults.update(overrides)
    return QueueItem(**defaults)


class TestQueueItemRoundtrip:
    def test_to_dict_contains_plain_strings(self):
        item = _make_item()
        d = item.to_dict()
        assert d["ecosystem"] == "npm"
        assert d["status"] == "queued"
        assert isinstance(d["ecosystem"], str)
        assert isinstance(d["status"], str)

    def test_to_dict_keys(self):
        d = _make_item().to_dict()
        expected_keys = {
            "repo",
            "pr_number",
            "ecosystem",
            "package_name",
            "old_version",
            "new_version",
            "status",
        }
        assert set(d.keys()) == expected_keys

    def test_roundtrip_default_status(self):
        original = _make_item()
        restored = QueueItem.from_dict(original.to_dict())
        assert restored == original

    def test_roundtrip_non_default_status(self):
        original = _make_item(status=Status.FAILED, ecosystem=Ecosystem.GEM)
        restored = QueueItem.from_dict(original.to_dict())
        assert restored == original

    def test_from_dict_defaults_status_to_queued(self):
        d = _make_item().to_dict()
        del d["status"]
        restored = QueueItem.from_dict(d)
        assert restored.status is Status.QUEUED

    def test_roundtrip_through_json(self):
        original = _make_item()
        json_str = json.dumps(original.to_dict())
        restored = QueueItem.from_dict(json.loads(json_str))
        assert restored == original


# ---------------------------------------------------------------------------
# load_queue / save_queue
# ---------------------------------------------------------------------------


class TestLoadSaveQueue:
    def test_save_then_load(self, tmp_path: Path):
        path = tmp_path / "queue.json"
        items = [
            _make_item(pr_number=1, package_name="a"),
            _make_item(pr_number=2, package_name="b", status=Status.DONE),
        ]
        save_queue(items, path)
        loaded = load_queue(path)
        assert loaded == items

    def test_save_creates_valid_json(self, tmp_path: Path):
        path = tmp_path / "queue.json"
        save_queue([_make_item()], path)
        data = json.loads(path.read_text())
        assert isinstance(data, list)
        assert len(data) == 1

    def test_save_empty_list(self, tmp_path: Path):
        path = tmp_path / "queue.json"
        save_queue([], path)
        assert json.loads(path.read_text()) == []

    def test_load_nonexistent_returns_empty(self, tmp_path: Path):
        path = tmp_path / "does_not_exist.json"
        assert load_queue(path) == []

    def test_save_overwrites_existing(self, tmp_path: Path):
        path = tmp_path / "queue.json"
        save_queue([_make_item(pr_number=1)], path)
        save_queue([_make_item(pr_number=2)], path)
        loaded = load_queue(path)
        assert len(loaded) == 1
        assert loaded[0].pr_number == 2
