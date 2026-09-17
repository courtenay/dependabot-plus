"""The queue file is long-lived state, so the new field must be back-compatible.

queue.json currently holds ~390 rows written before coverage_complete existed.
Those rows were produced by the body parser and are not known to be complete —
but defaulting them to False would retroactively un-vet PRs already labelled by
hand. They default True, meaning "no worse than before"; only newly fetched
rows carry a real verdict.
"""
from __future__ import annotations

from dependabot_plus.queue.models import Ecosystem, QueueItem, Status, load_queue, save_queue


def _legacy_row() -> dict:
    return {
        "repo": "soffi-ai/soffi-main",
        "pr_number": 3169,
        "ecosystem": "npm",
        "package_name": "highlight.js",
        "old_version": "11.11.1",
        "new_version": "11.12.0",
        "status": "done",
    }


def test_row_without_the_field_loads_with_the_previous_meaning():
    item = QueueItem.from_dict(_legacy_row())
    assert item.coverage_complete is True
    assert item.status is Status.DONE


def test_round_trip_preserves_an_incomplete_verdict(tmp_path):
    path = tmp_path / "queue.json"
    save_queue(
        [
            QueueItem(
                repo="o/r",
                pr_number=1,
                ecosystem=Ecosystem.NPM,
                package_name="p",
                old_version="1",
                new_version="2",
                coverage_complete=False,
            )
        ],
        path,
    )
    assert load_queue(path)[0].coverage_complete is False
