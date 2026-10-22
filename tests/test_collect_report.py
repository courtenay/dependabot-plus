"""The in-container report builder (parses tcpdump/inotify logs into JSON)."""
from __future__ import annotations

import importlib.util
import json
import pathlib

_PATH = pathlib.Path(__file__).parent.parent / "dependabot_plus" / "sandbox" / "dockerfiles" / "collect_report.py"
_spec = importlib.util.spec_from_file_location("collect_report", _PATH)
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)

DNS = """\
100.5 IP (tos 0x0, ttl 64, id 1, offset 0, flags [DF], proto UDP (17), length 60)
    172.17.0.2.54321 > 8.8.8.8.53: 12345+ A? registry.npmjs.org. (32)
100.6 IP (tos 0x0, ttl 64, id 2, offset 0, flags [none], proto UDP (17), length 92)
    8.8.8.8.53 > 172.17.0.2.54321: 12345 1/0/0 registry.npmjs.org. A 104.16.1.35 (64)
200.5 IP (tos 0x0, ttl 64, id 3, offset 0, flags [DF], proto UDP (17), length 60)
    172.17.0.2.54322 > 8.8.8.8.53: 12346+ A? late.evil.example. (32)
"""

TCP = """\
100.7 IP 172.17.0.2.40000 > 104.16.1.35.443: tcp 0
100.8 IP 172.17.0.2.40000 > 104.16.1.35.443: tcp 517
200.7 IP 172.17.0.2.40001 > 203.0.113.5.443: tcp 0
200.9 In IP 203.0.113.5.443 > 172.17.0.2.40001: tcp 0
"""


def test_dns_queries_phases_and_answers():
    queries, post, answers = cr.parse_dns(DNS, install_end=150.0)
    assert queries == ["A? registry.npmjs.org", "A? late.evil.example"]
    assert post == ["A? late.evil.example"]
    assert answers == {"104.16.1.35": ["registry.npmjs.org"]}


def test_tcp_destinations_deduped_and_phased():
    dests, post = cr.parse_tcp(TCP, install_end=150.0)
    assert dests == ["104.16.1.35.443", "203.0.113.5.443"]
    assert post == ["203.0.113.5.443"]


def test_write_log_lines_pass_through(tmp_path):
    (tmp_path / "writes.log").write_text("CREATE|/home/sandbox/.bashrc\n\n")
    (tmp_path / "install.log").write_text("ok")
    out = cr.build_report(str(tmp_path), install_exit=0, install_end=0.0)
    assert out["file_writes"] == ["CREATE|/home/sandbox/.bashrc"]
    assert out["install_exit_code"] == 0
    json.dumps(out)


def test_missing_logs_are_tolerated(tmp_path):
    out = cr.build_report(str(tmp_path), install_exit=1, install_end=0.0)
    assert out["dns_queries"] == [] and out["file_writes"] == [] and out["install_exit_code"] == 1
