from __future__ import annotations

import argparse
import logging
import shutil
import sys
from pathlib import Path

from dependabot_plus.analysis.binary_scan import scan_diff_for_new_binaries
from dependabot_plus.analysis.claude_review import review_diff
from dependabot_plus.analysis.source_diff import fetch_source_with_dirs
from dependabot_plus.queue.fetch import fetch_and_save
from dependabot_plus.queue.models import (
    RiskLevel,
    StaticFindings,
    Status,
    Verdict,
    load_queue,
    save_queue,
)
from dependabot_plus.report.github import post_report
from dependabot_plus.sandbox.runner import run_sandbox

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("dependabot_plus")

DEFAULT_QUEUE = Path("queue.json")


def cmd_fetch(args: argparse.Namespace) -> None:
    """Fetch Dependabot PRs and save to queue."""
    queue_path = Path(args.queue_file)
    items = fetch_and_save(args.repo, queue_path)
    queued = [i for i in items if i.status == Status.QUEUED]
    log.info("Queue has %d items (%d new/queued)", len(items), len(queued))


def cmd_process(args: argparse.Namespace) -> None:
    """Process queued items through the full analysis pipeline."""
    queue_path = Path(args.queue_file)
    items = load_queue(queue_path)

    if args.pr:
        items = [i for i in items if i.pr_number == args.pr]

    to_process = [i for i in items if i.status == Status.QUEUED]
    if not to_process:
        log.info("Nothing to process")
        return

    all_items = load_queue(queue_path)

    for item in to_process:
        log.info(
            "Processing PR #%d: %s %s -> %s (%s)",
            item.pr_number, item.package_name,
            item.old_version, item.new_version,
            item.ecosystem.value,
        )

        # Update status
        _update_status(all_items, item, Status.PROCESSING)
        save_queue(all_items, queue_path)

        try:
            verdict = _analyse(item, mode=getattr(args, "mode", "monitor"))
            post_report(item, verdict)
            _update_status(all_items, item, Status.DONE)
            log.info(
                "PR #%d: risk=%s", item.pr_number, verdict.risk_level.value,
            )
        except Exception:
            log.exception("Failed processing PR #%d", item.pr_number)
            _update_status(all_items, item, Status.FAILED)

        save_queue(all_items, queue_path)


def cmd_run(args: argparse.Namespace) -> None:
    """Fetch then process — full pipeline."""
    cmd_fetch(args)
    cmd_process(args)


def _analyse(item, mode="monitor"):
    """Run static + dynamic + binary analysis and return a Verdict."""
    workdir = None
    diff = ""
    binary_findings = []

    # Phase 1: Fetch source diff + binary scan
    log.info("  Fetching source diff...")
    try:
        diff, workdir, old_dir, new_dir = fetch_source_with_dirs(item)
        log.info("  Scanning for suspicious binaries...")
        bin_result = scan_diff_for_new_binaries(old_dir, new_dir)
        if bin_result.binary_count:
            log.info(
                "  Found %d binary file(s), %d suspicious",
                bin_result.binary_count, bin_result.suspicious_count,
            )
        binary_findings = [
            f"{f.path}: {f.reason} ({f.size} bytes)"
            for f in bin_result.findings
        ]
    except Exception:
        log.exception("  Source diff failed, continuing with dynamic only")

    # Phase 2: Claude static review
    log.info("  Running Claude static review...")
    if diff or binary_findings:
        # Include binary findings in the prompt so Claude can factor them in
        extra = ""
        if binary_findings:
            extra = (
                "\n\nBinary file analysis also found these suspicious files:\n"
                + "\n".join(f"- {f}" for f in binary_findings)
            )
        static = review_diff(
            diff + extra, item.package_name, item.ecosystem.value,
        )
        # Merge binary findings into static findings
        static.suspicious_patterns.extend(binary_findings)
    else:
        static = StaticFindings(summary="Source diff unavailable.")

    # Phase 3: Dynamic analysis (sandbox install)
    log.info("  Running sandbox install (mode=%s) ...", mode)
    dynamic = run_sandbox(item, mode=mode)

    # Cleanup source dirs
    if workdir:
        shutil.rmtree(workdir, ignore_errors=True)

    # Check install logs for blocked network attempts (EAI_AGAIN, ENOTFOUND, etc.)
    blocked_network = _scan_install_logs_for_network(dynamic.install_logs)
    if blocked_network:
        log.info("  Install logs indicate blocked network access: %s", blocked_network)

    # Determine overall risk
    risk = _overall_risk(
        static.risk_level, dynamic, bool(binary_findings), bool(blocked_network),
    )

    summary_parts = []
    if static.summary:
        summary_parts.append(f"**Static:** {static.summary}")
    if binary_findings:
        summary_parts.append(
            f"**Binary scan:** {len(binary_findings)} suspicious binary file(s) found."
        )
    if dynamic.file_accesses:
        summary_parts.append(
            f"**Dynamic:** {len(dynamic.file_accesses)} canary file(s) accessed."
        )
    if blocked_network:
        summary_parts.append(
            f"**Network:** Install attempted network access that was blocked: "
            + ", ".join(blocked_network)
        )
    if dynamic.network_attempts:
        summary_parts.append(
            f"**Network:** {len(dynamic.network_attempts)} network event(s) captured."
        )
    if dynamic.install_exit_code != 0 and dynamic.install_exit_code != -1:
        summary_parts.append(
            f"**Install failed** with exit code {dynamic.install_exit_code}."
        )

    return Verdict(
        risk_level=risk,
        static_findings=static,
        dynamic_findings=dynamic,
        summary=" ".join(summary_parts) or "No issues found.",
    )


_NETWORK_ERROR_PATTERNS = [
    ("EAI_AGAIN", "DNS resolution failed (blocked egress)"),
    ("ENOTFOUND", "DNS resolution failed"),
    ("ECONNREFUSED", "Connection refused (blocked egress)"),
    ("ETIMEDOUT", "Connection timed out (blocked egress)"),
    ("ENETUNREACH", "Network unreachable (blocked egress)"),
    ("getaddrinfo", "DNS lookup attempted"),
]


def _scan_install_logs_for_network(logs: str) -> list[str]:
    """Scan install logs for signs of blocked network access."""
    if not logs:
        return []
    findings = []
    seen = set()
    for pattern, desc in _NETWORK_ERROR_PATTERNS:
        if pattern in logs and desc not in seen:
            # Extract the hostname if possible
            import re
            m = re.search(rf'{pattern}.*?(\S+\.(?:com|org|net|io|dev|test)\b)', logs)
            if m:
                findings.append(f"{desc}: {m.group(1)}")
            else:
                findings.append(desc)
            seen.add(desc)
    return findings


def _overall_risk(
    static_risk, dynamic, has_suspicious_binaries=False, has_blocked_network=False,
):
    """Combine static and dynamic signals into an overall risk level."""
    if dynamic.file_accesses:
        return RiskLevel.HIGH
    if dynamic.network_attempts:
        return RiskLevel.HIGH
    if has_blocked_network:
        return RiskLevel.MEDIUM
    if has_suspicious_binaries:
        return RiskLevel.MEDIUM if static_risk != RiskLevel.HIGH else RiskLevel.HIGH
    if static_risk == RiskLevel.HIGH:
        return RiskLevel.HIGH
    if static_risk == RiskLevel.MEDIUM:
        return RiskLevel.MEDIUM
    return static_risk


def _update_status(all_items, item, new_status):
    for i in all_items:
        if i.repo == item.repo and i.pr_number == item.pr_number:
            i.status = new_status
            break


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dependabot-plus",
        description="Analyse Dependabot PRs for supply chain attacks",
    )
    parser.add_argument(
        "--repo", required=True,
        help="GitHub repo (owner/name)",
    )
    parser.add_argument(
        "--queue-file", default=str(DEFAULT_QUEUE),
        help="Path to queue JSON file (default: queue.json)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("fetch", help="Fetch Dependabot PRs into queue")

    proc = sub.add_parser("process", help="Process queued items")
    proc.add_argument(
        "--pr", type=int, default=None,
        help="Process a single PR by number",
    )
    proc.add_argument(
        "--mode", choices=["monitor", "strict"], default="monitor",
        help="Sandbox mode: monitor (network+tcpdump) or strict (no network)",
    )

    run = sub.add_parser("run", help="Fetch and process (full pipeline)")
    run.add_argument(
        "--pr", type=int, default=None,
        help="Process a single PR by number",
    )
    run.add_argument(
        "--mode", choices=["monitor", "strict"], default="monitor",
        help="Sandbox mode: monitor (network+tcpdump) or strict (no network)",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    commands = {
        "fetch": cmd_fetch,
        "process": cmd_process,
        "run": cmd_run,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
