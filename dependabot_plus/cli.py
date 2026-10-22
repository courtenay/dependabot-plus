from __future__ import annotations

import argparse
import logging
import shutil
from pathlib import Path

from dependabot_plus.analysis.autorun_scan import scan_diff_for_autorun
from dependabot_plus.analysis.binary_scan import scan_diff_for_new_binaries
from dependabot_plus.analysis.claude_review import review_diff
from dependabot_plus.analysis.source_diff import ChecksumMismatch, fetch_source_with_dirs
from dependabot_plus.queue.fetch import fetch_and_save
from dependabot_plus.queue.models import (
    SKIP_DYNAMIC_ECOSYSTEMS,
    SUPPORTED_ECOSYSTEMS,
    Ecosystem,
    RiskLevel,
    SandboxResult,
    StaticFindings,
    Status,
    Verdict,
    load_queue,
    save_queue,
)
from dependabot_plus.report.github import add_label, post_report
from dependabot_plus.risk import assess
from dependabot_plus.sandbox.egress import assess_egress
from dependabot_plus.sandbox.runner import run_sandbox

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("dependabot_plus")

DEFAULT_QUEUE = Path("queue.json")
DEFAULT_STATIC_VETTED = frozenset({Ecosystem.GO})


def parse_static_vetted(value: str | None) -> frozenset:
    """Parse --static-vetted: ecosystems that may be vetted by deterministic
    source scans alone (no sandbox). Defaults to Go only (sum.golang.org is an
    independent check); an explicit empty string disables it. Unknown names are an error."""
    if value is None:
        return DEFAULT_STATIC_VETTED
    if not value.strip():
        return frozenset()
    try:
        return frozenset(Ecosystem(v.strip()) for v in value.split(",") if v.strip())
    except ValueError as e:
        raise SystemExit(f"--static-vetted: {e}")


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

    static_vetted = parse_static_vetted(getattr(args, "static_vetted", None))

    # Track (risk, vetted) per PR to decide labeling
    pr_verdicts: dict[int, list[tuple[RiskLevel, bool]]] = {}

    for item in to_process:
        log.info(
            "Processing PR #%d: %s %s -> %s (%s)",
            item.pr_number, item.package_name,
            item.old_version, item.new_version,
            item.ecosystem.value,
        )

        if item.ecosystem not in SUPPORTED_ECOSYSTEMS:
            log.info(
                "  Skipping unsupported ecosystem %s for %s",
                item.ecosystem.value, item.package_name,
            )
            _update_status(all_items, item, Status.DONE)
            save_queue(all_items, queue_path)
            # No analysis happened: never counts toward the deps-vetted label.
            pr_verdicts.setdefault(item.pr_number, []).append((RiskLevel.UNKNOWN, False))
            continue

        # Update status
        _update_status(all_items, item, Status.PROCESSING)
        save_queue(all_items, queue_path)

        try:
            verdict = _analyse(
                item, mode=getattr(args, "mode", "monitor"),
                static_vetted_ecosystems=static_vetted,
            )
            post_report(item, verdict)
            _update_status(all_items, item, Status.DONE)
            pr_verdicts.setdefault(item.pr_number, []).append((verdict.risk_level, verdict.vetted))
            log.info(
                "PR #%d: risk=%s", item.pr_number, verdict.risk_level.value,
            )
        except Exception:
            log.exception("Failed processing PR #%d", item.pr_number)
            _update_status(all_items, item, Status.FAILED)
            pr_verdicts.setdefault(item.pr_number, []).append((RiskLevel.UNKNOWN, False))

        save_queue(all_items, queue_path)

    # Label PRs where ALL packages are LOW *and* backed by deterministic evidence
    # (an LLM LOW alone never labels; see dependabot_plus/risk.py)
    for pr_number, risks in pr_verdicts.items():
        # Check all items for this PR are done (including ones from prior runs)
        pr_items = [i for i in all_items if i.pr_number == pr_number]
        all_done = all(i.status in (Status.DONE, Status.FAILED) for i in pr_items)
        all_low = all(r == RiskLevel.LOW and vetted for r, vetted in risks)

        if all_done and all_low:
            repo = pr_items[0].repo
            log.info("PR #%d: all packages LOW with deterministic evidence — adding deps-vetted label", pr_number)
            try:
                add_label(repo, pr_number, "deps-vetted")
            except Exception:
                log.exception("Failed to label PR #%d", pr_number)


def cmd_run(args: argparse.Namespace) -> None:
    """Fetch then process — full pipeline."""
    cmd_fetch(args)
    cmd_process(args)


def _analyse(item, mode="monitor", static_vetted_ecosystems=frozenset()):
    """Run static + dynamic + binary analysis and return a Verdict."""
    workdir = None
    diff = ""
    binary_findings = []
    autorun_findings = []
    has_high_autorun = False
    source_scanned = False
    integrity_failure = False
    integrity_detail = ""

    # Phase 1: Fetch source diff + binary scan + auto-run config scan
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

        log.info("  Scanning for editor/agent auto-run config...")
        autorun_result = scan_diff_for_autorun(old_dir, new_dir)
        if autorun_result.has_findings:
            log.info(
                "  Found %d auto-run config finding(s) (high=%s)",
                len(autorun_result.findings), autorun_result.has_high,
            )
        autorun_findings = [f.describe() for f in autorun_result.findings]
        has_high_autorun = autorun_result.has_high
        source_scanned = True
    except ChecksumMismatch as e:
        integrity_failure = True
        integrity_detail = str(e)
        log.error("  Checksum verification FAILED: %s", e)
    except Exception:
        log.exception("  Source diff failed, continuing with dynamic only")

    # Phase 2: Claude static review
    log.info("  Running Claude static review...")
    if diff or binary_findings or autorun_findings:
        # Scanner findings go to the model as a separate fenced block, not
        # concatenated into the diff.
        scanner_findings = list(binary_findings) + [
            f"auto-run config (zero-click execution risk): {f}" for f in autorun_findings
        ]
        static = review_diff(
            diff, item.package_name, item.ecosystem.value, scanner_findings,
        )
        # Merge pre-computed findings into static findings
        static.suspicious_patterns.extend(binary_findings)
        static.suspicious_patterns.extend(autorun_findings)
    else:
        static = StaticFindings(summary="Source diff unavailable.")

    # Phase 3: Dynamic analysis (sandbox install)
    # Some ecosystems have no install scripts — skip dynamic analysis
    sandbox_ran = item.ecosystem not in SKIP_DYNAMIC_ECOSYSTEMS
    if not sandbox_ran:
        log.info("  Skipping dynamic analysis for %s (no install scripts)", item.ecosystem.value)
        dynamic = SandboxResult(install_exit_code=0, install_logs=f"N/A ({item.ecosystem.value})")
    else:
        log.info("  Running sandbox install (mode=%s) ...", mode)
        dynamic = run_sandbox(item, mode=mode)
        sandbox_ran = dynamic.install_exit_code != -1

    # Cleanup source dirs
    if workdir:
        shutil.rmtree(workdir, ignore_errors=True)

    # Check install logs for blocked network attempts (EAI_AGAIN, ENOTFOUND, etc.)
    blocked_network = _scan_install_logs_for_network(dynamic.install_logs)
    if blocked_network:
        log.info("  Install logs indicate blocked network access: %s", blocked_network)

    if dynamic.sudo_attempts:
        log.info("  SUDO attempts detected: %d", len(dynamic.sudo_attempts))

    # Determine overall risk: the LLM verdict can only raise what deterministic
    # signals say, and cannot vet a package on its own.
    assessment = assess(
        item.ecosystem, static.risk_level, dynamic,
        sandbox_ran=sandbox_ran,
        binary_findings=bool(binary_findings),
        autorun=bool(autorun_findings),
        autorun_high=has_high_autorun,
        blocked_network=bool(blocked_network),
        integrity_failure=integrity_failure,
        source_scanned=source_scanned,
        static_vetted_ecosystems=static_vetted_ecosystems,
    )
    risk = assessment.risk
    egress_findings = assess_egress(
        item.ecosystem, dynamic.network_attempts, resolved_ips=dynamic.dns_answers,
    )

    summary_parts = []
    if static.summary:
        summary_parts.append(f"**Static:** {static.summary}")
    if dynamic.sudo_attempts:
        summary_parts.append(
            f"**Privilege escalation:** {len(dynamic.sudo_attempts)} sudo attempt(s)."
        )
    if binary_findings:
        summary_parts.append(
            f"**Binary scan:** {len(binary_findings)} suspicious binary file(s) found."
        )
    if autorun_findings:
        summary_parts.append(
            f"**Auto-run config:** {len(autorun_findings)} editor/agent auto-run "
            f"finding(s) (zero-click execution risk)"
            + (" — includes high-severity" if has_high_autorun else "") + "."
        )
    if integrity_failure:
        summary_parts.append(
            f"**Integrity:** Go checksum database verification failed ({integrity_detail[:300]})."
        )
    for f in dynamic.detector_findings:
        summary_parts.append(f"**Runtime detector:** {f.get('detail', f.get('path'))}.")
    for ef in egress_findings:
        summary_parts.append(f"**Egress:** {ef.detail} ({ef.risk.value.upper()}).")
    if dynamic.file_accesses:
        summary_parts.append(
            f"**Dynamic:** {len(dynamic.file_accesses)} canary file(s) accessed."
        )
    if blocked_network:
        summary_parts.append(
            "**Network:** Install attempted network access that was blocked: "
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

    if assessment.note:
        summary_parts.append(f"**Not auto-vetted:** {assessment.note}")

    return Verdict(
        risk_level=risk,
        static_findings=static,
        dynamic_findings=dynamic,
        summary=" ".join(summary_parts) or "No issues found.",
        vetted=assessment.vetted,
        vetting_note=assessment.note,
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


def _update_status(all_items, item, new_status):
    for i in all_items:
        if (i.repo == item.repo
                and i.pr_number == item.pr_number
                and i.package_name == item.package_name):
            i.status = new_status
            break


_STATIC_VETTED_HELP = (
    "Comma-separated ecosystems (e.g. go,docker) that may earn deps-vetted from "
    "deterministic source scans without a sandbox. Default: go (needs a completed "
    "source scan and a clean sum.golang.org checksum verification). Docker and "
    "GitHub Actions always need a human unless listed. Pass \"\" to disable all."
)


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
        help="Sandbox mode: monitor (network on, egress logged and scored) or strict (--network=none)",
    )
    proc.add_argument("--static-vetted", default=None, metavar="ECOSYSTEMS", help=_STATIC_VETTED_HELP)

    run = sub.add_parser("run", help="Fetch and process (full pipeline)")
    run.add_argument(
        "--pr", type=int, default=None,
        help="Process a single PR by number",
    )
    run.add_argument(
        "--mode", choices=["monitor", "strict"], default="monitor",
        help="Sandbox mode: monitor (network on, egress logged and scored) or strict (--network=none)",
    )
    run.add_argument("--static-vetted", default=None, metavar="ECOSYSTEMS", help=_STATIC_VETTED_HELP)

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
