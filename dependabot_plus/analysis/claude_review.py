from __future__ import annotations

import json
import subprocess
import textwrap

from dependabot_plus.queue.models import RiskLevel, StaticFindings

_SYSTEM_PROMPT = textwrap.dedent("""\
    You are a security auditor reviewing a dependency update diff for signs of
    supply chain attacks. Analyse the diff and report findings.

    Look specifically for:
    - Environment variable access or exfiltration (process.env, ENV, os.environ)
    - File system scanning, especially of dotfiles and credential paths
      (~/.ssh, ~/.aws, ~/.npmrc, ~/.gem, /etc/shadow, /etc/passwd)
    - Network requests to unexpected or obfuscated domains
    - Obfuscated code, base64-encoded payloads, eval() of dynamic strings
    - Post-install scripts that execute arbitrary commands
    - Crypto mining indicators (stratum protocols, CPU-intensive loops)
    - Data exfiltration via DNS, HTTP, or other channels

    Respond with JSON only, no markdown fences:
    {
      "risk_level": "low" | "medium" | "high",
      "suspicious_patterns": ["description of each finding"],
      "summary": "one paragraph overall assessment"
    }

    If the diff is clean, return risk_level "low" with an empty suspicious_patterns list.
""")


def build_prompt(diff: str, package_name: str, ecosystem: str) -> str:
    return (
        f"Package: {package_name} (ecosystem: {ecosystem})\n\n"
        f"Diff:\n```\n{diff[:100_000]}\n```"
    )


def review_diff(
    diff: str,
    package_name: str,
    ecosystem: str,
) -> StaticFindings:
    """Send a source diff to Claude for static security analysis."""
    prompt = build_prompt(diff, package_name, ecosystem)

    result = subprocess.run(
        [
            "claude", "-p",
            "--output-format", "json",
            "--system", _SYSTEM_PROMPT,
        ],
        input=prompt,
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode != 0:
        return StaticFindings(
            suspicious_patterns=[f"Claude review failed: {result.stderr[:500]}"],
            risk_level=RiskLevel.UNKNOWN,
            summary="Static analysis could not be completed.",
        )

    try:
        # claude --output-format json wraps the response
        outer = json.loads(result.stdout)
        # The actual text content may be in a "result" field
        text = outer.get("result", result.stdout) if isinstance(outer, dict) else result.stdout
        # Parse the JSON from Claude's response
        if isinstance(text, str):
            data = json.loads(text)
        else:
            data = text
    except (json.JSONDecodeError, TypeError):
        return StaticFindings(
            suspicious_patterns=["Could not parse Claude response as JSON"],
            risk_level=RiskLevel.UNKNOWN,
            summary=result.stdout[:1000],
        )

    return StaticFindings(
        suspicious_patterns=data.get("suspicious_patterns", []),
        risk_level=RiskLevel(data.get("risk_level", "unknown")),
        summary=data.get("summary", ""),
    )
