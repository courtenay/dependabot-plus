"""Scan package source for editor/tooling auto-run configuration that can
execute code with zero developer interaction — the "VS Code task hijack"
class of supply chain attack.

Hijacked npm packages (and worms like Shai-Hulud) ship config files that the
developer's editor/agent runs automatically when the project folder is merely
opened, or a session starts. The canonical primitive is `.vscode/tasks.json`
with `runOptions.runOn: "folderOpen"`, usually paired with a silent
presentation so nothing is shown to the developer. Related primitives:

- tasks embedded in `*.code-workspace` files (same schema, different host file)
- `.claude/settings.json` hooks (e.g. `SessionStart`) that run shell commands
- `task.allowAutomaticTasks: "on"` in `.vscode/settings.json`
- payloads hidden in non-code assets and run via `node fonts/x.woff2`

These are JSON/text files, so the binary scanner never sees them, and they fire
on *folder open* rather than `npm install`, so the install sandbox misses them
too. This module fills that gap with a static scan of the package source.

See: https://github.com/microsoft/vscode/issues/309406
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field

from dependabot_plus.queue.models import RiskLevel

log = logging.getLogger("dependabot_plus")

# Shell / remote-exec primitives that have no business in an auto-run task
# shipped by a dependency package. Matched case-insensitively as substrings.
_EXEC_KEYWORDS = (
    "curl", "wget", "invoke-webrequest", "iwr", "invoke-expression", "iex",
    "| sh", "|sh", "| bash", "|bash", "bash -c", "sh -c", "powershell",
    "certutil", "bitsadmin", "base64 -d", "base64 --decode", "atob(",
    "eval", "/dev/tcp", " nc ", "ncat", "node -e", "node --eval",
    "python -c", "python3 -c", "ruby -e", "perl -e",
)

# A JS/other runtime pointed at a non-code asset file — the "font payload"
# trick where hex-encoded JS hides inside a .woff2 etc.
_ASSET_EXECUTION = re.compile(
    r"\b(node|bun|deno|ts-node)\b[^\n]*?\."
    r"(woff2?|ttf|otf|eot|dat|bin|png|jpe?g|gif|ico|mp3|mp4|wasm)\b",
    re.IGNORECASE,
)

# Claude Code hook events that fire with no explicit developer action.
_AUTO_FIRE_HOOK_EVENTS = {"SessionStart", "UserPromptSubmit"}


@dataclass
class AutorunFinding:
    path: str
    reason: str
    severity: RiskLevel  # MEDIUM or HIGH
    command: str = ""

    def describe(self) -> str:
        s = f"{self.path}: {self.reason}"
        if self.command:
            s += f" — `{self.command[:200]}`"
        return s


@dataclass
class AutorunScanResult:
    findings: list[AutorunFinding] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity == RiskLevel.HIGH for f in self.findings)


def _strip_comments(text: str) -> str:
    """Strip `//` and `/* */` comments from JSONC, respecting string literals.

    A regex can't do this safely — `//` appears inside URLs (`https://`,
    `/a//b`) within string values. This walks the text as a small state
    machine so comment stripping never touches characters inside strings.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_str = in_line = in_block = False
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            if c == "\n":
                in_line = False
                out.append(c)
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                in_block = False
                i += 2
            else:
                i += 1
        elif in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(nxt)
                i += 2
            else:
                if c == '"':
                    in_str = False
                i += 1
        else:
            if c == '"':
                in_str = True
                out.append(c)
                i += 1
            elif c == "/" and nxt == "/":
                in_line = True
                i += 2
            elif c == "/" and nxt == "*":
                in_block = True
                i += 2
            else:
                out.append(c)
                i += 1
    return "".join(out)


def _parse_jsonc(text: str):
    """Best-effort parse of JSON-with-comments (VS Code config dialect).

    Raises json.JSONDecodeError if it still can't parse, so callers can drop
    to substring detection.
    """
    text = _strip_comments(text)
    # Strip trailing commas before a closing brace/bracket.
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return json.loads(text)


def _command_string(task: dict) -> str:
    """Flatten a task's command + args into one inspectable string."""
    parts: list[str] = []
    cmd = task.get("command")
    if isinstance(cmd, dict):
        cmd = cmd.get("value", "")
    if cmd:
        parts.append(str(cmd))
    args = task.get("args")
    if isinstance(args, list):
        for a in args:
            if isinstance(a, dict):
                a = a.get("value", "")
            parts.append(str(a))
    return " ".join(parts).strip()


def _danger_reason(cmd: str) -> str | None:
    """Return a short reason if a command looks like a stager, else None."""
    low = cmd.lower()
    for kw in _EXEC_KEYWORDS:
        if kw in low:
            return f"command uses a shell/remote-exec primitive ({kw.strip()!r})"
    if _ASSET_EXECUTION.search(cmd):
        return "command runs a runtime against a non-code asset (possible hidden payload)"
    return None


def _is_stealthy(presentation) -> bool:
    """A presentation block configured to hide the task from the developer."""
    if not isinstance(presentation, dict):
        return False
    if str(presentation.get("reveal", "")).lower() in ("never", "silent"):
        return True
    if presentation.get("echo") is False:
        return True
    if presentation.get("close") is True:
        return True
    return False


def _runs_on_folder_open(task: dict, global_run_options) -> bool:
    ro = task.get("runOptions")
    if isinstance(ro, dict) and str(ro.get("runOn", "")).lower() == "folderopen":
        return True
    # Tolerate the (schema-invalid but PoC-observed) top-level form.
    if str(task.get("runOn", "")).lower() == "folderopen":
        return True
    if isinstance(global_run_options, dict) and \
            str(global_run_options.get("runOn", "")).lower() == "folderopen":
        return True
    return False


def _analyse_tasks(tasks_obj, relpath: str) -> list[AutorunFinding]:
    """Inspect a tasks.json-shaped object (dict with `tasks`, or a bare list)."""
    findings: list[AutorunFinding] = []
    if isinstance(tasks_obj, list):
        tasks, global_pres, global_run = tasks_obj, None, None
    elif isinstance(tasks_obj, dict):
        tasks = tasks_obj.get("tasks", [])
        global_pres = tasks_obj.get("presentation")
        global_run = tasks_obj.get("runOptions")
    else:
        return findings

    if not isinstance(tasks, list):
        return findings

    for task in tasks:
        if not isinstance(task, dict):
            continue
        if not _runs_on_folder_open(task, global_run):
            continue

        cmd = _command_string(task)
        stealthy = _is_stealthy(task.get("presentation")) or _is_stealthy(global_pres)
        danger = _danger_reason(cmd)

        reasons = ["auto-runs on folderOpen (zero-click execution)"]
        if stealthy:
            reasons.append("hidden via silent presentation")
        if danger:
            reasons.append(danger)

        severity = RiskLevel.HIGH if (stealthy or danger) else RiskLevel.MEDIUM
        findings.append(AutorunFinding(
            path=relpath,
            reason="VS Code task " + "; ".join(reasons),
            severity=severity,
            command=cmd,
        ))
    return findings


def _collect_hook_commands(obj) -> list[str]:
    """Recursively pull `command` strings out of a hooks config blob."""
    cmds: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "command" and isinstance(v, str):
                cmds.append(v)
            else:
                cmds.extend(_collect_hook_commands(v))
    elif isinstance(obj, list):
        for item in obj:
            cmds.extend(_collect_hook_commands(item))
    return cmds


def _analyse_claude_settings(data, relpath: str) -> list[AutorunFinding]:
    findings: list[AutorunFinding] = []
    if not isinstance(data, dict):
        return findings
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return findings

    for event, spec in hooks.items():
        cmds = _collect_hook_commands(spec)
        if not cmds:
            continue
        joined = " ; ".join(cmds)
        auto = event in _AUTO_FIRE_HOOK_EVENTS
        danger = _danger_reason(joined)
        severity = RiskLevel.HIGH if (auto or danger) else RiskLevel.MEDIUM
        reasons = [f"Claude Code {event} hook runs a shell command"]
        if auto:
            reasons.append("fires automatically (no developer action)")
        if danger:
            reasons.append(danger)
        findings.append(AutorunFinding(
            path=relpath,
            reason="; ".join(reasons),
            severity=severity,
            command=joined,
        ))
    return findings


def _analyse_vscode_settings(data, relpath: str) -> list[AutorunFinding]:
    if not isinstance(data, dict):
        return []
    val = data.get("task.allowAutomaticTasks")
    if str(val).lower() == "on":
        return [AutorunFinding(
            path=relpath,
            reason="enables automatic task execution (task.allowAutomaticTasks: on)",
            severity=RiskLevel.MEDIUM,
        )]
    return []


def _read_text(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _scan_file(path: str, relpath: str) -> list[AutorunFinding]:
    """Dispatch a candidate config file to the right analyser."""
    norm = relpath.replace(os.sep, "/")
    base = os.path.basename(norm).lower()

    text = _read_text(path)
    if text is None:
        return []

    try:
        data = _parse_jsonc(text)
    except (json.JSONDecodeError, ValueError):
        # Unparseable — fall back to a substring tripwire so we don't miss an
        # obfuscated/broken config that still contains the primitive.
        if "folderopen" in text.lower():
            return [AutorunFinding(
                path=relpath,
                reason="contains a 'folderOpen' auto-run directive (unparseable JSON)",
                severity=RiskLevel.HIGH,
            )]
        return []

    if base == "tasks.json":
        return _analyse_tasks(data, relpath)
    if norm.endswith(".code-workspace"):
        # tasks live under the top-level "tasks" key in a workspace file.
        return _analyse_tasks(data.get("tasks") if isinstance(data, dict) else None, relpath)
    if "/.claude/" in f"/{norm}" and base in ("settings.json", "settings.local.json"):
        return _analyse_claude_settings(data, relpath)
    if "/.vscode/" in f"/{norm}" and base == "settings.json":
        return _analyse_vscode_settings(data, relpath)
    return []


def _is_candidate(relpath: str) -> bool:
    norm = f"/{relpath.replace(os.sep, '/')}"
    base = os.path.basename(norm).lower()
    if base == "tasks.json":
        return True
    if norm.endswith(".code-workspace"):
        return True
    if "/.claude/" in norm and base in ("settings.json", "settings.local.json"):
        return True
    if "/.vscode/" in norm and base == "settings.json":
        return True
    return False


def scan_directory(directory: str) -> AutorunScanResult:
    """Walk a directory and flag editor/agent auto-run config."""
    result = AutorunScanResult()
    if not os.path.isdir(directory):
        return result
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            relpath = os.path.relpath(os.path.join(root, fname), directory)
            if not _is_candidate(relpath):
                continue
            result.findings.extend(_scan_file(os.path.join(root, fname), relpath))
    return result


def scan_diff_for_autorun(old_dir: str, new_dir: str) -> AutorunScanResult:
    """Flag auto-run config that is new or changed relative to the old version.

    Unchanged config carried across versions is not re-flagged, matching the
    diff-aware behaviour of the binary scanner.
    """
    result = AutorunScanResult()
    if not os.path.isdir(new_dir):
        return result

    for root, _dirs, files in os.walk(new_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            relpath = os.path.relpath(fpath, new_dir)
            if not _is_candidate(relpath):
                continue

            old_path = os.path.join(old_dir, relpath)
            new_text = _read_text(fpath)
            if new_text is None:
                continue
            if os.path.exists(old_path) and _read_text(old_path) == new_text:
                continue  # unchanged — already present in prior version

            result.findings.extend(_scan_file(fpath, relpath))
    return result
