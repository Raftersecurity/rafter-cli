"""Hook handlers for agent platform integration."""
from __future__ import annotations

import json
import subprocess
import sys

import typer

from ..core.audit_logger import AuditLogger
from ..core.command_interceptor import CommandInterceptor
from ..scanners.regex_scanner import RegexScanner

hook_app = typer.Typer(name="hook", help="Hook handlers for agent platform integration", no_args_is_help=True)


def _read_stdin() -> str:
    return sys.stdin.read()


def _write_decision(decision: dict) -> None:
    sys.stdout.write(json.dumps(decision) + "\n")
    sys.stdout.flush()


def _scan_staged_files() -> dict:
    try:
        output = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True,
        ).stdout.strip()
        if not output:
            return {"secrets_found": False, "count": 0, "files": 0}
        staged = [f for f in output.split("\n") if f.strip()]
        scanner = RegexScanner()
        results = scanner.scan_files(staged)
        total = sum(len(r.matches) for r in results)
        return {"secrets_found": len(results) > 0, "count": total, "files": len(results)}
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"rafter: staged file scan failed: {exc}", file=sys.stderr)
        return {"secrets_found": False, "count": 0, "files": 0}


def _evaluate_bash(command: str) -> dict:
    interceptor = CommandInterceptor()
    audit = AuditLogger()
    evaluation = interceptor.evaluate(command)

    # Blocked — hard deny
    if not evaluation.allowed and not evaluation.requires_approval:
        audit.log_command_intercepted(command, False, "blocked", evaluation.reason)
        return {"decision": "deny", "reason": f"Blocked by Rafter policy: {evaluation.reason}"}

    # Requires approval — deny (hook can't prompt interactively)
    if evaluation.requires_approval:
        audit.log_command_intercepted(command, False, "blocked", evaluation.reason)
        return {"decision": "deny", "reason": f"Rafter policy requires approval: {evaluation.reason}"}

    # Git commit/push — scan staged files
    trimmed = command.strip()
    if trimmed.startswith(("git commit", "git push")):
        result = _scan_staged_files()
        if result["secrets_found"]:
            audit.log_secret_detected("staged files", f"{result['count']} secret(s)", "blocked")
            return {
                "decision": "deny",
                "reason": f"{result['count']} secret(s) detected in {result['files']} staged file(s). "
                          "Run 'rafter agent scan --staged' for details.",
            }

    audit.log_command_intercepted(command, True, "allowed")
    return {"decision": "allow"}


def _evaluate_write(tool_input: dict) -> dict:
    content = tool_input.get("content", "") or tool_input.get("new_string", "")
    if not content:
        return {"decision": "allow"}

    scanner = RegexScanner()
    if scanner.has_secrets(content):
        matches = scanner.scan_text(content)
        names = list({m.pattern.name for m in matches})
        audit = AuditLogger()
        audit.log_secret_detected(
            tool_input.get("file_path", "file content"),
            ", ".join(names),
            "blocked",
        )
        return {"decision": "deny", "reason": f"Secret detected in file content: {', '.join(names)}"}

    return {"decision": "allow"}


@hook_app.command("pretool")
def pretool():
    """PreToolUse hook handler. Reads tool input JSON from stdin, writes decision to stdout."""
    raw = _read_stdin()

    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        _write_decision({"decision": "allow"})
        return

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})

    if tool_name == "Bash":
        decision = _evaluate_bash(tool_input.get("command", ""))
    elif tool_name in ("Write", "Edit"):
        decision = _evaluate_write(tool_input)
    else:
        decision = {"decision": "allow"}

    _write_decision(decision)
