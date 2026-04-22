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

# Directive injected once per session via Claude Code SessionStart hook. Keep it short —
# this lands in model context every session, so every word costs tokens. Goal: steer
# the agent toward rafter skills + scan without relying on a verbose CLAUDE.md block.
SESSION_START_DIRECTIVE = (
    "Rafter is active in this project. Before `git commit` or signalling a task is done, "
    "run `rafter scan local .` to catch secrets. When working on auth, payments, credentials, "
    "file upload, or data deletion, invoke the `rafter-secure-design` skill before writing code."
)

# Emitted by the Stop hook when the session ends without touching rafter. Blocks at
# most once (stop_hook_active guard) so we never loop the agent.
STOP_DIRECTIVE = (
    "Before finishing: run `rafter scan local .` to catch secrets in the work you just did. "
    "If you touched auth, payments, credentials, file upload, or data deletion, also invoke "
    "the `rafter-secure-design` skill to review the design."
)

_RISK_LABELS = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW",
}

_RISK_DESCRIPTIONS = {
    "critical": "irreversible system damage",
    "high": "significant system changes",
    "medium": "moderate risk operation",
    "low": "minimal risk",
}


def _format_blocked_message(command: str, evaluation) -> str:
    cmd_display = command[:60] + "..." if len(command) > 60 else command
    rule = evaluation.matched_pattern or "policy violation"
    label = _RISK_LABELS.get(evaluation.risk_level, evaluation.risk_level.upper())
    desc = _RISK_DESCRIPTIONS.get(evaluation.risk_level, "")
    return f"\u2717 Rafter blocked: {cmd_display}\n  Rule: {rule}\n  Risk: {label}\u2014{desc}"


def _format_approval_message(command: str, evaluation) -> str:
    cmd_display = command[:60] + "..." if len(command) > 60 else command
    rule = evaluation.matched_pattern or "policy match"
    label = _RISK_LABELS.get(evaluation.risk_level, evaluation.risk_level.upper())
    desc = _RISK_DESCRIPTIONS.get(evaluation.risk_level, "")
    return (
        f"\u26a0 Rafter: approval required\n"
        f"  Command: {cmd_display}\n"
        f"  Rule: {rule}\n"
        f"  Risk: {label}\u2014{desc}\n"
        f"\n"
        f'To approve: rafter agent exec --approve "{command}"\n'
        f"To configure: rafter agent config set agent.riskLevel minimal"
    )


_STDIN_TIMEOUT_S = 5

def _read_stdin() -> str:
    import threading
    result: list[str] = [""]
    def _reader() -> None:
        try:
            result[0] = sys.stdin.read()
        except Exception:
            pass
    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    t.join(timeout=_STDIN_TIMEOUT_S)
    return result[0]


def _write_pretool_decision(decision: dict, fmt: str = "claude") -> None:
    """Write a PreToolUse hook decision in the platform's expected format."""
    is_deny = decision.get("decision") == "deny"
    reason = decision.get("reason", "")

    if fmt == "cursor":
        out: dict = {"permission": "deny" if is_deny else "allow"}
        if is_deny and reason:
            out["agentMessage"] = reason
            out["userMessage"] = reason
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()
    elif fmt == "gemini":
        if is_deny:
            sys.stdout.write(json.dumps({"decision": "deny", "reason": reason}) + "\n")
        else:
            sys.stdout.write("{}\n")
        sys.stdout.flush()
    elif fmt == "windsurf":
        if is_deny:
            sys.stderr.write(reason + "\n")
            sys.stderr.flush()
            sys.exit(2)
        # Allow: exit 0 (no output needed)
    else:
        # Claude Code / Codex / Continue.dev
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny" if is_deny else "allow",
                "permissionDecisionReason": reason,
            },
        }
        sys.stdout.write(json.dumps(output) + "\n")
        sys.stdout.flush()


def _write_posttool_output(output: dict, fmt: str = "claude") -> None:
    """Write a PostToolUse hook output in the platform's expected format."""
    is_modify = output.get("action") == "modify" and "tool_response" in output

    if fmt == "cursor":
        if is_modify:
            sys.stdout.write(json.dumps({"agentMessage": "Rafter redacted secrets from tool output"}) + "\n")
            sys.stdout.flush()
    elif fmt == "gemini":
        if is_modify:
            sys.stdout.write(json.dumps({"systemMessage": "Rafter redacted secrets from tool output"}) + "\n")
        else:
            sys.stdout.write("{}\n")
        sys.stdout.flush()
    elif fmt == "windsurf":
        if is_modify:
            sys.stderr.write("Rafter: secrets redacted from tool output\n")
            sys.stderr.flush()
    else:
        # Claude Code / Codex / Continue.dev
        hook_output: dict = {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
            },
        }
        if is_modify:
            hook_output["hookSpecificOutput"]["modifiedToolResult"] = output["tool_response"]
        sys.stdout.write(json.dumps(hook_output) + "\n")
        sys.stdout.flush()


def _normalize_pretool_input(raw: dict, fmt: str) -> tuple[str, dict]:
    """Normalize platform-specific stdin into (tool_name, tool_input)."""
    if fmt == "cursor":
        event = raw.get("hook_event_name", "")
        if event == "beforeShellExecution":
            return "Bash", {"command": raw.get("command", "")}
        elif event == "beforeReadFile":
            return "Read", raw.get("tool_input", {})
        elif event == "afterFileEdit":
            return "Write", raw.get("tool_input", {})
        return raw.get("tool_name", "unknown"), raw.get("tool_input", {})

    if fmt == "windsurf":
        action = raw.get("agent_action_name", "")
        tool_info = raw.get("tool_info", {})
        if "run_command" in action:
            return "Bash", {"command": tool_info.get("command_line", "")}
        elif "write_code" in action:
            return "Write", tool_info
        elif "read_code" in action:
            return "Read", tool_info
        return tool_info.get("mcp_tool_name", "unknown"), tool_info

    # Claude, Codex, Continue, Gemini
    return raw.get("tool_name", ""), raw.get("tool_input") or {}


def _normalize_posttool_input(raw: dict, fmt: str) -> tuple[str, dict | None]:
    """Normalize platform-specific PostToolUse stdin into (tool_name, tool_response)."""
    if fmt == "windsurf":
        tool_info = raw.get("tool_info", {})
        action = raw.get("agent_action_name", "")
        name = "Bash" if "run_command" in action else (tool_info.get("mcp_tool_name", "unknown"))
        return name, {"output": tool_info.get("stdout", ""), "error": tool_info.get("stderr", "")}

    if fmt == "cursor":
        event = raw.get("hook_event_name", "")
        name = "Bash" if event == "afterShellExecution" else raw.get("tool_name", "unknown")
        resp = raw.get("tool_response") or {}
        return name, {"output": raw.get("output", resp.get("output", "")),
                       "content": raw.get("content", resp.get("content", "")),
                       "error": raw.get("error", resp.get("error", ""))}

    # Claude, Codex, Continue, Gemini
    return raw.get("tool_name", "unknown"), raw.get("tool_response")


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
        return {"decision": "deny", "reason": _format_blocked_message(command, evaluation)}

    # Requires approval — deny (hook can't prompt interactively)
    if evaluation.requires_approval:
        audit.log_command_intercepted(command, False, "blocked", evaluation.reason)
        return {"decision": "deny", "reason": _format_approval_message(command, evaluation)}

    # Git commit/push — scan staged files
    trimmed = command.strip()
    if trimmed.startswith(("git commit", "git push")):
        result = _scan_staged_files()
        if result["secrets_found"]:
            audit.log_secret_detected("staged files", f"{result['count']} secret(s)", "blocked")
            return {
                "decision": "deny",
                "reason": f"{result['count']} secret(s) detected in {result['files']} staged file(s). "
                          "Run 'rafter scan local --staged' for details.",
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
def pretool(
    format: str = typer.Option("claude", "--format", help="Output format: claude (default, also Codex/Continue), cursor, gemini, windsurf"),
):
    """PreToolUse hook handler. Reads tool input JSON from stdin, writes decision to stdout."""
    try:
        raw = _read_stdin()

        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            _write_pretool_decision({"decision": "allow"}, format)
            return

        # Validate payload is a dict with expected shape
        if not isinstance(payload, dict):
            _write_pretool_decision({"decision": "allow"}, format)
            return

        tool_name, tool_input = _normalize_pretool_input(payload, format)

        if not isinstance(tool_input, dict):
            tool_input = {}

        if tool_name == "Bash":
            decision = _evaluate_bash(tool_input.get("command", ""))
        elif tool_name in ("Write", "Edit"):
            decision = _evaluate_write(tool_input)
        else:
            decision = {"decision": "allow"}

        _write_pretool_decision(decision, format)
    except Exception:
        # Any unexpected error -> fail open
        _write_pretool_decision({"decision": "allow"}, format)


@hook_app.command("session-start")
def session_start(
    format: str = typer.Option("claude", "--format", help="Output format: claude (default)"),
):
    """SessionStart hook handler. Emits additionalContext to steer the agent toward rafter skills + scan."""
    try:
        # Drain stdin (best-effort) — some agents send a JSON payload we ignore.
        _read_stdin()
        output = {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": SESSION_START_DIRECTIVE,
            },
        }
        sys.stdout.write(json.dumps(output) + "\n")
        sys.stdout.flush()
    except Exception:
        # Fail soft — don't block session startup.
        sys.stdout.write("{}\n")
        sys.stdout.flush()


_RAFTER_BASH_RE = None


def _scan_single_transcript(path_str: str) -> bool:
    """Scan one JSONL for a rafter CLI or rafter-* Skill invocation."""
    import re
    global _RAFTER_BASH_RE
    if _RAFTER_BASH_RE is None:
        _RAFTER_BASH_RE = re.compile(r"\brafter\s+(scan|mcp|skill|agent\s+scan|agent\s+audit)\b")

    try:
        with open(path_str, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return False

    for line in text.split("\n"):
        if not line:
            continue
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue

        message = entry.get("message") or {}
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue

        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            name = block.get("name") or ""
            block_input = block.get("input") or {}

            if name == "Bash":
                cmd = str(block_input.get("command", "")) if isinstance(block_input, dict) else ""
                if _RAFTER_BASH_RE.search(cmd):
                    return True

            if name == "Skill":
                skill = ""
                if isinstance(block_input, dict):
                    skill = str(block_input.get("skill") or block_input.get("name") or "")
                if skill.startswith("rafter-") or skill.startswith("rafter:"):
                    return True
    return False


def _transcript_touched_rafter(transcript_path: str) -> bool:
    """Check main transcript + any subagent transcripts for rafter engagement.

    Claude Code writes subagent transcripts under
    ``<dir>/<main_basename_without_.jsonl>/subagents/*.jsonl`` — delegated work
    counts toward engagement.
    """
    import os
    if _scan_single_transcript(transcript_path):
        return True

    parent = os.path.dirname(transcript_path)
    base = os.path.basename(transcript_path)
    if base.endswith(".jsonl"):
        base = base[:-len(".jsonl")]
    sub_dir = os.path.join(parent, base, "subagents")
    if not os.path.isdir(sub_dir):
        return False
    try:
        entries = os.listdir(sub_dir)
    except OSError:
        return False
    for f in entries:
        if not f.endswith(".jsonl"):
            continue
        if _scan_single_transcript(os.path.join(sub_dir, f)):
            return True
    return False


@hook_app.command("stop")
def stop(
    format: str = typer.Option("claude", "--format", help="Output format: claude (default)"),
):
    """Stop hook handler. Blocks completion (once) until rafter scan or rafter skill has run."""
    try:
        raw = _read_stdin()
        try:
            payload = json.loads(raw) if raw else {}
        except (json.JSONDecodeError, ValueError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}

        # Prevent infinite loops — we block at most once per session.
        if payload.get("stop_hook_active"):
            sys.stdout.write("{}\n")
            sys.stdout.flush()
            return

        transcript = payload.get("transcript_path")
        if not transcript or not _transcript_touched_rafter(str(transcript)):
            sys.stdout.write(json.dumps({
                "decision": "block",
                "reason": STOP_DIRECTIVE,
            }) + "\n")
            sys.stdout.flush()
            return

        sys.stdout.write("{}\n")
        sys.stdout.flush()
    except Exception:
        # Fail open — never trap the agent if the hook itself breaks.
        sys.stdout.write("{}\n")
        sys.stdout.flush()


@hook_app.command("posttool")
def posttool(
    format: str = typer.Option("claude", "--format", help="Output format: claude (default, also Codex/Continue), cursor, gemini, windsurf"),
):
    """PostToolUse hook handler. Reads tool response JSON from stdin, redacts secrets in output, writes action to stdout."""
    try:
        raw = _read_stdin()

        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            _write_posttool_output({"action": "continue"}, format)
            return

        # Validate payload is a dict
        if not isinstance(payload, dict):
            _write_posttool_output({"action": "continue"}, format)
            return

        tool_name, tool_response = _normalize_posttool_input(payload, format)

        # No response body — pass through
        if not tool_response or not isinstance(tool_response, dict):
            _write_posttool_output({"action": "continue"}, format)
            return

        scanner = RegexScanner()
        modified = False
        redacted = dict(tool_response)

        # Scan and redact output field
        output_text = tool_response.get("output", "")
        if output_text and isinstance(output_text, str) and scanner.has_secrets(output_text):
            redacted["output"] = scanner.redact(output_text)
            modified = True

        # Scan and redact content field (used by some tools)
        content_text = tool_response.get("content", "")
        if content_text and isinstance(content_text, str) and scanner.has_secrets(content_text):
            redacted["content"] = scanner.redact(content_text)
            modified = True

        if modified:
            audit = AuditLogger()
            match_count = 0
            if output_text and isinstance(output_text, str):
                match_count += len(scanner.scan_text(output_text))
            if content_text and isinstance(content_text, str):
                match_count += len(scanner.scan_text(content_text))
            audit.log_content_sanitized(f"{tool_name} tool response", match_count)
            _write_posttool_output({"action": "modify", "tool_response": redacted}, format)
            return

        _write_posttool_output({"action": "continue"}, format)
    except Exception:
        # Any unexpected error -> fail open
        _write_posttool_output({"action": "continue"}, format)
