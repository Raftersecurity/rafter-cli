"""Hook handlers for agent platform integration."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import typer

from ..core.audit_logger import AuditLogger
from ..core.command_interceptor import CommandInterceptor
from ..core.env_writer import SecretToPersist, persist_secrets
from ..scanners.prompt_shield_patterns import (
    CREDENTIAL_KEYWORD_RE,
    DEFAULT_PATTERN_ENV_NAMES,
    PROMPT_SHIELD_PATTERNS,
    PromptShieldPattern,
)
from ..scanners.regex_scanner import RegexScanner

hook_app = typer.Typer(name="hook", help="Hook handlers for agent platform integration", no_args_is_help=True)

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
                          "Run 'rafter secrets --staged' for details.",
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


_PLACEHOLDER_LITERALS = {"changeme", "change-me", "your-secret", "your_secret"}
_PLACEHOLDER_BRACKET_RE = __import__("re").compile(r"^<.+>$")
_PLACEHOLDER_VAR_RE = __import__("re").compile(r"^\$\{?[A-Z_][A-Z0-9_]*\}?$")


def _is_likely_placeholder(value: str) -> bool:
    lower = value.lower()
    if "xxx" in lower and len(lower) < 16:
        return True
    if lower in _PLACEHOLDER_LITERALS:
        return True
    if _PLACEHOLDER_BRACKET_RE.match(value):
        return True
    if _PLACEHOLDER_VAR_RE.match(value):
        return True
    if lower.startswith("example"):
        return True
    return False


def _detect_secrets(text: str) -> list[dict]:
    """Return list of {pattern_name, env_base_name, value} dicts."""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []

    # 1. Prompt-shield patterns (capture-group aware)
    for p in PROMPT_SHIELD_PATTERNS:
        for m in p.regex.finditer(text):
            value = m.group(p.value_group) if p.value_group <= (m.lastindex or 0) else None
            if not value or _is_likely_placeholder(value):
                continue
            if p.name == "Inline credential assignment":
                lhs = m.group(1) if (m.lastindex or 0) >= 1 else ""
                if not CREDENTIAL_KEYWORD_RE.search(lhs):
                    continue
                env_base = lhs
            else:
                env_base = p.env_base_name
            key = (p.name, value)
            if key in seen:
                continue
            seen.add(key)
            out.append({"pattern_name": p.name, "env_base_name": env_base, "value": value})

    # 2. Default secret patterns (full match = value)
    scanner = RegexScanner()
    for match in scanner.scan_text(text):
        value = match.match
        if not value or _is_likely_placeholder(value):
            continue
        base_name = DEFAULT_PATTERN_ENV_NAMES.get(match.pattern.name, "RAFTER_SECRET")
        # Skip if a prompt-shield pattern already captured this exact value.
        if any(prior["value"] == value for prior in out):
            continue
        key = (match.pattern.name, value)
        if key in seen:
            continue
        seen.add(key)
        out.append({"pattern_name": match.pattern.name, "env_base_name": base_name, "value": value})

    return out


def _build_context_note(detected: list[dict], result, written) -> str:
    lines = []
    n = len(detected)
    lines.append(
        f"\U0001f510 Rafter prompt-shield: detected {n} secret{'s' if n != 1 else ''} in the user's prompt."
    )
    if result:
        newly = [w for w in written if not w.already_present]
        reused = [w for w in written if w.already_present]
        if newly:
            lines.append(f"Written to {result.env_file_path}:")
            for w in newly:
                lines.append(f"  - ${w.name}")
        if reused:
            lines.append(f"Already in {result.env_file_path} (reusing existing entries):")
            for w in reused:
                lines.append(f"  - ${w.name}")
        env_state = []
        if result.env_file_created:
            env_state.append(".env was created")
        if result.gitignore_created:
            env_state.append(".gitignore was created with .env")
        elif result.gitignore_updated:
            env_state.append(".env was added to .gitignore")
        if env_state:
            lines.append("(" + "; ".join(env_state) + ")")
    else:
        lines.append("Could not write to .env in the project directory.")
        for d in detected:
            lines.append(f"  - {d['pattern_name']}")
    lines.append("")
    lines.append("⚠️ Treat these literal values as sensitive:")
    lines.append("  - Do NOT echo them back in your reply.")
    lines.append("  - Do NOT write them into source files.")
    lines.append(
        "  - Reference them via the env var names above (e.g., os.environ['DB_PASSWORD'], process.env.DB_PASSWORD)."
    )
    return "\n".join(lines)


@hook_app.command("user-prompt-submit")
def user_prompt_submit(
    mode: str = typer.Option(
        os.environ.get("RAFTER_PROMPT_SHIELD_MODE", "warn"),
        "--mode",
        help="warn (default): pass prompt through with warning context; block: stop the prompt and require re-submit",
    ),
):
    """UserPromptSubmit hook handler.

    Detects secrets in the user's prompt, persists them to .env, ensures
    .gitignore covers .env, and warns the model.
    """
    if os.environ.get("RAFTER_PROMPT_SHIELD") == "0":
        sys.stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}) + "\n")
        sys.stdout.flush()
        return

    try:
        raw = _read_stdin()
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            sys.stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}) + "\n")
            sys.stdout.flush()
            return

        if not isinstance(payload, dict) or not isinstance(payload.get("prompt"), str) or not payload["prompt"]:
            sys.stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}) + "\n")
            sys.stdout.flush()
            return

        detected = _detect_secrets(payload["prompt"])
        if not detected:
            sys.stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}) + "\n")
            sys.stdout.flush()
            return

        root = payload.get("cwd") if isinstance(payload.get("cwd"), str) and payload.get("cwd") else os.getcwd()
        to_persist = [SecretToPersist(base_name=d["env_base_name"], value=d["value"]) for d in detected]

        try:
            result = persist_secrets(to_persist, root)
        except Exception:
            note = _build_context_note(detected, None, [])
            sys.stdout.write(
                json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": note}}) + "\n"
            )
            sys.stdout.flush()
            return

        try:
            audit = AuditLogger()
            audit.log_content_sanitized("user prompt", len(detected))
        except Exception:
            pass

        note = _build_context_note(detected, result, result.written)
        if mode == "block":
            sys.stdout.write(
                json.dumps({
                    "decision": "block",
                    "reason": note + "\n\nRe-submit your prompt referencing the env var names above instead of the literal values.",
                }) + "\n"
            )
        else:
            sys.stdout.write(
                json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": note}}) + "\n"
            )
        sys.stdout.flush()
    except Exception:
        sys.stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}) + "\n")
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
