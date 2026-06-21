"""Hook handlers for agent platform integration."""
from __future__ import annotations

import json
import math
import os
import subprocess
import sys

import typer

from ..core.audit_logger import AuditLogger
from ..core.command_interceptor import CommandInterceptor
from ..scanners.regex_scanner import RegexScanner

# allow_extra_args / ignore_unknown_options: tolerate extra flags/args the host
# harness appends to the hook command (e.g. Claude Code adds `--hook-json <data>`).
# Hook input comes from stdin, so anything else is unused — discard, don't error.
hook_app = typer.Typer(
    name="hook",
    help="Hook handlers for agent platform integration",
    no_args_is_help=True,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
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

def _stdin_timeout_s() -> float:
    # Bound the stdin read so a hung/never-closing stdin can't wedge the hook.
    # Overridable via env (milliseconds, parity with the Node hook) as an
    # operator safety valve / for tests.
    raw = os.environ.get("RAFTER_HOOK_STDIN_TIMEOUT_MS")
    if raw:
        try:
            ms = float(raw)
            # Require finite and positive (parity with the Node `Number.isFinite`
            # check). `inf`/`nan` must NOT pass — `join(timeout=inf)` would
            # reintroduce the exact unbounded hang this bound exists to prevent.
            if math.isfinite(ms) and ms > 0:
                return ms / 1000.0
        except ValueError:
            pass
    return _STDIN_TIMEOUT_S

def _read_stdin() -> str:
    import threading
    result: list[str] = [""]
    def _reader() -> None:
        try:
            result[0] = sys.stdin.read()
        except Exception:
            pass
    # daemon=True: if stdin never closes, the abandoned reader thread does not
    # block interpreter exit, so the process exits after the join timeout.
    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    t.join(timeout=_stdin_timeout_s())
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


def _load_scan_config():
    """Load the policy-merged scan config + suppression list the same way
    scan.py does, so hook decisions match ``rafter secrets`` (sable-55u).

    Returns ``(scan_cfg, suppressions, custom_patterns)``. The hook is
    patterns-only by design (no betterleaks subprocess — it runs on every
    tool call and must stay fast), so betterleaks version skew can never
    affect it; it still honors custom patterns, ``exclude_paths``, and
    ``ignore`` from ``.rafter.yml``.
    """
    from ..core.config_manager import ConfigManager
    from ..core.custom_patterns import load_suppressions, policy_ignore_to_suppressions

    cfg = ConfigManager().load_with_policy()
    scan_cfg = cfg.agent.scan
    custom_patterns = (
        [{"name": p.name, "regex": p.regex, "severity": p.severity} for p in scan_cfg.custom_patterns]
        if scan_cfg and scan_cfg.custom_patterns else None
    )
    # Policy ignore rules first so an explicit reason wins over a bare
    # .rafterignore line covering the same finding.
    suppressions = policy_ignore_to_suppressions(scan_cfg.ignore if scan_cfg else None) + load_suppressions()
    return scan_cfg, suppressions, custom_patterns


# Cap on individual findings listed in a deny reason before truncating.
_MAX_REASON_FINDINGS = 10


def _format_staged_secret_reason(result: dict) -> str:
    """Render a deny reason that names each offending file + pattern (+ line
    when known) instead of a bare count, so the agent knows what to fix
    without a second ``rafter secrets`` run. Truncates long lists.
    """
    repo_root = result.get("repo_root") or os.getcwd()
    lines: list[str] = []
    shown = 0
    for r in result["findings"]:
        try:
            rel = os.path.relpath(r.file, repo_root)
        except ValueError:
            rel = os.path.basename(r.file)
        for m in r.matches:
            if shown >= _MAX_REASON_FINDINGS:
                lines.append(f"  …and {result['count'] - shown} more")
                break
            loc = f":{m.line}" if m.line else ""
            lines.append(f"  {rel}{loc} — {m.pattern.name}")
            shown += 1
        else:
            continue
        break
    return "\n".join([
        f"{result['count']} secret(s) detected in {result['files']} staged file(s):",
        *lines,
        "Hook scan is pattern-only (betterleaks version is irrelevant). "
        "Run 'rafter secrets --staged' for full detail, or add an exclude_paths/ignore "
        "rule to .rafter.yml if this is a false positive.",
    ])


def _scan_staged_files() -> dict:
    """Scan git staged files, routed through the SAME config-aware pipeline
    as ``rafter secrets --staged`` (sable-55u). Previously the hook ran
    RegexScanner directly on the raw staged list with no config, so it
    phantom-blocked commits on findings the CLI would suppress.
    """
    empty = {"secrets_found": False, "count": 0, "files": 0, "findings": [], "repo_root": os.getcwd()}
    try:
        repo_root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True,
        ).stdout.strip() or os.getcwd()

        output = subprocess.run(
            ["git", "diff", "-U0", "--no-color", "--cached", "--diff-filter=ACM"],
            capture_output=True, text=True,
        ).stdout
        if not output.strip():
            return {**empty, "repo_root": repo_root}

        from ..utils.git_diff import parse_unified_diff_added_lines
        from ..scanners.git_diff_scan import scan_added_diff_lines
        from ..core.custom_patterns import apply_suppressions
        from .agent import _apply_exclude_paths

        added = parse_unified_diff_added_lines(output)
        if not added:
            return {**empty, "repo_root": repo_root}

        scan_cfg, suppressions, custom_patterns = _load_scan_config()
        raw = scan_added_diff_lines(added, repo_root, custom_patterns)

        exclude = scan_cfg.exclude_paths if scan_cfg else None
        after_exclude = _apply_exclude_paths(raw, exclude, repo_root)
        kept, _suppressed = apply_suppressions(after_exclude, suppressions)
        total = sum(len(r.matches) for r in kept)
        return {
            "secrets_found": len(kept) > 0,
            "count": total,
            "files": len(kept),
            "findings": kept,
            "repo_root": repo_root,
        }
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"rafter: staged file scan failed: {exc}", file=sys.stderr)
        return empty


def _evaluate_bash(command: str, control=None) -> dict:
    # The production caller (the pretool dispatch) always passes a resolved
    # control. `control=None` defaults to fully-enabled — fail-safe, and keeps
    # the function callable from focused tests that exercise interception/scan
    # without constructing a control object.
    if control is None:
        from ..core.hook_control import HookControl

        control = HookControl(
            hook_enabled=True,
            secret_scan_enabled=True,
            command_policy_enabled=True,
            source_hook="default",
            source_secret_scan="default",
            source_command_policy="default",
        )
    audit = AuditLogger()

    # Command-risk interception — gated by command_policy. When disabled, skip the
    # block/approval logic but still fall through to the staged-secret scan below.
    if control.command_policy_enabled:
        interceptor = CommandInterceptor()
        evaluation = interceptor.evaluate(command)

        # Blocked — hard deny
        if not evaluation.allowed and not evaluation.requires_approval:
            audit.log_command_intercepted(command, False, "blocked", evaluation.reason)
            return {"decision": "deny", "reason": _format_blocked_message(command, evaluation)}

        # Requires approval — deny (hook can't prompt interactively)
        if evaluation.requires_approval:
            audit.log_command_intercepted(command, False, "blocked", evaluation.reason)
            return {"decision": "deny", "reason": _format_approval_message(command, evaluation)}

    # Git commit/push — scan staged files. Gated by secret_scan so the git-commit
    # secret check survives command_policy being disabled on its own.
    trimmed = command.strip()
    if control.secret_scan_enabled and trimmed.startswith(("git commit", "git push")):
        result = _scan_staged_files()
        if result["secrets_found"]:
            # Audit per file so the log records WHICH file + pattern, not a bare count.
            repo_root = result.get("repo_root") or os.getcwd()
            for r in result["findings"]:
                try:
                    rel = os.path.relpath(r.file, repo_root)
                except ValueError:
                    rel = os.path.basename(r.file)
                names = list({m.pattern.name for m in r.matches})
                audit.log_secret_detected(rel, ", ".join(names), "blocked")
            return {
                "decision": "deny",
                "reason": _format_staged_secret_reason(result),
            }

    audit.log_command_intercepted(command, True, "allowed")
    return {"decision": "allow"}


def _evaluate_write(tool_input: dict) -> dict:
    content = tool_input.get("content", "") or tool_input.get("new_string", "")
    if not content:
        return {"decision": "allow"}

    # Route through the same config pipeline as scan.py so the hook honors
    # custom patterns, exclude_paths, and ignore rules from .rafter.yml.
    from ..core.custom_patterns import apply_suppressions
    from ..scanners.regex_scanner import ScanResult
    from .agent import _apply_exclude_paths

    scan_cfg, suppressions, custom_patterns = _load_scan_config()
    scanner = RegexScanner(custom_patterns)
    matches = scanner.scan_text(content)
    if not matches:
        return {"decision": "allow"}

    file_path = tool_input.get("file_path", "file content")
    # Apply exclude_paths + suppressions keyed on the target file path, so a
    # write to a policy-excluded path is allowed (matching `rafter secrets`).
    exclude = scan_cfg.exclude_paths if scan_cfg else None
    after_exclude = _apply_exclude_paths([ScanResult(file=file_path, matches=matches)], exclude, os.getcwd())
    kept, _suppressed = apply_suppressions(after_exclude, suppressions)
    kept_matches = kept[0].matches if kept else []
    if not kept_matches:
        return {"decision": "allow"}

    names = list({m.pattern.name for m in kept_matches})
    audit = AuditLogger()
    audit.log_secret_detected(file_path, ", ".join(names), "blocked")
    return {"decision": "deny", "reason": f"Secret detected in {file_path}: {', '.join(names)}"}


@hook_app.command(
    "pretool",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
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

        # Honor the (trusted-source-only) hook off-switch before doing any work.
        from ..core.hook_control import resolve_hook_control

        control = resolve_hook_control()
        if not control.hook_enabled:
            _write_pretool_decision({"decision": "allow"}, format)
            return

        if tool_name == "Bash":
            decision = _evaluate_bash(tool_input.get("command", ""), control)
        elif tool_name in ("Write", "Edit"):
            if not control.secret_scan_enabled:
                decision = {"decision": "allow"}
            else:
                decision = _evaluate_write(tool_input)
        else:
            decision = {"decision": "allow"}

        _write_pretool_decision(decision, format)
    except Exception:
        # Any unexpected error -> fail open
        _write_pretool_decision({"decision": "allow"}, format)


@hook_app.command(
    "posttool",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
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
