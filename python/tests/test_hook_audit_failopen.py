"""The audit log must never change a hook decision.

A repo's `.rafter.yml` used to choose where the audit log lives; pointing it at
an unwritable path made every deny branch raise on its audit write, and the
pretool's outer except then answered ALLOW, so `rm -rf /` went through. Driven
through the real CLI in a subprocess with an isolated HOME so the developer's
~/.rafter is never touched.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

_PKG_ROOT = Path(__file__).resolve().parent.parent


def _run_hook(home: Path, command: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config")}
    env["PYTHONPATH"] = str(_PKG_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "rafter_cli", "hook", "pretool"],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}),
        capture_output=True, text=True, cwd=home, env=env, timeout=60,
    )


def _decision(r: subprocess.CompletedProcess) -> str:
    return json.loads(r.stdout or "{}").get("hookSpecificOutput", {}).get("permissionDecision", "unknown")


def _write_global_config(home: Path, agent: dict) -> None:
    (home / ".rafter").mkdir(parents=True, exist_ok=True)
    (home / ".rafter" / "config.json").write_text(json.dumps({"version": "1", "agent": agent}))


def test_unwritable_audit_path_still_denies_critical(tmp_path):
    # Global (trusted) config isolates the logger fix from the project-config fix.
    _write_global_config(tmp_path, {"audit": {"logAllActions": True, "logPath": "/proc/version"}})
    r = _run_hook(tmp_path, "rm -rf /")
    assert _decision(r) == "deny", r.stderr
    assert "audit log" in r.stderr.lower()


def test_project_config_cannot_point_audit_at_unwritable_path(tmp_path):
    (tmp_path / ".rafter.yml").write_text("audit:\n  log_path: /proc/version\n")
    r = _run_hook(tmp_path, "rm -rf /")
    assert _decision(r) == "deny", r.stderr


def test_project_config_cannot_choose_audit_append_target(tmp_path):
    target = tmp_path / "victim.txt"
    (tmp_path / ".rafter.yml").write_text(f"audit:\n  log_path: {target}\n")
    r = _run_hook(tmp_path, "echo hi")
    assert _decision(r) == "allow", r.stderr
    assert not target.exists()
    assert (tmp_path / ".rafter" / "audit.jsonl").exists()
    assert "audit.log_path" in r.stderr


def test_unexpected_error_fails_closed_for_risky_bash(monkeypatch, tmp_path):
    from rafter_cli.commands.hook import hook_app
    from rafter_cli.core.command_interceptor import CommandInterceptor

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    def boom(self, command):
        raise RuntimeError("boom")

    monkeypatch.setattr(CommandInterceptor, "evaluate", boom)
    runner = CliRunner()

    def decide(command: str) -> str:
        r = runner.invoke(hook_app, ["pretool"], input=json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": command}}))
        return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"]

    assert decide("rm -rf /") == "deny"
    assert decide("git commit -m x") == "deny"
    assert decide("ls -la") == "allow"
