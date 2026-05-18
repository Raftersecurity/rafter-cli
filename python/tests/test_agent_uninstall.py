"""Tests for `rafter agent uninstall` — the bulk revert of `rafter agent init`.
Mirrors node/tests/agent-uninstall.test.ts.

Each test gets a fake HOME so on-disk side effects are inspectable and the
developer's real configs aren't touched.
"""
from __future__ import annotations

import json
import os
import site
import subprocess
import sys
from pathlib import Path

import pytest

# Captured under the real HOME so user-site packages (typer, etc.) remain
# importable in subprocesses launched with HOME overridden to tmp_path.
_USER_BASE = site.getuserbase()


def _run_cli(args: str, home: Path) -> tuple[str, str, int]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["PYTHONUSERBASE"] = _USER_BASE
    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", *args.split()],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(home),
        timeout=30,
    )
    return result.stdout, result.stderr, result.returncode


def _snapshot_tree(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in root.rglob("*"):
        if p.is_file():
            out[str(p.relative_to(root))] = p.read_text(encoding="utf-8")
    return out


@pytest.fixture
def home(tmp_path: Path) -> Path:
    return tmp_path


class TestAgentUninstall:
    def test_nothing_to_uninstall_when_empty(self, home: Path):
        stdout, stderr, code = _run_cli("agent uninstall --yes", home)
        assert code == 0
        assert "Nothing to uninstall" in (stdout + stderr)

    def test_dry_run_writes_nothing(self, home: Path):
        (home / ".cursor").mkdir()
        _run_cli("agent enable cursor.mcp", home)
        before = _snapshot_tree(home)

        stdout, _, code = _run_cli("agent uninstall --dry-run --yes", home)
        assert code == 0
        assert "DRY RUN" in stdout
        assert "cursor.mcp" in stdout
        assert _snapshot_tree(home) == before

    def test_yes_skips_confirmation_and_reverses_components(self, home: Path):
        (home / ".cursor").mkdir()
        (home / ".claude").mkdir()
        _run_cli("agent enable cursor.mcp", home)
        _run_cli("agent enable claude-code.mcp", home)
        _run_cli("agent enable claude-code.instructions", home)
        assert (home / ".cursor" / "mcp.json").exists()

        _, stderr, code = _run_cli("agent uninstall --yes", home)
        assert code == 0, f"stderr={stderr!r}"

        cursor_cfg = json.loads((home / ".cursor" / "mcp.json").read_text())
        assert "rafter" not in (cursor_cfg.get("mcpServers") or {})

        # claude-code.mcp writes <cwd>/.mcp.json; with only rafter present
        # uninstall deletes the file.
        assert not (home / ".mcp.json").exists()

        claude_md = home / ".claude" / "CLAUDE.md"
        if claude_md.exists():
            assert "rafter:start" not in claude_md.read_text()

    def test_preserves_pre_existing_non_rafter_hook(self, home: Path):
        (home / ".claude").mkdir()
        settings_path = home / ".claude" / "settings.json"
        settings_path.write_text(json.dumps({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [
                        {"type": "command", "command": "some-other-tool guard"},
                    ]},
                ],
            },
        }, indent=2))

        _run_cli("agent enable claude-code.hooks", home)
        _run_cli("agent uninstall --yes", home)

        s = json.loads(settings_path.read_text())
        cmds = [h["command"] for e in (s.get("hooks") or {}).get("PreToolUse", []) for h in e["hooks"]]
        assert "some-other-tool guard" in cmds
        assert "rafter hook pretool" not in cmds

    def test_round_trip_returns_filesystem(self, home: Path):
        (home / ".cursor").mkdir()
        (home / ".claude").mkdir()
        before = _snapshot_tree(home)

        _run_cli("agent enable cursor.mcp", home)
        _run_cli("agent enable claude-code.instructions", home)
        _run_cli("agent enable claude-code.mcp", home)

        _, _, code = _run_cli("agent uninstall --yes", home)
        assert code == 0

        after = _snapshot_tree(home)
        # ~/.rafter/config.json is allowed to exist (records component state);
        # exclude it from the comparison.
        after = {k: v for k, v in after.items() if not k.startswith(".rafter/")}
        assert after == before

    def test_preserves_audit_log_without_purge(self, home: Path):
        rafter_dir = home / ".rafter"
        rafter_dir.mkdir()
        (rafter_dir / "audit.jsonl").write_text('{"event":"test"}\n')
        (rafter_dir / "config.json").write_text('{"keep":true}')

        (home / ".cursor").mkdir()
        _run_cli("agent enable cursor.mcp", home)

        _, _, code = _run_cli("agent uninstall --yes", home)
        assert code == 0

        assert (rafter_dir / "audit.jsonl").exists()
        assert "test" in (rafter_dir / "audit.jsonl").read_text()
        assert (rafter_dir / "config.json").exists()

    def test_purge_removes_rafter_dir(self, home: Path):
        rafter_dir = home / ".rafter"
        (rafter_dir / "bin").mkdir(parents=True)
        (rafter_dir / "audit.jsonl").write_text('{"event":"test"}\n')
        (rafter_dir / "config.json").write_text('{"keep":true}')
        (rafter_dir / "bin" / "betterleaks").write_text("fake binary")

        (home / ".cursor").mkdir()
        _run_cli("agent enable cursor.mcp", home)

        _, _, code = _run_cli("agent uninstall --purge --yes", home)
        assert code == 0

        assert not (rafter_dir / "audit.jsonl").exists()
        assert not (rafter_dir / "bin").exists()

    def test_idempotent_second_run_noop(self, home: Path):
        (home / ".cursor").mkdir()
        _run_cli("agent enable cursor.mcp", home)
        _run_cli("agent uninstall --yes", home)

        before = _snapshot_tree(home)
        stdout, stderr, code = _run_cli("agent uninstall --yes", home)
        assert code == 0
        assert "Nothing to uninstall" in (stdout + stderr)
        assert _snapshot_tree(home) == before
