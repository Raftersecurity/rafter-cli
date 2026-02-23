"""Tests for rafter agent baseline command and --baseline scan flag."""
from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from rafter_cli.commands.agent import agent_app, _load_baseline_entries, _apply_baseline
from rafter_cli.scanners.regex_scanner import ScanResult
from rafter_cli.core.pattern_engine import Pattern, PatternMatch


runner = CliRunner()


class TestApplyBaseline:
    def _make_result(self, file: str, pattern: str, line: int | None = 5) -> ScanResult:
        p = Pattern(name=pattern, regex="test", severity="high", description="")
        m = PatternMatch(pattern=p, match="secret", line=line, column=1, redacted="REDACTED")
        return ScanResult(file=file, matches=[m])

    def test_empty_baseline_passes_all(self):
        results = [self._make_result("/f.py", "AWS Access Key")]
        assert _apply_baseline(results, []) == results

    def test_filters_matching_entry(self):
        results = [self._make_result("/f.py", "AWS Access Key", line=5)]
        entries = [{"file": "/f.py", "pattern": "AWS Access Key", "line": 5}]
        assert _apply_baseline(results, entries) == []

    def test_does_not_filter_different_pattern(self):
        results = [self._make_result("/f.py", "AWS Access Key", line=5)]
        entries = [{"file": "/f.py", "pattern": "GitHub Token", "line": 5}]
        out = _apply_baseline(results, entries)
        assert len(out) == 1

    def test_does_not_filter_different_file(self):
        results = [self._make_result("/f.py", "AWS Access Key", line=5)]
        entries = [{"file": "/other.py", "pattern": "AWS Access Key", "line": 5}]
        out = _apply_baseline(results, entries)
        assert len(out) == 1

    def test_null_line_in_baseline_matches_any_line(self):
        results = [self._make_result("/f.py", "AWS Access Key", line=42)]
        entries = [{"file": "/f.py", "pattern": "AWS Access Key", "line": None}]
        assert _apply_baseline(results, entries) == []

    def test_preserves_unfiltered_matches(self):
        p1 = Pattern(name="AWS Access Key", regex="test", severity="high", description="")
        p2 = Pattern(name="GitHub Token", regex="test", severity="high", description="")
        m1 = PatternMatch(pattern=p1, match="s", line=5, column=1, redacted="R1")
        m2 = PatternMatch(pattern=p2, match="s", line=10, column=1, redacted="R2")
        r = ScanResult(file="/f.py", matches=[m1, m2])
        entries = [{"file": "/f.py", "pattern": "AWS Access Key", "line": 5}]
        out = _apply_baseline([r], entries)
        assert len(out) == 1
        assert len(out[0].matches) == 1
        assert out[0].matches[0].pattern.name == "GitHub Token"


class TestBaselineCreate:
    def test_creates_baseline_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("rafter_cli.commands.agent._BASELINE_PATH", tmp_path / "baseline.json")

        # Create a file with a fake secret
        secret_file = tmp_path / "secrets.txt"
        secret_file.write_text("AKIAIOSFODNN7EXAMPLE = test\n")

        result = runner.invoke(agent_app, ["baseline", "create", str(secret_file), "--engine", "patterns"])
        assert result.exit_code == 0

        baseline_path = tmp_path / "baseline.json"
        assert baseline_path.exists()
        data = json.loads(baseline_path.read_text())
        assert data["version"] == 1
        assert "entries" in data

    def test_empty_baseline_on_clean_scan(self, tmp_path, monkeypatch):
        monkeypatch.setattr("rafter_cli.commands.agent._BASELINE_PATH", tmp_path / "baseline.json")

        clean_file = tmp_path / "clean.py"
        clean_file.write_text("x = 1\n")

        result = runner.invoke(agent_app, ["baseline", "create", str(clean_file), "--engine", "patterns"])
        assert result.exit_code == 0
        assert "empty" in result.output.lower() or "0" in result.output

    def test_fails_on_missing_path(self, tmp_path, monkeypatch):
        monkeypatch.setattr("rafter_cli.commands.agent._BASELINE_PATH", tmp_path / "baseline.json")
        result = runner.invoke(agent_app, ["baseline", "create", str(tmp_path / "nonexistent.py")])
        assert result.exit_code != 0


class TestBaselineShow:
    def test_empty_baseline_message(self, tmp_path, monkeypatch):
        monkeypatch.setattr("rafter_cli.commands.agent._BASELINE_PATH", tmp_path / "nonexistent.json")
        result = runner.invoke(agent_app, ["baseline", "show"])
        assert result.exit_code == 0
        assert "empty" in result.output.lower() or "baseline" in result.output.lower()

    def test_shows_entries(self, tmp_path, monkeypatch):
        baseline_path = tmp_path / "baseline.json"
        monkeypatch.setattr("rafter_cli.commands.agent._BASELINE_PATH", baseline_path)

        data = {
            "version": 1,
            "created": "2026-01-01T00:00:00Z",
            "updated": "2026-01-01T00:00:00Z",
            "entries": [
                {"file": "/repo/config.py", "line": 10, "pattern": "AWS Access Key", "addedAt": "2026-01-01T00:00:00Z"},
            ],
        }
        baseline_path.write_text(json.dumps(data))

        result = runner.invoke(agent_app, ["baseline", "show"])
        assert result.exit_code == 0
        assert "AWS Access Key" in result.output
        assert "config.py" in result.output

    def test_json_output(self, tmp_path, monkeypatch):
        baseline_path = tmp_path / "baseline.json"
        monkeypatch.setattr("rafter_cli.commands.agent._BASELINE_PATH", baseline_path)

        data = {"version": 1, "created": "", "updated": "", "entries": []}
        baseline_path.write_text(json.dumps(data))

        result = runner.invoke(agent_app, ["baseline", "show", "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "entries" in parsed


class TestBaselineClear:
    def test_clears_existing_baseline(self, tmp_path, monkeypatch):
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text('{"version":1,"entries":[]}')
        monkeypatch.setattr("rafter_cli.commands.agent._BASELINE_PATH", baseline_path)

        result = runner.invoke(agent_app, ["baseline", "clear"])
        assert result.exit_code == 0
        assert not baseline_path.exists()

    def test_no_error_if_not_exists(self, tmp_path, monkeypatch):
        monkeypatch.setattr("rafter_cli.commands.agent._BASELINE_PATH", tmp_path / "missing.json")
        result = runner.invoke(agent_app, ["baseline", "clear"])
        assert result.exit_code == 0


class TestBaselineAdd:
    def test_adds_entry(self, tmp_path, monkeypatch):
        baseline_path = tmp_path / "baseline.json"
        monkeypatch.setattr("rafter_cli.commands.agent._BASELINE_PATH", baseline_path)

        result = runner.invoke(agent_app, [
            "baseline", "add",
            "--file", "/repo/config.py",
            "--pattern", "AWS Access Key",
            "--line", "42",
        ])
        assert result.exit_code == 0

        data = json.loads(baseline_path.read_text())
        assert len(data["entries"]) == 1
        e = data["entries"][0]
        assert e["pattern"] == "AWS Access Key"
        assert e["line"] == 42

    def test_appends_to_existing(self, tmp_path, monkeypatch):
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps({
            "version": 1, "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
            "entries": [{"file": "/a.py", "line": 1, "pattern": "GitHub Token", "addedAt": "2026-01-01T00:00:00Z"}],
        }))
        monkeypatch.setattr("rafter_cli.commands.agent._BASELINE_PATH", baseline_path)

        runner.invoke(agent_app, ["baseline", "add", "--file", "/b.py", "--pattern", "Slack Token"])
        data = json.loads(baseline_path.read_text())
        assert len(data["entries"]) == 2


class TestInstallHookPush:
    def test_installs_pre_push_hook(self, tmp_path):
        subprocess.run(["git", "init", str(tmp_path)], capture_output=True, check=True)
        original_cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            result = runner.invoke(agent_app, ["install-hook", "--push"])
            assert result.exit_code == 0
            hook_path = tmp_path / ".git" / "hooks" / "pre-push"
            assert hook_path.exists()
            assert "Rafter Security Pre-Push Hook" in hook_path.read_text()
            mode = hook_path.stat().st_mode
            assert mode & stat.S_IXUSR
        finally:
            os.chdir(original_cwd)

    def test_pre_push_hook_idempotent(self, tmp_path):
        subprocess.run(["git", "init", str(tmp_path)], capture_output=True, check=True)
        original_cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            runner.invoke(agent_app, ["install-hook", "--push"])
            result = runner.invoke(agent_app, ["install-hook", "--push"])
            assert result.exit_code == 0
            assert "already installed" in result.output
        finally:
            os.chdir(original_cwd)

    def test_pre_push_hook_template_content(self):
        from rafter_cli.commands.agent import _get_hook_template
        content = _get_hook_template("pre-push")
        assert "Rafter Security Pre-Push Hook" in content
        assert "rafter agent scan" in content
        assert "git push --no-verify" in content
