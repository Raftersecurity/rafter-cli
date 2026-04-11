"""Tests for the completion command — shell completion generation."""
from __future__ import annotations

from typer.testing import CliRunner

from rafter_cli.__main__ import app

runner = CliRunner()


class TestCompletionBash:
    def test_generates_bash_completion(self):
        result = runner.invoke(app, ["completion", "bash"])
        # Typer generates bash completion; should exit 0 or produce output
        # The implementation delegates to typer's --show-completion
        assert result.exit_code == 0

    def test_bash_contains_rafter_reference(self):
        result = runner.invoke(app, ["completion", "bash"])
        if result.exit_code == 0 and result.stdout.strip():
            assert "rafter" in result.stdout.lower()


class TestCompletionZsh:
    def test_generates_zsh_completion(self):
        result = runner.invoke(app, ["completion", "zsh"])
        assert result.exit_code == 0

    def test_zsh_contains_rafter_reference(self):
        result = runner.invoke(app, ["completion", "zsh"])
        if result.exit_code == 0 and result.stdout.strip():
            assert "rafter" in result.stdout.lower()


class TestCompletionFish:
    def test_generates_fish_completion(self):
        result = runner.invoke(app, ["completion", "fish"])
        assert result.exit_code == 0


class TestCompletionErrors:
    def test_unknown_shell_exits_1(self):
        result = runner.invoke(app, ["completion", "powershell"])
        assert result.exit_code == 1

    def test_unknown_shell_shows_error(self):
        result = runner.invoke(app, ["completion", "powershell"])
        # CliRunner mixes stderr into output
        combined = result.output.lower()
        assert "powershell" in combined or "unknown" in combined
