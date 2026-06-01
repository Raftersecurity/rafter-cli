"""Tests for rafter policy export command."""
from __future__ import annotations

import json

from rafter_cli.commands.policy import _generate_claude_config
from rafter_cli.core.policy_loader import _validate_policy, _map_policy, find_policy_file, load_policy


class TestBackendCompat:
    """sable-c1c — CLI reads .rafter/config.yml indefinitely and accepts
    backend's flat-shape schema alongside the canonical nested form."""

    def test_finds_subdir_config_yml_as_fallback(self, tmp_path, monkeypatch):
        import subprocess
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        (tmp_path / ".rafter").mkdir()
        (tmp_path / ".rafter" / "config.yml").write_text("version: '1'\n")
        monkeypatch.chdir(tmp_path)
        assert find_policy_file() == tmp_path / ".rafter" / "config.yml"

    def test_finds_subdir_config_yaml_as_fallback(self, tmp_path, monkeypatch):
        import subprocess
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        (tmp_path / ".rafter").mkdir()
        (tmp_path / ".rafter" / "config.yaml").write_text("version: '1'\n")
        monkeypatch.chdir(tmp_path)
        assert find_policy_file() == tmp_path / ".rafter" / "config.yaml"

    def test_dotfile_wins_over_subdir(self, tmp_path, monkeypatch):
        import subprocess
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        (tmp_path / ".rafter.yml").write_text("version: 'dot'\n")
        (tmp_path / ".rafter").mkdir()
        (tmp_path / ".rafter" / "config.yml").write_text("version: 'subdir'\n")
        monkeypatch.chdir(tmp_path)
        assert find_policy_file() == tmp_path / ".rafter.yml"
        policy = load_policy()
        assert policy["version"] == "dot"

    def test_top_level_exclude_paths_accepted(self):
        raw = {"exclude_paths": ["scripts/", "components/common/Mermaid.tsx"]}
        result = _validate_policy(_map_policy(raw), raw)
        assert result["scan"]["exclude_paths"] == ["scripts/", "components/common/Mermaid.tsx"]

    def test_top_level_custom_patterns_accepted(self):
        raw = {
            "custom_patterns": [
                {"name": "Foo", "regex": "foo-[a-z0-9]+", "severity": "high"},
            ],
        }
        result = _validate_policy(_map_policy(raw), raw)
        assert result["scan"]["custom_patterns"][0]["name"] == "Foo"

    def test_nested_wins_over_top_level(self):
        raw = {
            "exclude_paths": ["flat"],
            "scan": {"exclude_paths": ["nested"]},
        }
        result = _validate_policy(_map_policy(raw), raw)
        assert result["scan"]["exclude_paths"] == ["nested"]

    def test_no_warnings_for_compat_keys(self, capsys):
        raw = {"exclude_paths": ["foo/"], "custom_patterns": []}
        _validate_policy(_map_policy(raw), raw)
        err = capsys.readouterr().err
        assert "exclude_paths" not in err
        assert "custom_patterns" not in err


class TestGenerateClaudeConfig:
    def test_valid_json(self):
        output = _generate_claude_config()
        config = json.loads(output)
        assert "hooks" in config
        assert "PreToolUse" in config["hooks"]

    def test_has_bash_matcher(self):
        config = json.loads(_generate_claude_config())
        matchers = [entry["matcher"] for entry in config["hooks"]["PreToolUse"]]
        assert "Bash" in matchers

    def test_has_write_edit_matcher(self):
        config = json.loads(_generate_claude_config())
        matchers = [entry["matcher"] for entry in config["hooks"]["PreToolUse"]]
        assert "Write|Edit" in matchers

    def test_hook_command(self):
        config = json.loads(_generate_claude_config())
        for entry in config["hooks"]["PreToolUse"]:
            for hook in entry["hooks"]:
                assert hook["command"] == "rafter hook pretool"
                assert hook["type"] == "command"


class TestValidatePolicyUnknownKeys:
    """Unknown top-level keys warn on stderr and are not propagated."""

    def test_unknown_keys_warn_and_strip(self, capsys):
        raw = {"version": "1", "risk_level": "moderate", "banana": True, "foo": 42}
        policy = _map_policy(raw)
        result = _validate_policy(policy, raw)
        err = capsys.readouterr().err
        assert '"banana"' in err
        assert '"foo"' in err
        assert "banana" not in result
        assert "foo" not in result
        # Valid keys survive
        assert result["risk_level"] == "moderate"


class TestValidateRiskLevel:
    """Invalid risk_level stripped; valid preserved."""

    def test_invalid_risk_level_stripped(self, capsys):
        raw = {"risk_level": "extreme"}
        policy = _map_policy(raw)
        result = _validate_policy(policy, raw)
        err = capsys.readouterr().err
        assert "risk_level" in err
        assert "risk_level" not in result

    def test_valid_risk_level_preserved(self, capsys):
        raw = {"risk_level": "moderate"}
        policy = _map_policy(raw)
        result = _validate_policy(policy, raw)
        capsys.readouterr()  # consume any output
        assert result["risk_level"] == "moderate"


class TestValidateCommandPolicy:
    """command_policy.mode and blocked_patterns validation."""

    def test_invalid_mode_stripped(self, capsys):
        raw = {"command_policy": {"mode": "yolo"}}
        policy = _map_policy(raw)
        result = _validate_policy(policy, raw)
        err = capsys.readouterr().err
        assert "command_policy.mode" in err
        assert "mode" not in result.get("command_policy", {})

    def test_non_string_blocked_patterns_stripped(self, capsys):
        raw = {"command_policy": {"blocked_patterns": [1, 2]}}
        policy = _map_policy(raw)
        result = _validate_policy(policy, raw)
        err = capsys.readouterr().err
        assert "blocked_patterns" in err
        assert "blocked_patterns" not in result.get("command_policy", {})


class TestValidateFullPolicy:
    """A fully valid policy passes through unchanged."""

    def test_valid_policy_preserved(self, capsys):
        raw = {
            "version": "1",
            "risk_level": "aggressive",
            "command_policy": {
                "mode": "deny-list",
                "blocked_patterns": ["rm -rf /"],
                "require_approval": ["sudo *"],
            },
            "scan": {
                "exclude_paths": ["vendor/"],
                "custom_patterns": [
                    {"name": "AWS Key", "regex": "AKIA[0-9A-Z]{16}", "severity": "high"},
                ],
            },
            "audit": {
                "retention_days": 90,
                "log_level": "warn",
            },
        }
        policy = _map_policy(raw)
        result = _validate_policy(policy, raw)
        err = capsys.readouterr().err
        assert err == ""
        assert result["version"] == "1"
        assert result["risk_level"] == "aggressive"
        assert result["command_policy"]["mode"] == "deny-list"
        assert result["command_policy"]["blocked_patterns"] == ["rm -rf /"]
        assert result["command_policy"]["require_approval"] == ["sudo *"]
        assert result["scan"]["exclude_paths"] == ["vendor/"]
        assert len(result["scan"]["custom_patterns"]) == 1
        assert result["audit"]["retention_days"] == 90
        assert result["audit"]["log_level"] == "warn"


class TestValidateCustomPatterns:
    """Empty name/regex in custom_patterns is rejected."""

    def test_empty_regex_stripped(self, capsys):
        raw = {
            "scan": {
                "custom_patterns": [
                    {"name": "", "regex": "", "severity": "high"},
                ],
            },
        }
        policy = _map_policy(raw)
        result = _validate_policy(policy, raw)
        err = capsys.readouterr().err
        assert "custom_patterns" in err
        assert "custom_patterns" not in result.get("scan", {})


class TestMapPolicyRetentionDays:
    """Non-numeric retention_days in _map_policy should warn, not crash."""

    def test_non_numeric_retention_days(self, capsys):
        raw = {"audit": {"retention_days": "thirty"}}
        policy = _map_policy(raw)
        err = capsys.readouterr().err
        assert "retention_days" in err
        assert "retention_days" not in policy.get("audit", {})


class TestValidateLogLevel:
    """Invalid log_level stripped; all valid levels accepted."""

    def test_invalid_log_level_stripped(self, capsys):
        raw = {"audit": {"log_level": "verbose"}}
        policy = _map_policy(raw)
        result = _validate_policy(policy, raw)
        err = capsys.readouterr().err
        assert "log_level" in err
        assert "log_level" not in result.get("audit", {})

    def test_valid_log_levels_accepted(self, capsys):
        for level in ("debug", "info", "warn", "error"):
            raw = {"audit": {"log_level": level}}
            policy = _map_policy(raw)
            result = _validate_policy(policy, raw)
            err = capsys.readouterr().err
            assert err == "", f"Unexpected warning for log_level={level}"
            assert result["audit"]["log_level"] == level


class TestIgnoreRules:
    """`.rafter.yml` ignore section parsing + validation."""

    def test_parses_paths_rules_reason(self):
        raw = {"ignore": [
            {"paths": ["tests/fixtures/**", "*.example.env"],
             "rules": ["AWS Access Key", "Generic API Key"],
             "reason": "test fixtures"},
            {"paths": ["docs/**"], "reason": "docs examples"},
        ]}
        result = _validate_policy(_map_policy(raw), raw)
        assert len(result["ignore"]) == 2
        assert result["ignore"][0]["paths"] == ["tests/fixtures/**", "*.example.env"]
        assert result["ignore"][0]["rules"] == ["AWS Access Key", "Generic API Key"]
        assert result["ignore"][0]["reason"] == "test fixtures"
        assert "rules" not in result["ignore"][1]

    def test_skips_entries_without_paths(self, capsys):
        raw = {"ignore": [
            {"rules": ["AWS Access Key"]},
            {"paths": ["valid/**"], "reason": "kept"},
        ]}
        # _map_policy already drops the malformed entry; validate sees only the valid one.
        # We exercise validate directly with an unfiltered policy to assert the warning path.
        result = _validate_policy(
            {"ignore": [{"rules": ["AWS Access Key"]}, {"paths": ["valid/**"], "reason": "kept"}]},
            raw,
        )
        err = capsys.readouterr().err
        assert "paths" in err
        assert len(result["ignore"]) == 1
        assert result["ignore"][0]["paths"] == ["valid/**"]

    def test_empty_ignore_array_dropped(self):
        raw = {"ignore": []}
        result = _validate_policy(_map_policy(raw), raw)
        assert "ignore" not in result

    def test_non_array_ignore_warned_and_dropped(self, capsys):
        result = _validate_policy({"ignore": "not-a-list"}, {"ignore": "not-a-list"})
        err = capsys.readouterr().err
        assert "ignore" in err
        assert "ignore" not in result
