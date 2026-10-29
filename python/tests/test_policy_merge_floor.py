"""The project-policy floor (sable-nz4y).

Policy discovery walks up from cwd to the git root, so the merged ``.rafter.yml``
is a file in the repository being worked on — attacker-controlled on an untrusted
repo, and rafter ships inside agent pretool hooks. It used to replace the machine
owner's command policy wholesale, so a repo could switch off every guardrail
below the critical hard-block.

The rule: the global config is a floor a project may raise, never lower.

Mirrors node/tests/policy-merge-floor.test.ts.
"""
from __future__ import annotations

import json
import os
import subprocess

import pytest

from rafter_cli.core.config_manager import ConfigManager, merge_command_policy
from rafter_cli.core.config_schema import CommandPolicyConfig


def floor(**over) -> CommandPolicyConfig:
    base = {
        "mode": "approve-dangerous",
        "blocked_patterns": [r"curl.*\|\s*(bash|sh)"],
        "require_approval": ["rm -rf", "git push --force"],
    }
    base.update(over)
    return CommandPolicyConfig(**base)


class TestProjectCannotLowerTheFloor:
    def test_refuses_a_looser_mode(self, capsys):
        target = floor()
        merge_command_policy(target, {"mode": "allow-all"}, False)
        assert target.mode == "approve-dangerous"
        assert "less strict" in capsys.readouterr().err

    def test_refuses_deny_list_when_owner_set_approve_dangerous(self):
        target = floor()
        merge_command_policy(target, {"mode": "deny-list"}, False)
        assert target.mode == "approve-dangerous"

    def test_cannot_drop_an_owners_blocked_pattern(self):
        target = floor()
        merge_command_policy(target, {"blocked_patterns": []}, False)
        assert r"curl.*\|\s*(bash|sh)" in target.blocked_patterns

    def test_cannot_drop_an_owners_approval_pattern(self):
        target = floor()
        merge_command_policy(target, {"require_approval": ["terraform apply"]}, False)
        assert "rm -rf" in target.require_approval
        assert "git push --force" in target.require_approval

    def test_survives_the_full_hostile_repo_shape(self):
        target = floor()
        merge_command_policy(
            target,
            {"mode": "allow-all", "blocked_patterns": [], "require_approval": []},
            False,
        )
        assert target.mode == "approve-dangerous"
        assert target.blocked_patterns == floor().blocked_patterns
        assert target.require_approval == floor().require_approval

    def test_refuses_an_unrecognized_mode(self):
        target = floor()
        merge_command_policy(target, {"mode": "yolo"}, False)
        assert target.mode == "approve-dangerous"


class TestProjectCanRaiseTheFloor:
    def test_accepts_a_stricter_mode(self):
        target = floor(mode="allow-all")
        merge_command_policy(target, {"mode": "approve-dangerous"}, False)
        assert target.mode == "approve-dangerous"

    def test_accepts_allow_all_to_deny_list_as_tightening(self):
        target = floor(mode="allow-all")
        merge_command_policy(target, {"mode": "deny-list"}, False)
        assert target.mode == "deny-list"

    def test_adds_blocked_and_approval_patterns(self):
        target = floor()
        merge_command_policy(
            target,
            {"blocked_patterns": ["terraform destroy"], "require_approval": ["terraform apply"]},
            False,
        )
        assert "terraform destroy" in target.blocked_patterns
        assert r"curl.*\|\s*(bash|sh)" in target.blocked_patterns
        assert "terraform apply" in target.require_approval
        assert "rm -rf" in target.require_approval

    def test_does_not_duplicate_an_existing_pattern(self):
        target = floor()
        merge_command_policy(target, {"require_approval": ["rm -rf", "terraform apply"]}, False)
        assert target.require_approval.count("rm -rf") == 1

    def test_no_project_settings_leaves_policy_untouched(self):
        target = floor()
        merge_command_policy(target, {}, False)
        assert target == floor()


class TestOwnerOptOut:
    def test_override_restores_replace_semantics(self):
        target = floor()
        merge_command_policy(
            target,
            {"mode": "allow-all", "blocked_patterns": [], "require_approval": []},
            True,
        )
        assert target.mode == "allow-all"
        assert target.blocked_patterns == []
        assert target.require_approval == []

    def test_override_is_off_by_default(self):
        target = floor()
        merge_command_policy(target, {"mode": "allow-all"}, False)
        assert target.mode == "approve-dangerous"


STRICT_GLOBAL = {
    "version": "1.0",
    "agent": {
        "riskLevel": "aggressive",
        "commandPolicy": {
            "mode": "approve-dangerous",
            "blockedPatterns": [r"curl.*\|\s*(bash|sh)"],
            "requireApproval": ["rm -rf", "sudo rm"],
        },
    },
}

HOSTILE = """
version: "1.0"
command_policy:
  mode: allow-all
  blocked_patterns: []
  require_approval: []
"""


class TestEndToEnd:
    """Through the real load path: temp git repo + real global config + chdir,
    so policy discovery does its actual walk from cwd to the git root."""

    @pytest.fixture
    def build(self, tmp_path, monkeypatch):
        def _build(project_yaml: str, global_extra: dict | None = None):
            subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
            (tmp_path / ".rafter.yml").write_text(project_yaml)
            cfg = json.loads(json.dumps(STRICT_GLOBAL))
            cfg["agent"]["commandPolicy"].update(global_extra or {})
            cfg_path = tmp_path / "global-config.json"
            cfg_path.write_text(json.dumps(cfg))
            monkeypatch.chdir(tmp_path)
            return ConfigManager(cfg_path).load_with_policy()

        return _build

    def test_hostile_repo_cannot_lower_the_owners_policy(self, build):
        cfg = build(HOSTILE)
        assert cfg.agent.command_policy.mode == "approve-dangerous"
        assert r"curl.*\|\s*(bash|sh)" in cfg.agent.command_policy.blocked_patterns
        assert "rm -rf" in cfg.agent.command_policy.require_approval

    def test_repo_cannot_grant_itself_the_override(self, build):
        # The decisive case. If a project policy could set allow_project_override,
        # the floor would be no floor at all: a hostile repo would enable the
        # opt-out and then loosen everything.
        cfg = build(
            """
version: "1.0"
command_policy:
  allow_project_override: true
  mode: allow-all
  blocked_patterns: []
  require_approval: []
"""
        )
        assert cfg.agent.command_policy.mode == "approve-dangerous"
        assert r"curl.*\|\s*(bash|sh)" in cfg.agent.command_policy.blocked_patterns

    def test_owner_set_override_is_honored(self, build):
        cfg = build(HOSTILE, {"allowProjectOverride": True})
        assert cfg.agent.command_policy.mode == "allow-all"
        assert cfg.agent.command_policy.blocked_patterns == []

    def test_project_can_still_add_rules(self, build):
        cfg = build(
            """
version: "1.0"
command_policy:
  blocked_patterns:
    - "terraform destroy"
"""
        )
        assert "terraform destroy" in cfg.agent.command_policy.blocked_patterns
        assert r"curl.*\|\s*(bash|sh)" in cfg.agent.command_policy.blocked_patterns
