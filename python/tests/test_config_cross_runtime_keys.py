"""A config written by the Node CLI must be readable here.

Node writes camelCase (``logAllActions``, ``commandPolicy``, ``riskLevel``);
this implementation writes and reads snake_case. Python has tolerated both
spellings since it shipped (``ConfigManager._pick_fields`` maps camelCase to
snake_case on load) — but nothing pinned it, and the Node side had no mirror at
all: a Python-written config made every Node audit write a silent no-op
(sable-2t0w). This is the Python half of that pair, so neither direction can
regress unnoticed.

Mirrors node/tests/config-snake-case.test.ts.
"""
from __future__ import annotations

import json

from rafter_cli.core.audit_logger import AuditLogger
from rafter_cli.core.config_manager import ConfigManager


def node_written_config() -> dict:
    """A config in exactly the shape `rafter agent init` writes under Node."""
    return {
        "version": "1.0.0",
        "initialized": "2026-08-11T00:00:00.000Z",
        "agent": {
            "riskLevel": "aggressive",
            "audit": {"logAllActions": True, "retentionDays": 30, "logLevel": "info"},
            "commandPolicy": {
                "mode": "deny-list",
                "blockedPatterns": ["never-run-me"],
                "requireApproval": ["ask-me-first"],
            },
            "scan": {"excludePaths": ["vendor/"], "autoUpdateBetterleaks": False},
        },
    }


def _write(tmp_path, config: dict):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return path


def test_load_reads_camel_case_policy_and_audit(tmp_path):
    cfg = ConfigManager(_write(tmp_path, node_written_config())).load()

    assert cfg.agent.risk_level == "aggressive"
    assert cfg.agent.audit.log_all_actions is True
    assert cfg.agent.audit.retention_days == 30
    assert cfg.agent.command_policy.mode == "deny-list"
    assert cfg.agent.command_policy.blocked_patterns == ["never-run-me"]
    assert cfg.agent.command_policy.require_approval == ["ask-me-first"]
    assert cfg.agent.scan.exclude_paths == ["vendor/"]


def test_audit_logger_writes_under_a_node_written_config(tmp_path):
    config_path = _write(tmp_path, node_written_config())
    log_path = tmp_path / "audit.jsonl"

    AuditLogger(log_path, config_manager=ConfigManager(config_path)).log(
        {
            "eventType": "command_intercepted",
            "action": {"command": "echo hi", "riskLevel": "low"},
            "securityCheck": {"passed": True},
            "resolution": {"actionTaken": "allowed"},
        }
    )

    assert log_path.exists()
    lines = log_path.read_text().strip().split("\n")
    assert len(lines) == 1
    assert json.loads(lines[0])["action"]["command"] == "echo hi"


def test_audit_logger_still_honors_log_all_actions_false(tmp_path):
    config = node_written_config()
    config["agent"]["audit"]["logAllActions"] = False
    config_path = _write(tmp_path, config)
    log_path = tmp_path / "audit.jsonl"

    AuditLogger(log_path, config_manager=ConfigManager(config_path)).log(
        {
            "eventType": "command_intercepted",
            "action": {"command": "echo hi", "riskLevel": "low"},
            "securityCheck": {"passed": True},
            "resolution": {"actionTaken": "allowed"},
        }
    )

    assert not log_path.exists()
