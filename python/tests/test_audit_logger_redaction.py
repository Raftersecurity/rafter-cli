"""Regression tests: audit logger must redact secrets before persisting commands."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from rafter_cli.core.audit_logger import AuditLogger


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def enabled_config():
    """Patch config to enable audit logging."""
    class _Audit:
        log_all_actions = True
        retention_days = 30

    class _Notifications:
        webhook = None
        min_risk_level = "high"

    class _Agent:
        audit = _Audit()
        notifications = _Notifications()

    class _Config:
        agent = _Agent()

    with patch("rafter_cli.core.config_manager.ConfigManager") as mgr:
        mgr.return_value.load.return_value = _Config()
        yield


def test_log_command_intercepted_redacts_github_token(audit_path, enabled_config):
    logger = AuditLogger(log_path=audit_path)
    token = "ghp_FAKE1234567890abcdefghijklmnopqrstuvwxyz"
    logger.log_command_intercepted(
        f"export GITHUB_TOKEN={token} && gh repo list",
        passed=True,
        action_taken="allowed",
    )
    on_disk = audit_path.read_text()
    assert token not in on_disk, "raw secret leaked into audit.jsonl"
    entry = json.loads(on_disk.strip())
    assert "ghp_" in entry["action"]["command"]
    assert "*" in entry["action"]["command"]
    assert entry["eventType"] == "command_intercepted"


def test_log_command_intercepted_preserves_risk_assessment(audit_path, enabled_config):
    logger = AuditLogger(log_path=audit_path)
    logger.log_command_intercepted("rm -rf /", passed=False, action_taken="blocked")
    entry = json.loads(audit_path.read_text().strip())
    # Risk level must still be assessed on the real command
    assert entry["action"]["riskLevel"] in ("critical", "high")


def test_log_auto_populates_cwd_and_git_repo(audit_path, enabled_config):
    logger = AuditLogger(log_path=audit_path)
    logger.log_command_intercepted("ls", passed=True, action_taken="allowed")
    entry = json.loads(audit_path.read_text().strip())
    import os
    assert entry["cwd"] == os.getcwd()
    # Running from inside the rafter-cli repo → gitRepo should be set
    assert entry.get("gitRepo"), "gitRepo should be auto-populated when run inside a git repo"


def test_read_filters_by_git_repo(audit_path, enabled_config):
    # Forge entries with different repo paths
    audit_path.write_text(
        "\n".join([
            json.dumps({"timestamp": "2026-01-01T00:00:00+00:00", "sessionId": "s1", "eventType": "command_intercepted", "gitRepo": "/home/alice/repo-a"}),
            json.dumps({"timestamp": "2026-01-01T00:00:00+00:00", "sessionId": "s2", "eventType": "command_intercepted", "gitRepo": "/home/alice/repo-b"}),
            json.dumps({"timestamp": "2026-01-01T00:00:00+00:00", "sessionId": "s3", "eventType": "command_intercepted", "gitRepo": "/home/bob/repo-a"}),
        ]) + "\n"
    )
    logger = AuditLogger(log_path=audit_path)
    assert len(logger.read(git_repo="repo-a")) == 2
    assert len(logger.read(git_repo="alice")) == 2
    assert len(logger.read(git_repo="nowhere")) == 0
