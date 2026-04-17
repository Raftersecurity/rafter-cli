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


def test_verify_returns_no_breaks_on_pristine_chain(audit_path, enabled_config):
    logger = AuditLogger(log_path=audit_path)
    for _ in range(3):
        logger.log_command_intercepted("ls", passed=True, action_taken="allowed")
    assert logger.verify() == []


def test_verify_detects_edited_entry(audit_path, enabled_config):
    logger = AuditLogger(log_path=audit_path)
    logger.log_command_intercepted("echo 1", passed=True, action_taken="allowed")
    logger.log_command_intercepted("echo 2", passed=True, action_taken="allowed")
    logger.log_command_intercepted("echo 3", passed=True, action_taken="allowed")
    tampered = audit_path.read_text().replace("echo 2", "echo EVIL")
    audit_path.write_text(tampered)
    breaks = logger.verify()
    assert len(breaks) > 0
    assert breaks[0]["line"] == 3  # line 3's prevHash no longer matches tampered line 2


def test_verify_detects_deleted_entry(audit_path, enabled_config):
    logger = AuditLogger(log_path=audit_path)
    logger.log_command_intercepted("echo 1", passed=True, action_taken="allowed")
    logger.log_command_intercepted("echo 2", passed=True, action_taken="allowed")
    logger.log_command_intercepted("echo 3", passed=True, action_taken="allowed")
    lines = [l for l in audit_path.read_text().split("\n") if l]
    audit_path.write_text(lines[0] + "\n" + lines[2] + "\n")
    assert len(logger.verify()) > 0


def test_cleanup_reseals_hash_chain(audit_path, enabled_config, tmp_path):
    from datetime import datetime, timedelta, timezone
    logger = AuditLogger(log_path=audit_path)
    logger.log_command_intercepted("echo a", passed=True, action_taken="allowed")
    logger.log_command_intercepted("echo b", passed=True, action_taken="allowed")
    logger.log_command_intercepted("echo c", passed=True, action_taken="allowed")
    logger.log_command_intercepted("echo d", passed=True, action_taken="allowed")

    # Age first two entries so they fall outside retention.
    lines = [l for l in audit_path.read_text().split("\n") if l.strip()]
    entries = [json.loads(l) for l in lines]
    old_ts = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    entries[0]["timestamp"] = old_ts
    entries[1]["timestamp"] = old_ts
    audit_path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")

    logger.cleanup(retention_days=7)

    remaining = logger.read()
    assert len(remaining) == 2
    # Chain must verify clean after cleanup re-seals it.
    assert logger.verify() == []

    sidecar = audit_path.parent / (audit_path.name + ".retention.log")
    assert sidecar.exists()
    note = json.loads(sidecar.read_text().strip())
    assert note["prunedCount"] == 2
    assert note["retainedCount"] == 2


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
