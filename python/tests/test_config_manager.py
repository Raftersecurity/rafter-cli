"""Tests for config manager."""
import json
from pathlib import Path

import pytest

from rafter_cli.core.config_manager import ConfigManager
from rafter_cli.core.config_schema import RafterConfig, get_default_config


@pytest.fixture
def cfg_path(tmp_path):
    return tmp_path / ".rafter" / "config.json"


@pytest.fixture
def manager(cfg_path):
    return ConfigManager(config_path=cfg_path)


def test_load_returns_default_when_no_file(manager):
    cfg = manager.load()
    assert isinstance(cfg, RafterConfig)
    assert cfg.version == "1.0.0"
    assert cfg.agent.risk_level == "moderate"


def test_save_and_load(manager, cfg_path):
    cfg = get_default_config()
    cfg.agent.risk_level = "aggressive"
    manager.save(cfg)

    assert cfg_path.exists()
    loaded = manager.load()
    assert loaded.agent.risk_level == "aggressive"


def test_get_dot_path(manager):
    manager.save(get_default_config())
    assert manager.get("agent.risk_level") == "moderate"
    assert manager.get("agent.audit.retention_days") == 30
    assert manager.get("nonexistent.key") is None


def test_set_dot_path(manager):
    manager.save(get_default_config())
    manager.set("agent.risk_level", "minimal")
    assert manager.get("agent.risk_level") == "minimal"


def test_update_merges(manager):
    manager.save(get_default_config())
    manager.update({"agent": {"risk_level": "aggressive"}})
    loaded = manager.load()
    assert loaded.agent.risk_level == "aggressive"
    # Other fields preserved
    assert loaded.agent.audit.retention_days == 30


def test_initialize(manager, cfg_path, monkeypatch):
    # Patch get_rafter_dir in the config_manager module (where it's imported)
    monkeypatch.setattr("rafter_cli.core.config_manager.get_rafter_dir", lambda: cfg_path.parent)
    manager.initialize()
    assert cfg_path.exists()
    assert (cfg_path.parent / "bin").exists()
    assert (cfg_path.parent / "patterns").exists()


def test_exists(manager, cfg_path):
    assert not manager.exists()
    manager.save(get_default_config())
    assert manager.exists()


def test_load_with_policy_no_policy(manager):
    manager.save(get_default_config())
    # No .rafter.yml in cwd, should just return config
    cfg = manager.load_with_policy()
    assert cfg.agent.risk_level == "moderate"


def test_load_with_policy_merges(manager, tmp_path, monkeypatch):
    manager.save(get_default_config())

    # Create a .rafter.yml in tmp_path
    policy = tmp_path / ".rafter.yml"
    policy.write_text("risk_level: aggressive\nscan:\n  exclude_paths:\n    - vendor\n")

    monkeypatch.chdir(tmp_path)

    cfg = manager.load_with_policy()
    assert cfg.agent.risk_level == "aggressive"
    assert "vendor" in cfg.agent.scan.exclude_paths


def test_migrate_old_curl_sh_pattern(manager, cfg_path):
    """Old broad curl.*|.*sh pattern must be upgraded on load."""
    # Write a config with the old, overly broad patterns (as an older rafter would have)
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    old_data = {
        "version": "1.0.0",
        "initialized": "2026-01-01T00:00:00Z",
        "backend": {"endpoint": "https://rafter.so/api/"},
        "agent": {
            "riskLevel": "moderate",
            "commandPolicy": {
                "mode": "approve-dangerous",
                "blockedPatterns": [],
                "requireApproval": [
                    "rm -rf",
                    "sudo rm",
                    r"curl.*\|.*sh",
                    r"wget.*\|.*sh",
                    "chmod 777",
                ],
            },
            "outputFiltering": {"redactSecrets": True, "blockPatterns": True},
            "audit": {"logAllActions": True, "retentionDays": 30, "logLevel": "info"},
            "notifications": {},
        },
    }
    cfg_path.write_text(json.dumps(old_data))

    loaded = manager.load()
    patterns = loaded.agent.command_policy.require_approval

    assert r"curl.*\|\s*(bash|sh|zsh|dash)\b" in patterns
    assert r"wget.*\|\s*(bash|sh|zsh|dash)\b" in patterns
    assert r"curl.*\|.*sh" not in patterns
    assert r"wget.*\|.*sh" not in patterns
    # Unrelated patterns preserved
    assert "rm -rf" in patterns
    assert "chmod 777" in patterns


def test_migrate_does_not_change_precise_patterns(manager):
    """Configs already using precise patterns are not modified."""
    cfg = get_default_config()
    manager.save(cfg)
    original = list(cfg.agent.command_policy.require_approval)

    loaded = manager.load()
    assert loaded.agent.command_policy.require_approval == original
