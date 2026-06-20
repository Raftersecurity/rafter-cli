"""Hardening for sable-q9to: the API key is never stored world-readable, never
echoed in cleartext, and backend.api_key is a real (lowest-precedence) source.
Parity with the Node config-secret-handling tests."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from rafter_cli.core.config_manager import (
    ConfigManager,
    is_secret_config_key,
    mask_secret_value,
    redact_config_secrets,
)
from rafter_cli.utils.api import resolve_key


class TestRedactionHelpers:
    def test_masks_credential_keys_only_and_does_not_mutate(self):
        cfg = {
            "backend": {"api_key": "sk-secret-7777777"},
            "agent": {"risk_level": "moderate"},
            "token": "tok-abcdef",
            "nested": {"authToken": "zzzz9999", "note": "plain"},
            "list": [{"password": "hunter2xx"}],
        }
        r = redact_config_secrets(cfg)
        assert r["backend"]["api_key"] == "sk-s****"
        assert r["token"] == "tok-****"
        assert r["nested"]["authToken"] == "zzzz****"
        assert r["nested"]["note"] == "plain"
        assert r["agent"]["risk_level"] == "moderate"
        assert r["list"][0]["password"] == "hunt****"
        assert cfg["backend"]["api_key"] == "sk-secret-7777777"  # untouched

    def test_mask_secret_value_edges(self):
        assert mask_secret_value("") == "****"
        assert mask_secret_value("abcd") == "****"
        assert mask_secret_value("abcde") == "abcd****"
        assert mask_secret_value(None) == "****"
        assert mask_secret_value(12345) == "****"

    def test_is_secret_config_key(self):
        for k in ["apiKey", "api_key", "apikey", "token", "authToken", "secret", "password", "credential"]:
            assert is_secret_config_key(k) is True
        for k in ["risk_level", "mode", "name", "url", "version"]:
            assert is_secret_config_key(k) is False


class TestSavePerms:
    def test_fresh_config_is_owner_only(self, tmp_path):
        p = tmp_path / "config.json"
        ConfigManager(p).set("backend.api_key", "sk-xyz")
        assert stat.S_IMODE(p.stat().st_mode) == 0o600

    def test_existing_world_readable_config_is_tightened(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text("{}")
        p.chmod(0o644)
        ConfigManager(p).set("agent.risk_level", "minimal")
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


class TestResolveKeyPrecedence:
    """--api-key > RAFTER_API_KEY > global config backend.api_key."""

    @pytest.fixture
    def home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("RAFTER_API_KEY", raising=False)
        # Hand-write the config under the temp HOME (never a default-path
        # ConfigManager write) so the real ~/.rafter is never touched.
        d = tmp_path / ".rafter"
        d.mkdir(parents=True, exist_ok=True)
        (d / "config.json").write_text(json.dumps({"backend": {"api_key": "CONFIG-key"}}))
        return tmp_path

    def test_flag_wins(self, home, monkeypatch):
        monkeypatch.setenv("RAFTER_API_KEY", "ENV-key")
        assert resolve_key("FLAG-key") == "FLAG-key"

    def test_env_over_config(self, home, monkeypatch):
        monkeypatch.setenv("RAFTER_API_KEY", "ENV-key")
        assert resolve_key(None) == "ENV-key"

    def test_global_config_used_when_no_flag_or_env(self, home):
        # No longer a dead path.
        assert resolve_key(None) == "CONFIG-key"
