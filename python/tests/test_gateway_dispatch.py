"""Python parity tests for the Hermes gateway-dispatch hook."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from rafter_cli.core.config_schema import get_default_config


@pytest.fixture(autouse=True)
def _use_default_config():
    with patch("rafter_cli.core.config_manager.ConfigManager.load", return_value=get_default_config()), \
         patch("rafter_cli.core.config_manager.ConfigManager.load_with_policy", return_value=get_default_config()):
        yield


def _run_hook(event: dict | None, cwd: Path, env_extra: dict | None = None):
    args = [sys.executable, "-m", "rafter_cli", "hook", "gateway-dispatch"]
    env = {**os.environ, **(env_extra or {})}
    payload = json.dumps({"event": event, "cwd": str(cwd)}) if event is not None else "{}"
    proc = subprocess.run(args, input=payload, capture_output=True, text=True, timeout=15, env=env)
    try:
        out = json.loads(proc.stdout.strip()) if proc.stdout.strip() else None
    except json.JSONDecodeError:
        out = None
    return proc, out


class TestGatewayDispatchHook:
    def test_no_secrets_returns_allow(self, tmp_path: Path):
        proc, out = _run_hook({"text": "Hey can you summarize my last commit", "channel": "telegram"}, tmp_path)
        assert proc.returncode == 0
        assert out == {"action": "allow"}
        assert not (tmp_path / ".env").exists()

    def test_rewrites_when_secret_present(self, tmp_path: Path):
        proc, out = _run_hook(
            {"text": "Hermes please connect with DB_PASSWORD=hunter2andmore now", "channel": "telegram"},
            tmp_path,
        )
        assert proc.returncode == 0
        assert out["action"] == "rewrite"
        assert "hunter2andmore" not in out["text"]
        assert "$DB_PASSWORD" in out["text"]
        assert "DB_PASSWORD=hunter2andmore" in (tmp_path / ".env").read_text()
        assert ".env" in (tmp_path / ".gitignore").read_text()

    def test_kill_switch_returns_allow(self, tmp_path: Path):
        proc, out = _run_hook(
            {"text": "DB_PASSWORD=letmein123"},
            tmp_path,
            env_extra={"RAFTER_PROMPT_SHIELD": "0"},
        )
        assert out == {"action": "allow"}
        assert not (tmp_path / ".env").exists()

    def test_malformed_json_returns_allow(self, tmp_path: Path):
        proc = subprocess.run(
            [sys.executable, "-m", "rafter_cli", "hook", "gateway-dispatch"],
            input="not json", capture_output=True, text=True, timeout=15,
        )
        out = json.loads(proc.stdout.strip())
        assert out == {"action": "allow"}

    def test_missing_event_text_returns_allow(self, tmp_path: Path):
        proc, out = _run_hook({"channel": "telegram"}, tmp_path)
        assert out == {"action": "allow"}

    def test_non_string_text_returns_allow(self, tmp_path: Path):
        proc, out = _run_hook({"text": 12345}, tmp_path)
        assert out == {"action": "allow"}
