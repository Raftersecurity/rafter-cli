"""TDD tests for the Gemini before-model hook (Python parity)."""
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


def _run_hook(llm_request: dict, cwd: Path, env_extra: dict | None = None):
    args = [sys.executable, "-m", "rafter_cli", "hook", "before-model"]
    env = {**os.environ, **(env_extra or {})}
    payload = json.dumps({
        "session_id": "test",
        "hook_event_name": "BeforeModel",
        "cwd": str(cwd),
        "llm_request": llm_request,
    })
    proc = subprocess.run(args, input=payload, capture_output=True, text=True, timeout=15, env=env)
    try:
        out = json.loads(proc.stdout.strip()) if proc.stdout.strip() else None
    except json.JSONDecodeError:
        out = None
    return proc, out


class TestBeforeModelHook:
    def test_no_secrets_returns_noop_envelope(self, tmp_path: Path):
        proc, out = _run_hook(
            {"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": "Refactor foo.py"}]},
            tmp_path,
        )
        assert proc.returncode == 0
        assert out == {"hookSpecificOutput": {"hookEventName": "BeforeModel"}}
        assert not (tmp_path / ".env").exists()

    def test_rewrites_user_message_when_secret_detected(self, tmp_path: Path):
        proc, out = _run_hook(
            {
                "model": "gemini-2.0-flash",
                "messages": [
                    {"role": "system", "content": "You are a coding agent."},
                    {"role": "user", "content": "Connect with DB_PASSWORD=hunter2andmore"},
                ],
            },
            tmp_path,
        )
        assert proc.returncode == 0
        assert out["hookSpecificOutput"]["hookEventName"] == "BeforeModel"

        overridden = out["hookSpecificOutput"].get("llm_request")
        assert overridden, "must return llm_request override"
        msgs = overridden["messages"]
        assert len(msgs) == 2
        assert msgs[0] == {"role": "system", "content": "You are a coding agent."}

        rewritten = msgs[1]
        assert rewritten["role"] == "user"
        assert "hunter2andmore" not in rewritten["content"]
        assert "$DB_PASSWORD" in rewritten["content"]

        env_text = (tmp_path / ".env").read_text()
        assert "DB_PASSWORD=hunter2andmore" in env_text
        assert ".env" in (tmp_path / ".gitignore").read_text()

    def test_skips_non_user_roles(self, tmp_path: Path):
        proc, out = _run_hook(
            {
                "model": "gemini-2.0-flash",
                "messages": [
                    {"role": "model", "content": "Earlier you said password=abc123def"},
                    {"role": "user", "content": "no secrets in this turn"},
                ],
            },
            tmp_path,
        )
        assert proc.returncode == 0
        # Only user-role messages are scanned.
        assert "llm_request" not in out["hookSpecificOutput"]

    def test_handles_parts_array_content(self, tmp_path: Path):
        proc, out = _run_hook(
            {
                "model": "gemini-2.0-flash",
                "messages": [{
                    "role": "user",
                    "content": [{"type": "text", "text": "Use api_key=sk_test_secretvalue1234"}],
                }],
            },
            tmp_path,
        )
        assert proc.returncode == 0
        overridden = out["hookSpecificOutput"].get("llm_request")
        assert overridden, "must return override for parts-array content"
        part_text = overridden["messages"][0]["content"][0]["text"]
        assert "sk_test_secretvalue1234" not in part_text
        assert "$" in part_text

    def test_kill_switch(self, tmp_path: Path):
        proc, out = _run_hook(
            {"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": "DB_PASSWORD=letmein123"}]},
            tmp_path,
            env_extra={"RAFTER_PROMPT_SHIELD": "0"},
        )
        assert "llm_request" not in out["hookSpecificOutput"]
        assert not (tmp_path / ".env").exists()

    def test_malformed_json_fails_open(self, tmp_path: Path):
        proc = subprocess.run(
            [sys.executable, "-m", "rafter_cli", "hook", "before-model"],
            input="not json", capture_output=True, text=True, timeout=15,
        )
        out = json.loads(proc.stdout.strip())
        assert out == {"hookSpecificOutput": {"hookEventName": "BeforeModel"}}

    def test_missing_llm_request_fails_open(self, tmp_path: Path):
        proc, out = _run_hook(
            llm_request=None,  # type: ignore
            cwd=tmp_path,
        )
        # Even with None, hook must emit a valid noop envelope.
        assert out == {"hookSpecificOutput": {"hookEventName": "BeforeModel"}}
