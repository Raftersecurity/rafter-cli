"""Tests for the prompt-shield user-prompt-submit hook + env-writer."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from rafter_cli.commands.hook import _detect_secrets
from rafter_cli.core.config_schema import get_default_config
from rafter_cli.core.env_writer import (
    SecretToPersist,
    ensure_gitignored,
    persist_secrets,
)


@pytest.fixture(autouse=True)
def _use_default_config():
    with patch("rafter_cli.core.config_manager.ConfigManager.load", return_value=get_default_config()), \
         patch("rafter_cli.core.config_manager.ConfigManager.load_with_policy", return_value=get_default_config()):
        yield


# ────────────────────────── env_writer ──────────────────────────

class TestEnvWriter:
    def test_creates_env_and_gitignore_on_first_call(self, tmp_path: Path):
        result = persist_secrets(
            [SecretToPersist(base_name="DB_PASSWORD", value="hunter2andmore")],
            tmp_path,
        )
        assert result.env_file_created is True
        assert result.gitignore_created is True
        assert result.gitignore_updated is True
        assert len(result.written) == 1
        assert result.written[0].name == "DB_PASSWORD"
        assert result.written[0].already_present is False
        env_content = (tmp_path / ".env").read_text()
        assert "DB_PASSWORD=hunter2andmore" in env_content
        assert ".env" in (tmp_path / ".gitignore").read_text()

    def test_reuses_existing_entry_for_same_value(self, tmp_path: Path):
        (tmp_path / ".env").write_text("EXISTING_KEY=hunter2\n")
        (tmp_path / ".gitignore").write_text(".env\n")

        result = persist_secrets(
            [SecretToPersist(base_name="DB_PASSWORD", value="hunter2")],
            tmp_path,
        )
        assert result.written[0].name == "EXISTING_KEY"
        assert result.written[0].already_present is True
        assert result.env_file_created is False
        assert result.gitignore_updated is False
        assert (tmp_path / ".env").read_text() == "EXISTING_KEY=hunter2\n"

    def test_suffixes_name_on_collision(self, tmp_path: Path):
        (tmp_path / ".env").write_text("DB_PASSWORD=existing\n")
        result = persist_secrets(
            [SecretToPersist(base_name="DB_PASSWORD", value="different-value")],
            tmp_path,
        )
        assert result.written[0].name == "DB_PASSWORD_1"
        assert "DB_PASSWORD_1=different-value" in (tmp_path / ".env").read_text()

    def test_quotes_values_with_special_chars(self, tmp_path: Path):
        result = persist_secrets(
            [SecretToPersist(base_name="FUNKY", value="has spaces")],
            tmp_path,
        )
        assert 'FUNKY="has spaces"' in (tmp_path / ".env").read_text()

    def test_does_not_duplicate_same_value_in_one_call(self, tmp_path: Path):
        result = persist_secrets(
            [
                SecretToPersist(base_name="FOO", value="samevalue"),
                SecretToPersist(base_name="BAR", value="samevalue"),
            ],
            tmp_path,
        )
        assert len(result.written) == 2
        assert result.written[0].name == "FOO"
        assert result.written[0].already_present is False
        assert result.written[1].name == "FOO"
        assert result.written[1].already_present is True
        content = (tmp_path / ".env").read_text()
        assert content.count("FOO=") == 1

    def test_sanitizes_invalid_characters_in_basename(self, tmp_path: Path):
        result = persist_secrets(
            [SecretToPersist(base_name="weird.name with-stuff!", value="abc123def")],
            tmp_path,
        )
        assert result.written[0].name == "WEIRD_NAME_WITH_STUFF"


class TestEnsureGitignored:
    def test_creates_if_missing(self, tmp_path: Path):
        gi = tmp_path / ".gitignore"
        created, updated = ensure_gitignored(gi, ".env")
        assert (created, updated) == (True, True)
        assert gi.read_text() == ".env\n"

    def test_appends_if_not_covered(self, tmp_path: Path):
        gi = tmp_path / ".gitignore"
        gi.write_text("node_modules/\ndist/\n")
        created, updated = ensure_gitignored(gi, ".env")
        assert (created, updated) == (False, True)
        assert ".env" in gi.read_text()

    def test_noop_if_already_present(self, tmp_path: Path):
        gi = tmp_path / ".gitignore"
        gi.write_text(".env\nnode_modules/\n")
        created, updated = ensure_gitignored(gi, ".env")
        assert (created, updated) == (False, False)

    def test_treats_leading_slash_as_covered(self, tmp_path: Path):
        gi = tmp_path / ".gitignore"
        gi.write_text("/.env\n")
        _, updated = ensure_gitignored(gi, ".env")
        assert updated is False


# ────────────────────────── detection ──────────────────────────

class TestDetectSecrets:
    def test_no_secrets_returns_empty(self):
        assert _detect_secrets("Refactor the function in foo.ts") == []

    def test_assignment_form_with_prefix(self):
        out = _detect_secrets("Connect with DB_PASSWORD=hunter2andmore please")
        assert len(out) == 1
        assert out[0]["env_base_name"] == "DB_PASSWORD"
        assert out[0]["value"] == "hunter2andmore"

    def test_phrase_form(self):
        # Construct fake-stripe-shaped key from parts so the test source isn't
        # itself flagged by secret-scanners.
        fake_key = "sk_" + "live_" + "abcdefghijklmnop"
        out = _detect_secrets(f"the api key is {fake_key} and please use it")
        # may match both phrase and Stripe pattern; at least one detected.
        assert len(out) >= 1
        assert any(d["value"].startswith("sk_") for d in out)

    def test_url_credentials(self):
        out = _detect_secrets("connect to postgres://user:correctsecret@host:5432/db")
        # Default DB connection-string pattern + URL-with-credentials may both match.
        assert len(out) >= 1
        assert any("correctsecret" in d["value"] for d in out)

    def test_skips_obvious_placeholder(self):
        out = _detect_secrets("Set api_key=<your-key-here> in your config")
        assert out == []

    def test_skips_non_credential_assignment(self):
        # "size" is not a credential keyword → assignment pattern skips it.
        # (Generic Secret pattern requires both digit + letter inside quotes,
        #  so an unquoted "size=200x200" also won't match.)
        out = _detect_secrets("set size=200x200pixels")
        assert out == []


# ────────────────────────── e2e via subprocess ──────────────────────────

def _run_hook(prompt: str, cwd: Path, mode: str | None = None, env_extra: dict | None = None):
    args = [sys.executable, "-m", "rafter_cli", "hook", "user-prompt-submit"]
    if mode:
        args.extend(["--mode", mode])
    import os as _os
    env = {**_os.environ, **(env_extra or {})}
    payload = json.dumps({
        "session_id": "test",
        "hook_event_name": "UserPromptSubmit",
        "cwd": str(cwd),
        "prompt": prompt,
    })
    proc = subprocess.run(args, input=payload, capture_output=True, text=True, timeout=15, env=env)
    try:
        out_json = json.loads(proc.stdout.strip()) if proc.stdout.strip() else None
    except json.JSONDecodeError:
        out_json = None
    return proc, out_json


class TestE2E:
    def test_no_secrets_emits_noop_envelope(self, tmp_path: Path):
        proc, out = _run_hook("Refactor foo.ts to use async", tmp_path)
        assert proc.returncode == 0
        assert out == {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}
        assert not (tmp_path / ".env").exists()

    def test_detects_writes_env_and_gitignore(self, tmp_path: Path):
        proc, out = _run_hook("Connect with DB_PASSWORD=hunter2andmore", tmp_path)
        assert proc.returncode == 0
        assert out is not None
        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert "Rafter prompt-shield" in ctx
        assert "DB_PASSWORD" in ctx
        env_text = (tmp_path / ".env").read_text()
        assert "DB_PASSWORD=hunter2andmore" in env_text
        gi_text = (tmp_path / ".gitignore").read_text()
        assert ".env" in gi_text

    def test_block_mode(self, tmp_path: Path):
        fake_key = "sk_" + "live_" + "a" * 24
        proc, out = _run_hook(
            f"Use api_key={fake_key} for stripe",
            tmp_path,
            mode="block",
        )
        assert out is not None
        assert out.get("decision") == "block"
        assert "Re-submit" in out.get("reason", "")

    def test_kill_switch(self, tmp_path: Path):
        proc, out = _run_hook(
            "Connect with password=letmein123",
            tmp_path,
            env_extra={"RAFTER_PROMPT_SHIELD": "0"},
        )
        assert out == {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}
        assert not (tmp_path / ".env").exists()

    def test_malformed_json_fails_open(self, tmp_path: Path):
        proc = subprocess.run(
            [sys.executable, "-m", "rafter_cli", "hook", "user-prompt-submit"],
            input="not json",
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode == 0
        out = json.loads(proc.stdout.strip())
        assert out == {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}
