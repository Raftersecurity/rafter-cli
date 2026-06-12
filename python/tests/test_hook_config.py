"""Config-aware hook tests (sable-55u).

The pretool hook's staged-file scan and Write/Edit scan must honor the same
``.rafter.yml`` policy as ``rafter secrets`` — custom patterns, exclude_paths,
and ignore rules — so the hook and the CLI agree. Before sable-55u the hook ran
RegexScanner directly with no config and phantom-blocked commits on findings the
CLI would suppress.

Unlike ``test_hook_integration.py`` these tests must read a REAL ``.rafter.yml``,
so we isolate only the global ``~/.rafter`` config (patch ``ConfigManager.load``)
and leave ``load_with_policy`` real to merge the temp-repo policy on top.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from rafter_cli.commands.hook import (
    _evaluate_bash,
    _evaluate_write,
    _format_staged_secret_reason,
    _scan_staged_files,
)
from rafter_cli.core.config_schema import get_default_config
from rafter_cli.core.hook_control import resolve_hook_control

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(autouse=True)
def _default_global_config():
    """Isolate the developer's global ~/.rafter config; the temp .rafter.yml
    policy is still read for real by load_with_policy."""
    with patch(
        "rafter_cli.core.config_manager.ConfigManager.load",
        return_value=get_default_config(),
    ):
        yield


@pytest.fixture
def git_repo(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@rafter.dev"],
                   cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Rafter Test"],
                   cwd=tmp_path, capture_output=True, check=True)
    original_cwd = Path.cwd()
    os.chdir(tmp_path)
    try:
        yield tmp_path
    finally:
        os.chdir(original_cwd)


class TestStagedScanConfigAware:
    def test_exclude_paths_allows_commit(self, git_repo):
        (git_repo / "secrets.env").write_text(f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n")
        (git_repo / ".rafter.yml").write_text("scan:\n  exclude_paths:\n    - secrets.env\n")
        subprocess.run(["git", "add", "secrets.env", ".rafter.yml"],
                       cwd=git_repo, capture_output=True, check=True)

        result = _scan_staged_files()
        assert result["secrets_found"] is False
        assert result["files"] == 0

        # End-to-end: the commit is allowed, matching `rafter secrets`.
        control = resolve_hook_control(config=get_default_config(), env={})
        assert _evaluate_bash('git commit -m "add"', control)["decision"] == "allow"

    def test_ignore_rule_suppresses_pattern(self, git_repo):
        (git_repo / "fixtures.env").write_text(f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n")
        (git_repo / ".rafter.yml").write_text(
            "ignore:\n  - paths: ['fixtures.env']\n"
            "    rules: ['AWS Access Key ID']\n    reason: test fixture\n"
        )
        subprocess.run(["git", "add", "fixtures.env", ".rafter.yml"],
                       cwd=git_repo, capture_output=True, check=True)

        result = _scan_staged_files()
        assert result["secrets_found"] is False

    def test_uncovered_file_still_blocks(self, git_repo):
        (git_repo / "ignored.env").write_text(f"KEY={FAKE_AWS_KEY}\n")
        (git_repo / "real.env").write_text(f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n")
        (git_repo / ".rafter.yml").write_text("scan:\n  exclude_paths:\n    - ignored.env\n")
        subprocess.run(["git", "add", "ignored.env", "real.env", ".rafter.yml"],
                       cwd=git_repo, capture_output=True, check=True)

        result = _scan_staged_files()
        assert result["secrets_found"] is True
        assert result["files"] == 1
        assert "real.env" in result["findings"][0].file

    def test_deny_reason_names_file_and_pattern(self, git_repo):
        (git_repo / "leak.env").write_text(f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n")
        subprocess.run(["git", "add", "leak.env"], cwd=git_repo, capture_output=True, check=True)

        reason = _format_staged_secret_reason(_scan_staged_files())
        assert "leak.env" in reason
        assert "AWS Access Key ID" in reason
        assert "rafter secrets --staged" in reason


class TestWriteConfigAware:
    def test_write_to_excluded_path_allowed(self, git_repo):
        (git_repo / ".rafter.yml").write_text("scan:\n  exclude_paths:\n    - generated/secrets.ts\n")
        result = _evaluate_write({
            "content": f"export const KEY = 'AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}';\n",
            "file_path": "generated/secrets.ts",
        })
        assert result["decision"] == "allow"

    def test_write_to_normal_path_blocked(self, git_repo):
        result = _evaluate_write({
            "content": f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n",
            "file_path": "src/config.ts",
        })
        assert result["decision"] == "deny"
        assert "src/config.ts" in result["reason"]
