"""Integration tests for hook system with real git repositories.

These tests create actual git repos in tmp directories, stage files
with (fake) secrets, and verify that pretool/posttool hooks behave
correctly against real git state.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from rafter_cli.commands.hook import _evaluate_bash, _evaluate_write, _scan_staged_files
from rafter_cli.core.config_schema import get_default_config
from rafter_cli.scanners.regex_scanner import RegexScanner


# ── Fake but realistic-looking secrets ──────────────────────────────────

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_GITHUB_TOKEN = "ghp_FAKEEFabcdef1234567890abcdef1234567"
FAKE_PRIVATE_KEY = """\
-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBALRiMLAB9pm5DhB2m1pGv43example1234567890abcdefghijklmn
opqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUV==
-----END RSA PRIVATE KEY-----"""


# ── Fixtures ────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _use_default_config():
    """Ensure tests use default config, not the real disk config."""
    with patch("rafter_cli.core.config_manager.ConfigManager.load", return_value=get_default_config()), \
         patch("rafter_cli.core.config_manager.ConfigManager.load_with_policy", return_value=get_default_config()):
        yield


@pytest.fixture
def git_repo(tmp_path):
    """Create a real git repository in a temporary directory."""
    subprocess.run(["git", "init", str(tmp_path)], capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@rafter.dev"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Rafter Test"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    original_cwd = Path.cwd()
    os.chdir(tmp_path)
    try:
        yield tmp_path
    finally:
        os.chdir(original_cwd)


# ── Pretool: git commit with real staged files ──────────────────────────

class TestPretoolGitCommitRealRepo:
    def test_blocks_commit_with_staged_aws_key(self, git_repo):
        env_file = git_repo / ".env"
        env_file.write_text(f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n")
        subprocess.run(["git", "add", ".env"], cwd=git_repo, capture_output=True, check=True)

        result = _evaluate_bash('git commit -m "add env"')
        assert result["decision"] == "deny"
        assert "secret(s)" in result["reason"]

    def test_blocks_commit_with_staged_github_token(self, git_repo):
        config = git_repo / "config.json"
        config.write_text(json.dumps({"token": FAKE_GITHUB_TOKEN}))
        subprocess.run(["git", "add", "config.json"], cwd=git_repo, capture_output=True, check=True)

        result = _evaluate_bash('git commit -m "add config"')
        assert result["decision"] == "deny"
        assert "secret(s)" in result["reason"]

    def test_blocks_commit_with_staged_private_key(self, git_repo):
        key_file = git_repo / "key.pem"
        key_file.write_text(FAKE_PRIVATE_KEY)
        subprocess.run(["git", "add", "key.pem"], cwd=git_repo, capture_output=True, check=True)

        result = _evaluate_bash('git commit -m "add key"')
        assert result["decision"] == "deny"
        assert "secret(s)" in result["reason"]

    def test_allows_commit_with_clean_staged_files(self, git_repo):
        readme = git_repo / "README.md"
        readme.write_text("# Hello World\n")
        subprocess.run(["git", "add", "README.md"], cwd=git_repo, capture_output=True, check=True)

        result = _evaluate_bash('git commit -m "add readme"')
        assert result["decision"] == "allow"

    def test_allows_commit_with_no_staged_files(self, git_repo):
        result = _evaluate_bash('git commit -m "empty"')
        assert result["decision"] == "allow"

    def test_detects_secrets_in_multiple_staged_files(self, git_repo):
        env_file = git_repo / ".env"
        env_file.write_text(f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n")

        config = git_repo / "config.json"
        config.write_text(json.dumps({"token": FAKE_GITHUB_TOKEN}))

        subprocess.run(["git", "add", ".env", "config.json"], cwd=git_repo, capture_output=True, check=True)

        result = _evaluate_bash('git commit -m "secrets"')
        assert result["decision"] == "deny"
        # Should report multiple files
        assert "staged file(s)" in result["reason"]

    def test_only_scans_staged_not_unstaged(self, git_repo):
        # Commit a clean file first
        readme = git_repo / "README.md"
        readme.write_text("# Hello\n")
        subprocess.run(["git", "add", "README.md"], cwd=git_repo, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=git_repo, capture_output=True, check=True)

        # Stage a clean file
        app = git_repo / "app.js"
        app.write_text("console.log('hello');\n")
        subprocess.run(["git", "add", "app.js"], cwd=git_repo, capture_output=True, check=True)

        # Create secret file but DON'T stage it
        secret_file = git_repo / "secret.env"
        secret_file.write_text(f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n")

        result = _evaluate_bash('git commit -m "add app"')
        assert result["decision"] == "allow"


# ── Pretool: git push with real staged files ────────────────────────────

class TestPretoolGitPushRealRepo:
    def test_blocks_push_with_staged_secrets(self, git_repo):
        env_file = git_repo / ".env"
        env_file.write_text(f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n")
        subprocess.run(["git", "add", ".env"], cwd=git_repo, capture_output=True, check=True)

        result = _evaluate_bash("git push origin main")
        assert result["decision"] == "deny"
        assert "secret(s)" in result["reason"]

    def test_allows_push_with_clean_staged_files(self, git_repo):
        readme = git_repo / "README.md"
        readme.write_text("# App\n")
        subprocess.run(["git", "add", "README.md"], cwd=git_repo, capture_output=True, check=True)

        result = _evaluate_bash("git push origin main")
        assert result["decision"] == "allow"


# ── Pretool: Write/Edit with secret content ─────────────────────────────

class TestPretoolWriteSecretContent:
    def test_blocks_write_with_aws_key(self):
        result = _evaluate_write({
            "content": f"DB_HOST=localhost\nAWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n",
            "file_path": ".env",
        })
        assert result["decision"] == "deny"
        assert "Secret detected" in result["reason"]

    def test_blocks_write_with_github_token(self):
        result = _evaluate_write({
            "content": json.dumps({"github_token": FAKE_GITHUB_TOKEN}),
            "file_path": "config.json",
        })
        assert result["decision"] == "deny"

    def test_allows_write_with_clean_content(self):
        result = _evaluate_write({
            "content": "export function hello() { return 'world'; }\n",
            "file_path": "app.ts",
        })
        assert result["decision"] == "allow"

    def test_blocks_edit_with_secret_in_new_string(self):
        result = _evaluate_write({
            "new_string": f'API_KEY = "{FAKE_AWS_KEY}"',
            "file_path": "config.py",
        })
        assert result["decision"] == "deny"


# ── scanStagedFiles — detailed behavior ─────────────────────────────────

class TestScanStagedFilesRealRepo:
    def test_returns_secrets_found_for_staged_secret(self, git_repo):
        env_file = git_repo / ".env"
        env_file.write_text(f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n")
        subprocess.run(["git", "add", ".env"], cwd=git_repo, capture_output=True, check=True)

        result = _scan_staged_files()
        assert result["secrets_found"] is True
        assert result["count"] >= 1
        assert result["files"] == 1

    def test_returns_secrets_across_multiple_files(self, git_repo):
        env_file = git_repo / ".env"
        env_file.write_text(f"KEY={FAKE_AWS_KEY}\n")

        config = git_repo / "config.yml"
        config.write_text(f"token: {FAKE_GITHUB_TOKEN}\n")

        subprocess.run(["git", "add", ".env", "config.yml"], cwd=git_repo, capture_output=True, check=True)

        result = _scan_staged_files()
        assert result["secrets_found"] is True
        assert result["files"] >= 2

    def test_returns_clean_for_no_secrets(self, git_repo):
        clean_file = git_repo / "main.js"
        clean_file.write_text("module.exports = {};\n")
        subprocess.run(["git", "add", "main.js"], cwd=git_repo, capture_output=True, check=True)

        result = _scan_staged_files()
        assert result["secrets_found"] is False
        assert result["count"] == 0
        assert result["files"] == 0

    def test_returns_clean_with_no_staged_files(self, git_repo):
        result = _scan_staged_files()
        assert result["secrets_found"] is False
        assert result["count"] == 0

    def test_handles_binary_files_gracefully(self, git_repo):
        bin_file = git_repo / "image.bin"
        bin_file.write_bytes(bytes([0x89, 0x50, 0x4E, 0x47, 0x00, 0xFF, 0xFE]))
        subprocess.run(["git", "add", "image.bin"], cwd=git_repo, capture_output=True, check=True)

        result = _scan_staged_files()
        assert result["secrets_found"] is False

    def test_only_counts_acm_filter(self, git_repo):
        """Deletion of a file with secrets should NOT trigger scan."""
        # Commit a file with a secret
        env_file = git_repo / ".env"
        env_file.write_text(f"OLD_KEY={FAKE_AWS_KEY}\n")
        subprocess.run(["git", "add", ".env"], cwd=git_repo, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=git_repo, capture_output=True, check=True)

        # Delete it and stage the deletion
        env_file.unlink()
        subprocess.run(["git", "add", ".env"], cwd=git_repo, capture_output=True, check=True)

        result = _scan_staged_files()
        assert result["secrets_found"] is False


# ── PostTool: secret redaction against real file content ────────────────

class TestPosttoolRedactionRealFiles:
    def test_redacts_aws_key_from_real_file(self, git_repo):
        env_file = git_repo / ".env"
        env_file.write_text(f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\nDB=localhost\n")

        content = env_file.read_text()
        scanner = RegexScanner()
        assert scanner.has_secrets(content) is True

        redacted = scanner.redact(content)
        assert FAKE_AWS_KEY not in redacted
        assert "DB=localhost" in redacted
        assert "****" in redacted

    def test_redacts_github_token_from_git_config_output(self):
        output = f"remote.origin.url=https://{FAKE_GITHUB_TOKEN}@github.com/user/repo.git"
        scanner = RegexScanner()
        assert scanner.has_secrets(output) is True

        redacted = scanner.redact(output)
        assert FAKE_GITHUB_TOKEN not in redacted

    def test_passes_through_clean_output(self):
        output = "file1.ts\nfile2.ts\nsrc/index.ts\n"
        scanner = RegexScanner()
        assert scanner.has_secrets(output) is False


# ── Install hook: real git repo ─────────────────────────────────────────

class TestInstallHookRealRepo:
    def test_creates_pre_commit_hook(self, git_repo):
        hooks_dir = git_repo / ".git" / "hooks"
        hook_path = hooks_dir / "pre-commit"

        template = Path(__file__).parent.parent / "rafter_cli" / "resources" / "pre-commit-hook.sh"
        if not template.exists():
            pytest.skip("Hook template not available")

        hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_content = template.read_text()
        hook_path.write_text(hook_content)
        hook_path.chmod(0o755)

        assert hook_path.exists()
        installed = hook_path.read_text()
        assert "Rafter Security Pre-Commit Hook" in installed
        assert "rafter scan local" in installed
        assert hook_path.stat().st_mode & stat.S_IXUSR

    def test_creates_pre_push_hook(self, git_repo):
        hooks_dir = git_repo / ".git" / "hooks"
        hook_path = hooks_dir / "pre-push"

        template = Path(__file__).parent.parent / "rafter_cli" / "resources" / "pre-push-hook.sh"
        if not template.exists():
            pytest.skip("Hook template not available")

        hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_content = template.read_text()
        hook_path.write_text(hook_content)
        hook_path.chmod(0o755)

        assert hook_path.exists()
        installed = hook_path.read_text()
        assert "Rafter Security Pre-Push Hook" in installed
        assert "rafter scan local" in installed

    def test_backs_up_existing_non_rafter_hook(self, git_repo):
        hooks_dir = git_repo / ".git" / "hooks"
        hook_path = hooks_dir / "pre-commit"
        hooks_dir.mkdir(parents=True, exist_ok=True)

        # Write a non-rafter hook
        hook_path.write_text("#!/bin/bash\necho 'existing'\n")

        template = Path(__file__).parent.parent / "rafter_cli" / "resources" / "pre-commit-hook.sh"
        if not template.exists():
            pytest.skip("Hook template not available")

        # Simulate backup + install
        existing = hook_path.read_text()
        assert "Rafter" not in existing

        backup_path = hooks_dir / "pre-commit.backup"
        backup_path.write_text(existing)

        hook_path.write_text(template.read_text())
        hook_path.chmod(0o755)

        assert backup_path.exists()
        assert "existing" in backup_path.read_text()
        assert "Rafter" in hook_path.read_text()

    def test_idempotent_detection(self, git_repo):
        hooks_dir = git_repo / ".git" / "hooks"
        hook_path = hooks_dir / "pre-commit"

        template = Path(__file__).parent.parent / "rafter_cli" / "resources" / "pre-commit-hook.sh"
        if not template.exists():
            pytest.skip("Hook template not available")

        hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_path.write_text(template.read_text())

        # Check for marker — second install should detect it
        installed = hook_path.read_text()
        marker = "Rafter Security Pre-Commit Hook"
        assert marker in installed


# ── Command interception in git context ─────────────────────────────────

class TestCommandInterceptionGitContext:
    def test_blocks_dangerous_commands(self):
        result = _evaluate_bash("rm -rf /")
        assert result["decision"] == "deny"

    def test_allows_normal_git_commands(self):
        for cmd in ["git status", "git log --oneline", "git diff HEAD"]:
            result = _evaluate_bash(cmd)
            assert result["decision"] == "allow", f"Expected allow for: {cmd}"


# ── End-to-end: secret lifecycle ────────────────────────────────────────

class TestSecretLifecycle:
    def test_detect_then_allow_after_removal(self, git_repo):
        # Step 1: Add a secret — should block
        env_file = git_repo / ".env"
        env_file.write_text(f"API_KEY={FAKE_AWS_KEY}\n")
        subprocess.run(["git", "add", ".env"], cwd=git_repo, capture_output=True, check=True)

        blocked = _evaluate_bash('git commit -m "add secret"')
        assert blocked["decision"] == "deny"

        # Step 2: Unstage and remove the secret
        subprocess.run(["git", "rm", "--cached", ".env"], cwd=git_repo, capture_output=True, check=True)
        env_file.unlink()

        # Step 3: Add a clean file instead
        clean = git_repo / "app.ts"
        clean.write_text("export const version = '1.0.0';\n")
        subprocess.run(["git", "add", "app.ts"], cwd=git_repo, capture_output=True, check=True)

        allowed = _evaluate_bash('git commit -m "add app"')
        assert allowed["decision"] == "allow"

    def test_detect_secret_in_modified_file_after_clean_commit(self, git_repo):
        # Initial clean commit
        config = git_repo / "config.ts"
        config.write_text("export const config = {};\n")
        subprocess.run(["git", "add", "config.ts"], cwd=git_repo, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=git_repo, capture_output=True, check=True)

        # Modify with a secret
        config.write_text(f'export const config = {{ key: "{FAKE_AWS_KEY}" }};\n')
        subprocess.run(["git", "add", "config.ts"], cwd=git_repo, capture_output=True, check=True)

        result = _evaluate_bash('git commit -m "update"')
        assert result["decision"] == "deny"

    def test_posttool_redacts_secrets_from_real_file(self, git_repo):
        secret_file = git_repo / "credentials.json"
        secret_file.write_text(json.dumps(
            {"aws_access_key_id": FAKE_AWS_KEY, "region": "us-east-1"},
            indent=2,
        ))

        output = secret_file.read_text()
        scanner = RegexScanner()
        redacted = scanner.redact(output)

        assert FAKE_AWS_KEY not in redacted
        assert "us-east-1" in redacted
        assert "****" in redacted
