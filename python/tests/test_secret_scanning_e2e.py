"""End-to-end secret scanning tests with real filesystem operations.

These tests go beyond pattern matching — they create realistic project
structures, git repos, and multi-file scenarios to validate the scanning
pipeline from file discovery through result reporting.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from rafter_cli.scanners.regex_scanner import RegexScanner


def _fake_secret(prefix: str, body: str) -> str:
    """Build test secrets at runtime to avoid triggering push protection."""
    return prefix + body


# ── Realistic project structure scanning ─────────────────────────────


class TestRealisticProjectScanning:
    def test_finds_secrets_across_multi_file_project(self, tmp_path):
        """Create a realistic project layout and verify all secrets are found."""
        (tmp_path / "src" / "config").mkdir(parents=True)
        (tmp_path / "src" / "utils").mkdir(parents=True)
        (tmp_path / "tests").mkdir()
        (tmp_path / "scripts").mkdir()

        # .env with database URL
        (tmp_path / ".env").write_text(
            "DATABASE_URL=postgres://admin:s3cret@db.example.com:5432/mydb\n"
            "NODE_ENV=production\n"
        )

        # Source file with API key
        (tmp_path / "src" / "config" / "keys.py").write_text(
            '# API configuration\n'
            'API_BASE = "https://api.example.com"\n'
            'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        )

        # Source file with GitHub token
        (tmp_path / "src" / "utils" / "auth.py").write_text(
            'def get_token():\n'
            '    return "ghp_FAKEEFghijklmnopqrstuvwxyz012345678"\n'
        )

        # Clean source file
        (tmp_path / "src" / "__init__.py").write_text(
            'from .config.keys import API_BASE\n'
        )

        # Clean test file
        (tmp_path / "tests" / "test_app.py").write_text(
            'def test_works():\n    assert True\n'
        )

        # Script with private key
        (tmp_path / "scripts" / "deploy.sh").write_text(
            '#!/bin/bash\n'
            '-----BEGIN RSA PRIVATE KEY-----\n'
            'MIIEpAIBAAKCAQEA...\n'
            '-----END RSA PRIVATE KEY-----\n'
            'ssh deploy@server "restart-app"\n'
        )

        scanner = RegexScanner()
        results = scanner.scan_directory(str(tmp_path))

        assert len(results) == 4

        files = sorted(os.path.basename(r.file) for r in results)
        assert ".env" in files
        assert "keys.py" in files
        assert "auth.py" in files
        assert "deploy.sh" in files

    def test_finds_secrets_in_config_file_formats(self, tmp_path):
        """YAML, JSON, and INI-style config files should all be scanned."""
        # YAML config
        (tmp_path / "config.yml").write_text(
            'database:\n'
            '  host: localhost\n'
            '  password: "MyS3cur3Pa55w0rd!"\n'
            '  port: 5432\n'
        )

        # JSON config
        (tmp_path / "config.json").write_text(json.dumps({
            "api": {
                "key": _fake_secret("sk_l1ve_", "abcdefghijklmnopqrstuvwx"),
                "url": "https://api.stripe.com",
            }
        }, indent=2))

        # INI-style config
        (tmp_path / "app.conf").write_text(
            '[database]\n'
            'host = localhost\n'
            'connection = mysql://root:password123@localhost:3306/app\n'
        )

        scanner = RegexScanner()
        results = scanner.scan_directory(str(tmp_path))

        assert len(results) == 3

        patterns = [m.pattern.name for r in results for m in r.matches]
        assert "Generic Secret" in patterns
        assert "Stripe API Key" in patterns
        assert "Database Connection String" in patterns

    def test_skips_node_modules_with_secrets(self, tmp_path):
        """Secrets in node_modules should not be reported."""
        (tmp_path / "index.js").write_text(
            "const token = 'ghp_FAKEEFghijklmnopqrstuvwxyz012345678';\n"
        )

        nm = tmp_path / "node_modules" / "some-pkg" / "src"
        nm.mkdir(parents=True)
        (nm / "config.js").write_text(
            "module.exports = { key: 'AKIAIOSFODNN7EXAMPLE' };\n"
        )

        scanner = RegexScanner()
        results = scanner.scan_directory(str(tmp_path))

        assert len(results) == 1
        assert "index.js" in results[0].file


# ── Mixed content: secrets buried in legitimate files ────────────────


class TestMixedContent:
    def test_finds_secret_buried_in_large_file(self, tmp_path):
        """A single secret hidden among 200 lines of clean code."""
        clean_lines = [f"x_{i} = {i}\n" for i in range(100)]
        secret_line = f'token = "{_fake_secret("sk_l1ve_", "abcdefghijklmnopqrstuvwx")}"\n'
        content = "".join(clean_lines) + secret_line + "".join(clean_lines)

        (tmp_path / "large_file.py").write_text(content)

        scanner = RegexScanner()
        results = scanner.scan_directory(str(tmp_path))

        assert len(results) == 1
        assert results[0].matches[0].line == 101
        assert results[0].matches[0].pattern.name == "Stripe API Key"

    def test_correct_line_numbers_for_multiple_secrets(self, tmp_path):
        """Multiple secrets in one file should each have correct line numbers."""
        content = "\n".join([
            "# Line 1: clean",
            "# Line 2: clean",
            'aws = "AKIAIOSFODNN7EXAMPLE"',       # line 3
            "# Line 4: clean",
            "# Line 5: clean",
            'gh = "ghp_FAKEEFghijklmnopqrstuvwxyz012345678"',  # line 6
            "# Line 7: clean",
            "-----BEGIN RSA PRIVATE KEY-----",     # line 8
            "MIIEpAIBAAKCAQEA...",
            "-----END RSA PRIVATE KEY-----",
        ])

        (tmp_path / "multi_secret.py").write_text(content)

        scanner = RegexScanner()
        result = scanner.scan_file(str(tmp_path / "multi_secret.py"))

        assert len(result.matches) >= 3

        aws = next((m for m in result.matches if m.pattern.name == "AWS Access Key ID"), None)
        gh = next((m for m in result.matches if m.pattern.name == "GitHub Personal Access Token"), None)
        pk = next((m for m in result.matches if m.pattern.name == "Private Key"), None)

        assert aws is not None and aws.line == 3
        assert gh is not None and gh.line == 6
        assert pk is not None and pk.line == 8

    def test_no_false_positive_on_variable_names(self, tmp_path):
        """Variable names containing secret-like substrings should not trigger."""
        content = "\n".join([
            "aws_key_id = os.environ.get('AWS_KEY_ID')",
            "github_token = get_token()",
            "stripe_api_key = config.get('stripe')",
            "def generate_private_key(): return crypto.generate_key()",
        ])

        (tmp_path / "clean_code.py").write_text(content)

        scanner = RegexScanner()
        result = scanner.scan_file(str(tmp_path / "clean_code.py"))
        assert len(result.matches) == 0


# ── Edge cases ───���───────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_file(self, tmp_path):
        (tmp_path / "empty.txt").write_text("")
        scanner = RegexScanner()
        result = scanner.scan_file(str(tmp_path / "empty.txt"))
        assert len(result.matches) == 0

    def test_whitespace_only_file(self, tmp_path):
        (tmp_path / "ws.txt").write_text("   \n\n\t\t\n   ")
        scanner = RegexScanner()
        result = scanner.scan_file(str(tmp_path / "ws.txt"))
        assert len(result.matches) == 0

    def test_unicode_content_around_secrets(self, tmp_path):
        content = (
            "# 配置文件 — Configuration\n"
            'api_key = "sk1234567890abcdef"\n'
            "# Ключ доступа — Access key\n"
            "aws_key = AKIAIOSFODNN7EXAMPLE\n"
            "# アクセストークン — Token\n"
        )
        (tmp_path / "unicode.txt").write_text(content)

        scanner = RegexScanner()
        result = scanner.scan_file(str(tmp_path / "unicode.txt"))
        assert len(result.matches) > 0
        assert any(m.pattern.name == "AWS Access Key ID" for m in result.matches)

    def test_deeply_nested_directory(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "d" / "e" / "f"
        deep.mkdir(parents=True)
        (deep / "secret.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")

        scanner = RegexScanner()
        results = scanner.scan_directory(str(tmp_path))
        assert len(results) == 1

    def test_binary_files_skipped(self, tmp_path):
        for ext in [".jpg", ".png", ".exe", ".dll", ".zip", ".pyc"]:
            (tmp_path / f"file{ext}").write_bytes(
                b"\x89PNG\r\n" + b"AKIAIOSFODNN7EXAMPLE"
            )

        # One text file that should be caught
        (tmp_path / "file.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")

        scanner = RegexScanner()
        results = scanner.scan_directory(str(tmp_path))
        assert len(results) == 1
        assert "file.txt" in results[0].file

    def test_nonexistent_file(self):
        scanner = RegexScanner()
        result = scanner.scan_file("/tmp/nonexistent-rafter-file-99999.txt")
        assert len(result.matches) == 0

    def test_empty_directory(self, tmp_path):
        scanner = RegexScanner()
        results = scanner.scan_directory(str(tmp_path))
        assert len(results) == 0


# ── Git --staged scanning ────────────────────────────────────────────


def _git(args: str, cwd: str) -> str:
    return subprocess.run(
        f"git {args}",
        shell=True,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


class TestGitStagedScanning:
    """Test that scanning git staged files works with real git repos."""

    @pytest.fixture(autouse=True)
    def setup_git_repo(self, tmp_path):
        self.repo = str(tmp_path)
        _git("init", self.repo)
        _git('config user.email "test@example.com"', self.repo)
        _git('config user.name "Test"', self.repo)

        (tmp_path / "README.md").write_text("# Test repo\n")
        _git("add README.md", self.repo)
        _git('commit -m "initial"', self.repo)

    def _get_staged_files(self) -> list[str]:
        """Get list of staged file paths (mimics what --staged does internally)."""
        output = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, check=True,
            cwd=self.repo,
        ).stdout.strip()
        if not output:
            return []
        repo_root = _git("rev-parse --show-toplevel", self.repo)
        return [os.path.join(repo_root, f.strip()) for f in output.split("\n") if f.strip()]

    def test_detects_secrets_in_staged_files(self, tmp_path):
        (tmp_path / "config.py").write_text(
            "API_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        )
        _git("add config.py", self.repo)

        staged = self._get_staged_files()
        assert len(staged) == 1

        scanner = RegexScanner()
        results = scanner.scan_files(staged)
        assert len(results) == 1
        assert results[0].matches[0].pattern.name == "AWS Access Key ID"

    def test_clean_staged_files_produce_no_results(self, tmp_path):
        (tmp_path / "clean.py").write_text("x = 42\n")
        _git("add clean.py", self.repo)

        staged = self._get_staged_files()
        scanner = RegexScanner()
        results = scanner.scan_files(staged)
        assert len(results) == 0

    def test_only_staged_files_scanned(self, tmp_path):
        """Unstaged files with secrets should not be reported."""
        (tmp_path / "clean.py").write_text("x = 42\n")
        _git("add clean.py", self.repo)

        # Create but don't stage a file with a secret
        (tmp_path / "secret.py").write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")

        staged = self._get_staged_files()
        assert len(staged) == 1
        assert "clean.py" in staged[0]

        scanner = RegexScanner()
        results = scanner.scan_files(staged)
        assert len(results) == 0


# ── Git --diff scanning ─────────────────────────────────────────────


class TestGitDiffScanning:
    """Test that scanning files changed since a ref works with real git repos."""

    @pytest.fixture(autouse=True)
    def setup_git_repo(self, tmp_path):
        self.repo = str(tmp_path)
        _git("init", self.repo)
        _git('config user.email "test@example.com"', self.repo)
        _git('config user.name "Test"', self.repo)

        (tmp_path / "README.md").write_text("# Test repo\n")
        _git("add README.md", self.repo)
        _git('commit -m "initial"', self.repo)

    def _get_diff_files(self, ref: str) -> list[str]:
        """Get files changed since ref (mimics what --diff does internally)."""
        output = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACM", ref],
            capture_output=True, text=True, check=True,
            cwd=self.repo,
        ).stdout.strip()
        if not output:
            return []
        repo_root = _git("rev-parse --show-toplevel", self.repo)
        return [os.path.join(repo_root, f.strip()) for f in output.split("\n") if f.strip()]

    def test_detects_secrets_in_changed_files(self, tmp_path):
        initial = _git("rev-parse HEAD", self.repo)

        (tmp_path / "secrets.py").write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")
        _git("add secrets.py", self.repo)
        _git('commit -m "add secrets"', self.repo)

        changed = self._get_diff_files(initial)
        assert len(changed) == 1

        scanner = RegexScanner()
        results = scanner.scan_files(changed)
        assert len(results) == 1
        assert results[0].matches[0].pattern.name == "AWS Access Key ID"

    def test_clean_changed_files_produce_no_results(self, tmp_path):
        initial = _git("rev-parse HEAD", self.repo)

        (tmp_path / "feature.py").write_text("def add(a, b): return a + b\n")
        _git("add feature.py", self.repo)
        _git('commit -m "add feature"', self.repo)

        changed = self._get_diff_files(initial)
        scanner = RegexScanner()
        results = scanner.scan_files(changed)
        assert len(results) == 0

    def test_only_changed_files_scanned(self, tmp_path):
        """Files with secrets committed before the ref should not appear."""
        (tmp_path / "old_secret.py").write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")
        _git("add old_secret.py", self.repo)
        _git('commit -m "old secret"', self.repo)

        ref = _git("rev-parse HEAD", self.repo)

        (tmp_path / "clean.py").write_text("x = 1\n")
        _git("add clean.py", self.repo)
        _git('commit -m "add clean"', self.repo)

        changed = self._get_diff_files(ref)
        assert len(changed) == 1
        assert "clean.py" in changed[0]

        scanner = RegexScanner()
        results = scanner.scan_files(changed)
        assert len(results) == 0


# ── Scanner API with realistic files ─────────────────────────────────


class TestScannerAPI:
    def test_scan_files_returns_only_dirty_files(self, tmp_path):
        files_data = [
            ("clean1.py", "x = 1"),
            ("dirty.py", "key = 'AKIAIOSFODNN7EXAMPLE'"),
            ("clean2.py", "y = 2"),
            ("dirty2.py", "-----BEGIN RSA PRIVATE KEY-----"),
        ]
        paths = []
        for name, content in files_data:
            p = tmp_path / name
            p.write_text(content)
            paths.append(str(p))

        scanner = RegexScanner()
        results = scanner.scan_files(paths)

        assert len(results) == 2
        result_files = sorted(os.path.basename(r.file) for r in results)
        assert result_files == ["dirty.py", "dirty2.py"]

    def test_multiple_exclude_paths(self, tmp_path):
        for d in ["vendor", "generated", "src"]:
            (tmp_path / d).mkdir()
            (tmp_path / d / "file.py").write_text("AKIAIOSFODNN7EXAMPLE\n")

        scanner = RegexScanner()
        # "vendor" is NOT in Python's DEFAULT_EXCLUDE, so exclude it manually
        results = scanner.scan_directory(
            str(tmp_path), exclude_paths=["vendor", "generated"]
        )

        assert len(results) == 1
        assert "src" in results[0].file

    def test_max_depth_limits_recursion(self, tmp_path):
        (tmp_path / "top.py").write_text("AKIAIOSFODNN7EXAMPLE\n")

        level1 = tmp_path / "level1"
        level1.mkdir()
        (level1 / "l1.py").write_text("AKIAIOSFODNN7EXAMPLE\n")

        level2 = level1 / "level2"
        level2.mkdir()
        (level2 / "l2.py").write_text("AKIAIOSFODNN7EXAMPLE\n")

        scanner = RegexScanner()

        shallow = scanner.scan_directory(str(tmp_path), max_depth=1)
        assert len(shallow) == 1
        assert "top.py" in shallow[0].file

        deeper = scanner.scan_directory(str(tmp_path), max_depth=3)
        assert len(deeper) == 3

    def test_redact_masks_all_secret_types(self):
        secrets = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_FAKEEFghijklmnopqrstuvwxyz012345678",
            _fake_secret("sk_l1ve_", "abcdefghijklmnopqrstuvwx"),
        ]

        scanner = RegexScanner()
        for secret in secrets:
            redacted = scanner.redact(f"token is {secret} here")
            assert secret not in redacted
            assert "token is" in redacted
