"""Tests for ci init command."""
from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from rafter_cli.__main__ import app
from rafter_cli.commands.ci import (
    _detect_platform,
    _github_template,
    _gitlab_template,
    _circleci_template,
)

runner = CliRunner()


class TestDetectPlatform:
    def test_detects_github(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github").mkdir()
        assert _detect_platform() == "github"

    def test_detects_gitlab(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".gitlab-ci.yml").write_text("stages:\n  - test\n")
        assert _detect_platform() == "gitlab"

    def test_detects_circleci(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".circleci").mkdir()
        assert _detect_platform() == "circleci"

    def test_returns_none_when_no_platform(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert _detect_platform() is None


class TestTemplates:
    def test_github_template_basic(self):
        content = _github_template(with_backend=False)
        assert "actions/checkout@v4" in content
        assert "pip install rafter-cli" in content
        assert "rafter scan local . --quiet" in content
        assert "security-audit" not in content

    def test_github_template_with_backend(self):
        content = _github_template(with_backend=True)
        assert "security-audit" in content
        assert "needs: secret-scan" in content
        assert "RAFTER_API_KEY" in content
        assert "rafter run --format json --quiet" in content

    def test_gitlab_template_basic(self):
        content = _gitlab_template(with_backend=False)
        assert "image: python:3.12" in content
        assert "stages:" in content
        assert "security-audit" not in content

    def test_gitlab_template_with_backend(self):
        content = _gitlab_template(with_backend=True)
        assert "security-audit" in content
        assert "needs: [secret-scan]" in content
        assert "RAFTER_API_KEY" in content

    def test_circleci_template_basic(self):
        content = _circleci_template(with_backend=False)
        assert "cimg/python:3.12" in content
        assert "version: 2.1" in content
        assert "workflows:" in content
        assert "security-audit" not in content

    def test_circleci_template_with_backend(self):
        content = _circleci_template(with_backend=True)
        assert "security-audit" in content
        assert "requires:" in content
        assert "- secret-scan" in content


class TestCiInitCommand:
    def test_explicit_github(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["ci", "init", "--platform", "github"])
        assert result.exit_code == 0
        generated = tmp_path / ".github" / "workflows" / "rafter-security.yml"
        assert generated.exists()
        assert "rafter scan local" in generated.read_text()

    def test_explicit_gitlab(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["ci", "init", "--platform", "gitlab"])
        assert result.exit_code == 0
        generated = tmp_path / ".gitlab-ci-rafter.yml"
        assert generated.exists()

    def test_explicit_circleci(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["ci", "init", "--platform", "circleci"])
        assert result.exit_code == 0
        generated = tmp_path / ".circleci" / "rafter-security.yml"
        assert generated.exists()

    def test_auto_detect_github(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".github").mkdir()
        result = runner.invoke(app, ["ci", "init"])
        assert result.exit_code == 0
        assert (tmp_path / ".github" / "workflows" / "rafter-security.yml").exists()

    def test_no_platform_exits_1(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["ci", "init"])
        assert result.exit_code == 1

    def test_invalid_platform_exits_1(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["ci", "init", "--platform", "jenkins"])
        assert result.exit_code == 1

    def test_with_backend_flag(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["ci", "init", "--platform", "github", "--with-backend"])
        assert result.exit_code == 0
        content = (tmp_path / ".github" / "workflows" / "rafter-security.yml").read_text()
        assert "security-audit" in content
        assert "RAFTER_API_KEY" in content

    def test_custom_output_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        custom = tmp_path / "custom" / "ci.yml"
        result = runner.invoke(app, ["ci", "init", "--platform", "github", "--output", str(custom)])
        assert result.exit_code == 0
        assert custom.exists()
        assert "rafter scan local" in custom.read_text()
