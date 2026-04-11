"""Tests for git utility functions."""
from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from rafter_cli.utils.git import (
    parse_remote,
    safe_branch,
    detect_repo,
    is_inside_repo,
    get_git_root,
)


# ── parse_remote (pure function) ────────────────────────────────────


class TestParseRemote:
    def test_https_github(self):
        assert parse_remote("https://github.com/owner/repo.git") == "owner/repo"

    def test_ssh_github(self):
        assert parse_remote("git@github.com:owner/repo.git") == "owner/repo"

    def test_without_git_suffix(self):
        assert parse_remote("https://github.com/owner/repo") == "owner/repo"

    def test_gitlab(self):
        assert parse_remote("git@gitlab.com:group/project.git") == "group/project"

    def test_nested_paths(self):
        assert parse_remote("https://gitlab.com/group/subgroup/project.git") == "subgroup/project"

    def test_http_no_tls(self):
        assert parse_remote("http://github.com/owner/repo.git") == "owner/repo"


# ── safe_branch ─────────────────────────────────────────────────────


class TestSafeBranch:
    def test_returns_branch_name(self):
        with patch("rafter_cli.utils.git._run", return_value="feature/abc"):
            assert safe_branch() == "feature/abc"

    def test_falls_back_to_short_head(self):
        def mock_run(cmd):
            if "symbolic-ref" in cmd:
                raise subprocess.CalledProcessError(1, cmd)
            return "abc1234"

        with patch("rafter_cli.utils.git._run", side_effect=mock_run):
            assert safe_branch() == "abc1234"

    def test_falls_back_to_main(self):
        with patch(
            "rafter_cli.utils.git._run",
            side_effect=subprocess.CalledProcessError(1, "git"),
        ):
            assert safe_branch() == "main"


# ── is_inside_repo ──────────────────────────────────────────────────


class TestIsInsideRepo:
    def test_true_in_repo(self):
        with patch("rafter_cli.utils.git._run", return_value="true"):
            assert is_inside_repo() is True

    def test_false_outside_repo(self):
        with patch(
            "rafter_cli.utils.git._run",
            side_effect=subprocess.CalledProcessError(1, "git"),
        ):
            assert is_inside_repo() is False


# ── get_git_root ────────────────────────────────────────────────────


class TestGetGitRoot:
    def test_returns_root(self):
        with patch("rafter_cli.utils.git._run", return_value="/home/user/repo"):
            assert get_git_root() == "/home/user/repo"

    def test_returns_none_outside_repo(self):
        with patch(
            "rafter_cli.utils.git._run",
            side_effect=subprocess.CalledProcessError(1, "git"),
        ):
            assert get_git_root() is None


# ── detect_repo ─────────────────────────────────────────────────────


class TestDetectRepo:
    def test_explicit_repo_and_branch(self):
        result = detect_repo(repo="org/repo", branch="main")
        assert result == ("org/repo", "main")

    def test_github_env_vars(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REPOSITORY", "gh-org/gh-repo")
        monkeypatch.setenv("GITHUB_REF_NAME", "develop")
        monkeypatch.delenv("CI_REPOSITORY", raising=False)
        monkeypatch.delenv("CI_COMMIT_BRANCH", raising=False)
        monkeypatch.delenv("CI_BRANCH", raising=False)
        result = detect_repo()
        assert result == ("gh-org/gh-repo", "develop")

    def test_ci_repository_fallback(self, monkeypatch):
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
        monkeypatch.setenv("CI_REPOSITORY", "ci-org/ci-repo")
        monkeypatch.setenv("CI_COMMIT_BRANCH", "staging")
        monkeypatch.delenv("CI_BRANCH", raising=False)
        result = detect_repo()
        assert result == ("ci-org/ci-repo", "staging")

    def test_ci_branch_env(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
        monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
        monkeypatch.delenv("CI_COMMIT_BRANCH", raising=False)
        monkeypatch.setenv("CI_BRANCH", "circle-branch")
        result = detect_repo()
        assert result == ("org/repo", "circle-branch")

    def test_explicit_opts_override_env(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REPOSITORY", "env-org/env-repo")
        monkeypatch.setenv("GITHUB_REF_NAME", "env-branch")
        result = detect_repo(repo="my/repo", branch="my-branch")
        assert result == ("my/repo", "my-branch")

    def test_github_precedence_over_ci(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REPOSITORY", "gh/repo")
        monkeypatch.setenv("CI_REPOSITORY", "ci/repo")
        monkeypatch.setenv("GITHUB_REF_NAME", "main")
        result = detect_repo()
        assert result == ("gh/repo", "main")

    def test_github_ref_precedence_over_ci_branch(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
        monkeypatch.setenv("GITHUB_REF_NAME", "gh-branch")
        monkeypatch.setenv("CI_COMMIT_BRANCH", "gl-branch")
        monkeypatch.setenv("CI_BRANCH", "ci-branch")
        result = detect_repo()
        assert result == ("org/repo", "gh-branch")

    def test_falls_back_to_git_when_no_env(self, monkeypatch):
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        monkeypatch.delenv("CI_REPOSITORY", raising=False)
        monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
        monkeypatch.delenv("CI_COMMIT_BRANCH", raising=False)
        monkeypatch.delenv("CI_BRANCH", raising=False)

        with patch("rafter_cli.utils.git.is_inside_repo", return_value=True), \
             patch("rafter_cli.utils.git._run", return_value="https://github.com/fallback/repo.git"), \
             patch("rafter_cli.utils.git.safe_branch", return_value="feat"):
            result = detect_repo()
            assert result == ("fallback/repo", "feat")

    def test_raises_when_not_in_repo_and_no_env(self, monkeypatch):
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        monkeypatch.delenv("CI_REPOSITORY", raising=False)
        monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
        monkeypatch.delenv("CI_COMMIT_BRANCH", raising=False)
        monkeypatch.delenv("CI_BRANCH", raising=False)

        with patch("rafter_cli.utils.git.is_inside_repo", return_value=False):
            with pytest.raises(RuntimeError, match="Could not auto-detect"):
                detect_repo()
