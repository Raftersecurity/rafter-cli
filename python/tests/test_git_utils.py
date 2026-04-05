"""Tests for git utility functions: remote parsing, branch detection, CI env detection."""
from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from rafter_cli.utils.git import parse_remote, safe_branch, detect_repo


class TestParseRemote:
    def test_https_github(self):
        assert parse_remote("https://github.com/owner/repo.git") == "owner/repo"

    def test_ssh_github(self):
        assert parse_remote("git@github.com:owner/repo.git") == "owner/repo"

    def test_no_git_suffix(self):
        assert parse_remote("https://github.com/owner/repo") == "owner/repo"

    def test_gitlab_ssh(self):
        assert parse_remote("git@gitlab.com:group/project.git") == "group/project"

    def test_nested_path_takes_last_two(self):
        assert parse_remote("https://gitlab.com/group/subgroup/project.git") == "subgroup/project"

    def test_http_no_ssl(self):
        assert parse_remote("http://github.com/owner/repo.git") == "owner/repo"


class TestSafeBranch:
    @patch("rafter_cli.utils.git._run", return_value="feature/my-branch")
    def test_returns_symbolic_ref(self, mock_run):
        assert safe_branch() == "feature/my-branch"
        mock_run.assert_called_once_with(["git", "symbolic-ref", "--quiet", "--short", "HEAD"])

    @patch("rafter_cli.utils.git._run")
    def test_falls_back_to_rev_parse(self, mock_run):
        mock_run.side_effect = [
            subprocess.CalledProcessError(1, "git"),  # symbolic-ref fails
            "abc1234",  # rev-parse succeeds
        ]
        assert safe_branch() == "abc1234"
        assert mock_run.call_count == 2

    @patch("rafter_cli.utils.git._run")
    def test_falls_back_to_main(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "git")
        assert safe_branch() == "main"


class TestDetectRepo:
    def test_explicit_repo_and_branch(self):
        slug, branch = detect_repo(repo="owner/repo", branch="main")
        assert slug == "owner/repo"
        assert branch == "main"

    @patch.dict("os.environ", {"GITHUB_REPOSITORY": "gh-owner/gh-repo", "GITHUB_REF_NAME": "develop"}, clear=False)
    def test_github_env_vars(self):
        slug, branch = detect_repo()
        assert slug == "gh-owner/gh-repo"
        assert branch == "develop"

    @patch.dict("os.environ", {"CI_REPOSITORY": "gl-group/gl-project", "CI_COMMIT_BRANCH": "release/v2"}, clear=False)
    def test_gitlab_env_vars(self):
        slug, branch = detect_repo()
        assert slug == "gl-group/gl-project"
        assert branch == "release/v2"

    @patch.dict("os.environ", {"CI_REPOSITORY": "ci-owner/ci-repo", "CI_BRANCH": "staging"}, clear=False)
    def test_generic_ci_env_vars(self):
        slug, branch = detect_repo()
        assert slug == "ci-owner/ci-repo"
        assert branch == "staging"

    @patch.dict("os.environ", {
        "GITHUB_REPOSITORY": "env-owner/env-repo",
        "GITHUB_REF_NAME": "env-branch",
    }, clear=False)
    def test_explicit_opts_override_env(self):
        slug, branch = detect_repo(repo="explicit/repo", branch="explicit-branch")
        assert slug == "explicit/repo"
        assert branch == "explicit-branch"

    @patch.dict("os.environ", {"GITHUB_REPOSITORY": "gh-owner/gh-repo"}, clear=False)
    @patch("rafter_cli.utils.git.safe_branch", return_value="detected-branch")
    @patch("rafter_cli.utils.git.is_inside_repo", return_value=True)
    def test_env_repo_with_git_branch(self, _mock_repo, _mock_branch):
        slug, branch = detect_repo()
        assert slug == "gh-owner/gh-repo"
        assert branch == "detected-branch"

    @patch.dict("os.environ", {
        "GITHUB_REPOSITORY": "gh/repo",
        "CI_REPOSITORY": "ci/repo",
        "GITHUB_REF_NAME": "main",
    }, clear=False)
    def test_github_takes_priority_over_ci(self):
        slug, _branch = detect_repo()
        assert slug == "gh/repo"

    @patch.dict("os.environ", {
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_REF_NAME": "gh-branch",
        "CI_COMMIT_BRANCH": "gl-branch",
    }, clear=False)
    def test_github_ref_takes_priority(self):
        _slug, branch = detect_repo()
        assert branch == "gh-branch"

    @patch.dict("os.environ", {}, clear=True)
    @patch("rafter_cli.utils.git.is_inside_repo", return_value=False)
    def test_raises_without_git_or_env(self, _mock):
        with pytest.raises(RuntimeError, match="Could not auto-detect"):
            detect_repo()
