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
    provider_for_host,
    infer_remote,
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


# sable-pqmw: parse_remote used to slice the last two path segments of ANY
# remote with no host check at all, so a non-GitHub-shaped remote silently
# produced a wrong slug (e.g. Azure DevOps's `.../_git/repo` becomes
# `_git/repo`; a filesystem remote becomes `<parent-dir>/<repo>`). The
# backend turns that slug into `https://github.com/{slug}` and 404s,
# burning a paid scan. It must now reject anything it can't recognize.
class TestParseRemoteHostValidation:
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://github.com/owner/repo", "owner/repo"),
            ("git@github.com:owner/repo.git", "owner/repo"),
            ("https://github.com/owner/repo.git", "owner/repo"),
            # GitLab stays supported -- separate multi-provider feature
            # (sable-w79q) that already sends provider + repo_url alongside.
            ("git@gitlab.com:group/project.git", "group/project"),
        ],
    )
    def test_recognized_remote_shapes_still_parse(self, url, expected):
        assert parse_remote(url) == expected

    @pytest.mark.parametrize(
        "url",
        [
            # Azure DevOps: naive last-two-segments yields "_git/repo".
            "https://dev.azure.com/my-org/my-proj/_git/my-repo",
            # Bare filesystem remote: naive last-two-segments yields
            # "<parent-dir>/<repo>" -- the "local/*" class seen in production.
            "/home/ci/local/my-repo",
        ],
    )
    def test_unrecognized_host_remotes_are_rejected(self, url):
        with pytest.raises(RuntimeError, match="[Uu]nsupported"):
            parse_remote(url)

    def test_rejection_names_the_offending_host(self):
        with pytest.raises(RuntimeError, match="dev.azure.com"):
            parse_remote("https://dev.azure.com/my-org/my-proj/_git/my-repo")

    # Found in security review of this fix: a naive "replace : with /"
    # treats the userinfo separator the same as the SCP host:path
    # separator, so `parts[0]` (the value checked against the host
    # allowlist) can be attacker-chosen credentials rather than the real
    # host -- and legitimate credentialed remotes (PAT-embedded HTTPS,
    # common in CI) hard-fail the same way.
    @pytest.mark.parametrize(
        "url,expected",
        [
            # CI token-embedded remotes -- real shapes, must keep working.
            ("https://x-access-token:ghp_abc123@github.com/owner/repo.git", "owner/repo"),
            ("https://gitlab-ci-token:glcbt-abc@gitlab.com/group/project.git", "group/project"),
            # Explicit ssh:// scheme -- a normal, non-adversarial clone form.
            ("ssh://git@github.com/owner/repo.git", "owner/repo"),
            ("ssh://git@github.com:2222/owner/repo.git", "owner/repo"),
        ],
    )
    def test_credentialed_and_ssh_scheme_remotes_still_parse(self, url, expected):
        assert parse_remote(url) == expected

    def test_userinfo_cannot_smuggle_an_unrecognized_host_past_the_check(self):
        # The real host is evil.com; "github.com" only appears as userinfo.
        # Must be rejected (as evil.com), never accepted as github.com.
        with pytest.raises(RuntimeError, match="evil.com"):
            parse_remote("https://github.com:x@evil.com/foo/bar.git")


# ── provider_for_host (host → provider inference) ───────────────────


class TestProviderForHost:
    def test_github(self):
        assert provider_for_host("github.com") == "github"

    def test_gitlab(self):
        assert provider_for_host("gitlab.com") == "gitlab"

    def test_gitlab_subdomain(self):
        assert provider_for_host("git.gitlab.com") == "gitlab"

    def test_bitbucket(self):
        assert provider_for_host("bitbucket.org") == "bitbucket"

    def test_codeberg_is_gitea(self):
        assert provider_for_host("codeberg.org") == "gitea"

    def test_gitea_io_subdomain(self):
        assert provider_for_host("try.gitea.io") == "gitea"

    def test_unknown_defaults_to_github(self):
        assert provider_for_host("git.example.com") == "github"

    def test_case_insensitive(self):
        assert provider_for_host("GitLab.com") == "gitlab"


# ── infer_remote (provider + canonical repo_url) ────────────────────


class TestInferRemote:
    def test_github_https(self):
        assert infer_remote("https://github.com/owner/repo.git") == (
            "github",
            "https://github.com/owner/repo",
        )

    def test_github_ssh(self):
        assert infer_remote("git@github.com:owner/repo.git") == (
            "github",
            "https://github.com/owner/repo",
        )

    def test_gitlab_ssh_normalized(self):
        assert infer_remote("git@gitlab.com:group/project.git") == (
            "gitlab",
            "https://gitlab.com/group/project",
        )

    def test_gitlab_https_no_suffix(self):
        assert infer_remote("https://gitlab.com/group/project") == (
            "gitlab",
            "https://gitlab.com/group/project",
        )

    def test_bitbucket_ssh(self):
        assert infer_remote("git@bitbucket.org:team/repo.git") == (
            "bitbucket",
            "https://bitbucket.org/team/repo",
        )

    def test_bitbucket_https(self):
        assert infer_remote("https://bitbucket.org/team/repo.git") == (
            "bitbucket",
            "https://bitbucket.org/team/repo",
        )

    def test_codeberg_is_gitea(self):
        assert infer_remote("https://codeberg.org/owner/repo.git") == (
            "gitea",
            "https://codeberg.org/owner/repo",
        )

    def test_gitea_io_ssh(self):
        assert infer_remote("git@try.gitea.io:owner/repo.git") == (
            "gitea",
            "https://try.gitea.io/owner/repo",
        )

    def test_unknown_host_defaults_github_but_normalizes(self):
        assert infer_remote("https://git.example.com/owner/repo.git") == (
            "github",
            "https://git.example.com/owner/repo",
        )

    def test_unparseable_returns_github_none(self):
        assert infer_remote("not-a-url") == ("github", None)


# ── safe_branch ─────────────────────────────────────────────────────


class TestSafeBranch:
    def test_returns_branch_name(self):
        with patch("rafter_cli.utils.git._run", return_value="feature/abc"):
            assert safe_branch() == "feature/abc"

    # sable-pqmw: a detached HEAD must not submit a commit SHA as a branch
    # name -- it is not a branch and is guaranteed to 404 on the backend.
    # The old behavior fell back to `rev-parse --short HEAD`; assert that
    # even when a SHA IS available, it is never returned.
    def test_detached_head_raises_even_when_a_sha_is_available(self):
        def mock_run(cmd):
            if "symbolic-ref" in cmd:
                raise subprocess.CalledProcessError(1, cmd)
            return "abc1234"  # a real SHA is obtainable but must be refused

        with patch("rafter_cli.utils.git._run", side_effect=mock_run):
            with pytest.raises(RuntimeError, match="branch"):
                safe_branch()

    # sable-pqmw: total git failure (e.g. an empty repo with no commits)
    # must not fall back to a hardcoded "main" -- that guesses the default
    # branch and is often wrong, and is misleading even when it isn't.
    def test_total_failure_does_not_invent_a_default_branch(self):
        with patch(
            "rafter_cli.utils.git._run",
            side_effect=subprocess.CalledProcessError(1, "git"),
        ):
            with pytest.raises(RuntimeError, match="branch"):
                safe_branch()


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
        # Both explicit → no provider/repo_url inferred (flags fill those in).
        result = detect_repo(repo="org/repo", branch="main")
        assert result == ("org/repo", "main", None, None)

    def test_github_env_vars(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REPOSITORY", "gh-org/gh-repo")
        monkeypatch.setenv("GITHUB_REF_NAME", "develop")
        monkeypatch.delenv("CI_REPOSITORY", raising=False)
        monkeypatch.delenv("CI_COMMIT_BRANCH", raising=False)
        monkeypatch.delenv("CI_BRANCH", raising=False)
        result = detect_repo()
        assert result == ("gh-org/gh-repo", "develop", None, None)

    def test_ci_repository_fallback(self, monkeypatch):
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
        monkeypatch.setenv("CI_REPOSITORY", "ci-org/ci-repo")
        monkeypatch.setenv("CI_COMMIT_BRANCH", "staging")
        monkeypatch.delenv("CI_BRANCH", raising=False)
        result = detect_repo()
        assert result == ("ci-org/ci-repo", "staging", None, None)

    def test_ci_branch_env(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
        monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
        monkeypatch.delenv("CI_COMMIT_BRANCH", raising=False)
        monkeypatch.setenv("CI_BRANCH", "circle-branch")
        result = detect_repo()
        assert result == ("org/repo", "circle-branch", None, None)

    def test_explicit_opts_override_env(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REPOSITORY", "env-org/env-repo")
        monkeypatch.setenv("GITHUB_REF_NAME", "env-branch")
        result = detect_repo(repo="my/repo", branch="my-branch")
        assert result == ("my/repo", "my-branch", None, None)

    def test_github_precedence_over_ci(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REPOSITORY", "gh/repo")
        monkeypatch.setenv("CI_REPOSITORY", "ci/repo")
        monkeypatch.setenv("GITHUB_REF_NAME", "main")
        result = detect_repo()
        assert result == ("gh/repo", "main", None, None)

    def test_github_ref_precedence_over_ci_branch(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
        monkeypatch.setenv("GITHUB_REF_NAME", "gh-branch")
        monkeypatch.setenv("CI_COMMIT_BRANCH", "gl-branch")
        monkeypatch.setenv("CI_BRANCH", "ci-branch")
        result = detect_repo()
        assert result == ("org/repo", "gh-branch", None, None)

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
            # github remote → provider inferred, but backward-compat is enforced
            # at the request-body layer (backend), not here.
            assert result == (
                "fallback/repo",
                "feat",
                "github",
                "https://github.com/fallback/repo",
            )

    def test_infers_gitlab_provider_and_repo_url_from_remote(self, monkeypatch):
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        monkeypatch.delenv("CI_REPOSITORY", raising=False)
        monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
        monkeypatch.delenv("CI_COMMIT_BRANCH", raising=False)
        monkeypatch.delenv("CI_BRANCH", raising=False)

        with patch("rafter_cli.utils.git.is_inside_repo", return_value=True), \
             patch("rafter_cli.utils.git._run", return_value="git@gitlab.com:group/project.git"), \
             patch("rafter_cli.utils.git.safe_branch", return_value="main"):
            result = detect_repo()
            assert result == (
                "group/project",
                "main",
                "gitlab",
                "https://gitlab.com/group/project",
            )

    # sable-pqmw: an unrecognized-host remote (e.g. Azure DevOps) must
    # surface as a clear, catchable error through the full detection path,
    # not a silently wrong repository_name.
    def test_raises_on_unrecognized_host_remote(self, monkeypatch):
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        monkeypatch.delenv("CI_REPOSITORY", raising=False)
        monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
        monkeypatch.delenv("CI_COMMIT_BRANCH", raising=False)
        monkeypatch.delenv("CI_BRANCH", raising=False)

        with patch("rafter_cli.utils.git.is_inside_repo", return_value=True), \
             patch(
                 "rafter_cli.utils.git._run",
                 return_value="https://dev.azure.com/my-org/my-proj/_git/my-repo",
             ):
            with pytest.raises(RuntimeError, match="dev.azure.com"):
                detect_repo()

    def test_raises_when_not_in_repo_and_no_env(self, monkeypatch):
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        monkeypatch.delenv("CI_REPOSITORY", raising=False)
        monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
        monkeypatch.delenv("CI_COMMIT_BRANCH", raising=False)
        monkeypatch.delenv("CI_BRANCH", raising=False)

        with patch("rafter_cli.utils.git.is_inside_repo", return_value=False):
            with pytest.raises(RuntimeError, match="Could not auto-detect"):
                detect_repo()
