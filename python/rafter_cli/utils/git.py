"""Git utility functions."""
from __future__ import annotations

import re
import subprocess


def _run(cmd: list[str]) -> str:
    return subprocess.check_output(
        cmd, text=True, stderr=subprocess.DEVNULL
    ).strip()


def get_git_root() -> str | None:
    """Return the git repository root, or None if not in a repo."""
    try:
        return _run(["git", "rev-parse", "--show-toplevel"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def is_inside_repo() -> bool:
    try:
        return _run(["git", "rev-parse", "--is-inside-work-tree"]) == "true"
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def safe_branch() -> str:
    """Return the current branch name, falling back to short HEAD."""
    try:
        return _run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"])
    except subprocess.CalledProcessError:
        try:
            return _run(["git", "rev-parse", "--short", "HEAD"])
        except subprocess.CalledProcessError:
            return "main"


def parse_remote(url: str) -> str:
    """Parse a git remote URL into 'owner/repo' format."""
    url = re.sub(r"^(https?://|git@)", "", url)
    url = url.replace(":", "/")
    if url.endswith(".git"):
        url = url[:-4]
    parts = url.split("/")
    return "/".join(parts[-2:])


def detect_repo(
    repo: str | None = None,
    branch: str | None = None,
) -> tuple[str, str]:
    """Auto-detect repo slug and branch from git or CI env vars.

    Returns (repo_slug, branch).
    Raises RuntimeError if detection fails.
    """
    import os

    repo_env = os.getenv("GITHUB_REPOSITORY") or os.getenv("CI_REPOSITORY")
    branch_env = (
        os.getenv("GITHUB_REF_NAME")
        or os.getenv("CI_COMMIT_BRANCH")
        or os.getenv("CI_BRANCH")
    )
    repo_slug = repo or repo_env
    branch_name = branch or branch_env

    if repo_slug and branch_name:
        return repo_slug, branch_name

    if not is_inside_repo():
        raise RuntimeError(
            "Could not auto-detect Git repository. "
            "Please pass --repo and --branch explicitly."
        )

    if not repo_slug:
        try:
            remote_url = _run(["git", "remote", "get-url", "origin"])
            repo_slug = parse_remote(remote_url)
        except subprocess.CalledProcessError:
            raise RuntimeError(
                "Could not auto-detect Git repository. "
                "Please pass --repo and --branch explicitly."
            )

    if not branch_name:
        branch_name = safe_branch()

    return repo_slug, branch_name
