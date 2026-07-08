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


def provider_for_host(host: str) -> str:
    """Map a git remote host to a provider.

    'github' is the backward-compatible default for any host we don't
    recognize — a GitHub user's request is unaffected, and unknown
    self-hosted hosts fall back to the legacy behavior.
    """
    host = host.lower()
    if host == "github.com":
        return "github"
    if host == "gitlab.com" or host.endswith(".gitlab.com"):
        return "gitlab"
    if host == "bitbucket.org":
        return "bitbucket"
    if host == "codeberg.org" or host.endswith(".gitea.io"):
        return "gitea"
    return "github"  # backward-compatible default


def _split_remote(url: str) -> tuple[str, str] | None:
    """Split a git remote URL into (host, 'owner/repo').

    Handles both 'git@host:owner/repo(.git)' (scp-like) and
    'https://host/owner/repo(.git)'. Returns None when it can't be parsed
    into host + slug.
    """
    rest = re.sub(r"^(https?://|git@)", "", url)
    rest = rest.replace(":", "/")
    if rest.endswith(".git"):
        rest = rest[:-4]
    parts = [p for p in rest.split("/") if p]
    if len(parts) < 3:  # need host + owner + repo
        return None
    host = parts[0]
    slug = "/".join(parts[-2:])
    return host, slug


def infer_remote(url: str) -> tuple[str, str | None]:
    """Infer (provider, repo_url) from a git remote URL.

    repo_url is a canonical 'https://<host>/<owner>/<repo>' clone URL.
    Falls back to ('github', None) when the URL can't be parsed.
    """
    parts = _split_remote(url)
    if parts is None:
        return "github", None
    host, slug = parts
    return provider_for_host(host), f"https://{host}/{slug}"


def detect_repo(
    repo: str | None = None,
    branch: str | None = None,
) -> tuple[str, str, str | None, str | None]:
    """Auto-detect repo slug and branch from git or CI env vars.

    Returns (repo_slug, branch, provider, repo_url). provider/repo_url are
    inferred from the git remote when the slug is auto-detected, else None.
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
    provider: str | None = None
    repo_url: str | None = None

    if repo_slug and branch_name:
        return repo_slug, branch_name, provider, repo_url

    if not is_inside_repo():
        raise RuntimeError(
            "Could not auto-detect Git repository. "
            "Please pass --repo and --branch explicitly."
        )

    if not repo_slug:
        try:
            remote_url = _run(["git", "remote", "get-url", "origin"])
        except subprocess.CalledProcessError:
            raise RuntimeError(
                "Could not auto-detect Git repository. "
                "Please pass --repo and --branch explicitly."
            )
        repo_slug = parse_remote(remote_url)
        provider, repo_url = infer_remote(remote_url)

    if not branch_name:
        branch_name = safe_branch()

    return repo_slug, branch_name, provider, repo_url
