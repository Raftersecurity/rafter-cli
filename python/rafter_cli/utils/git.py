"""Git utility functions."""
from __future__ import annotations

import re
import subprocess
from urllib.parse import urlsplit


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
    """Return the current branch name.

    Raises RuntimeError on a detached HEAD (or when there is no HEAD at
    all, e.g. an empty repo) instead of falling back to a commit SHA or a
    hardcoded default branch. Neither is a real branch: a SHA is guaranteed
    to 404 as a "branch" on the backend, and a hardcoded default is a guess
    that is often wrong and, even when right, doesn't reflect what is
    actually checked out.
    """
    try:
        return _run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"])
    except subprocess.CalledProcessError:
        raise RuntimeError(
            "Could not determine the current branch (detached HEAD or no "
            "commits yet). Please pass --branch explicitly."
        )


_SCHEME_RE = re.compile(r"^(https?|ssh)://", re.IGNORECASE)


def _split_remote(url: str) -> tuple[str, str] | None:
    """Split a git remote URL into (host, 'owner/repo').

    Handles 'https://[user[:token]@]host[:port]/owner/repo(.git)' (and
    http, ssh), and the scp-like '[user@]host:owner/repo(.git)'. Returns
    None when it can't be parsed into host + slug.

    Uses urlsplit (not a blanket ':' -> '/' substitution) so that a colon
    inside userinfo -- 'https://user:token@host/...', a real shape for
    CI-embedded credentials -- is never mistaken for the scp host:path
    separator. Getting this wrong is a security bug, not just a parsing
    one: the naive substitution let 'https://github.com:x@evil.com/a/b'
    read as host 'github.com' (an allowed host) with the real host,
    evil.com, silently discarded.
    """
    if _SCHEME_RE.match(url):
        parsed = urlsplit(url)
        host = parsed.hostname
        if not host:
            return None
        rest = f"{host}{parsed.path}"
    elif ":" in url:
        # scp-like: '[user@]host:owner/repo(.git)'. The user (if any) is
        # whatever precedes the LAST '@' before this colon.
        head, _, path = url.partition(":")
        host = head.rsplit("@", 1)[-1]
        if not host or "/" in host:
            return None
        rest = f"{host}/{path}"
    else:
        # No scheme, no ':' -- e.g. a bare filesystem path. Treated
        # opaquely: the leading segment stands in for "host" below, so it
        # is rejected unless it happens to equal a real host (it never
        # will for a real filesystem path).
        rest = url

    if rest.endswith(".git"):
        rest = rest[:-4]
    parts = [p for p in rest.split("/") if p]
    if len(parts) < 3:  # need host + owner + repo
        return None
    host = parts[0]
    slug = "/".join(parts[-2:])
    return host, slug


def _known_provider_for_host(host: str) -> str | None:
    """Map a git remote host to a provider we actually recognize.

    Unlike provider_for_host, returns None for a host we don't recognize
    instead of defaulting to 'github' -- used where guessing is not safe.
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
    return None


def parse_remote(url: str) -> str:
    """Parse a git remote URL into 'owner/repo' format.

    Raises RuntimeError when the remote's host isn't one we recognize.
    Blindly slicing the last two path segments of an arbitrary URL (the
    old behavior) manufactures a wrong slug for anything that isn't
    GitHub/GitLab/Bitbucket/Gitea shaped -- e.g. an Azure DevOps remote
    ('.../org/proj/_git/repo') becomes '_git/repo', and a bare filesystem
    remote becomes '<parent-dir>/<repo>'. The backend turns that slug into
    an invalid clone URL and 404s, burning a paid scan.
    """
    parts = _split_remote(url)
    if parts is None:
        raise RuntimeError(
            f"Could not determine owner/repo from git remote {url!r}. "
            "Please pass --repo and --branch explicitly."
        )
    host, slug = parts
    if _known_provider_for_host(host) is None:
        raise RuntimeError(
            f"Unsupported git remote host {host!r} (from {url!r}). "
            "Only GitHub, GitLab, Bitbucket, and Gitea remotes are "
            "auto-detected. Please pass --repo and --branch explicitly."
        )
    return slug


def provider_for_host(host: str) -> str:
    """Map a git remote host to a provider.

    'github' is the backward-compatible default for any host we don't
    recognize — a GitHub user's request is unaffected, and unknown
    self-hosted hosts fall back to the legacy behavior. (Only used for the
    additive provider/repo_url fields; parse_remote uses the stricter
    _known_provider_for_host and rejects what this would silently default.)
    """
    return _known_provider_for_host(host) or "github"


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
