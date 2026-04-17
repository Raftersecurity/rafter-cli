"""Remote source resolution and persistent cache for ``rafter skill review``.

Mirrors node/src/commands/skill/remote.ts. Accepts three shorthands and a
persistent cache, in addition to the local path / raw git URL forms already
handled by skill.py:

    github:owner/repo[/subpath]
    gitlab:owner/repo[/subpath]
    npm:<pkg>[@<version>]

Cache layout under ``~/.rafter/skill-cache/``::

    resolutions/<sha256(shorthand)>.json  -- {shorthand, sha|version, resolvedAt}
    content/<key>/                        -- extracted working tree
      meta.json                           -- {source, key, sha|version, fetchedAt}
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

DEFAULT_CACHE_TTL_MS = 24 * 60 * 60 * 1000  # 24h

SHORTHAND_KINDS = ("github", "gitlab", "npm")


@dataclass
class ParsedShorthand:
    kind: str  # "github" | "gitlab" | "npm"
    raw: str
    # git-based:
    host: str | None = None
    owner: str | None = None
    repo: str | None = None
    subpath: str | None = None
    git_url: str | None = None
    # npm-based:
    pkg: str | None = None
    version: str | None = None


def is_shorthand(input_: str) -> bool:
    return bool(re.match(r"^(github|gitlab|npm):", input_))


def parse_shorthand(input_: str) -> ParsedShorthand:
    m = re.match(r"^(github|gitlab|npm):(.+)$", input_)
    if not m:
        raise ValueError(f"Not a shorthand: {input_}")
    kind, tail = m.group(1), m.group(2)

    if kind == "npm":
        pkg = tail
        version = "latest"
        if tail.startswith("@"):
            at = tail.find("@", 1)
            if at != -1:
                pkg = tail[:at]
                version = tail[at + 1 :] or "latest"
        else:
            at = tail.find("@")
            if at != -1:
                pkg = tail[:at]
                version = tail[at + 1 :] or "latest"
        if not pkg:
            raise ValueError(f"Invalid npm shorthand: {input_}")
        return ParsedShorthand(kind=kind, raw=input_, pkg=pkg, version=version)

    parts = [p for p in tail.split("/") if p]
    if len(parts) < 2:
        raise ValueError(
            f"Invalid {kind} shorthand: expected {kind}:owner/repo[/subpath], got {input_}"
        )
    owner, repo = parts[0], parts[1]
    subpath = "/".join(parts[2:]) if len(parts) > 2 else ""
    host = "github.com" if kind == "github" else "gitlab.com"
    git_url = f"https://{host}/{owner}/{repo}.git"
    return ParsedShorthand(
        kind=kind,
        raw=input_,
        host=host,
        owner=owner,
        repo=repo,
        subpath=subpath,
        git_url=git_url,
    )


# ── Cache paths ────────────────────────────────────────────────────


def default_cache_root() -> Path:
    override = os.environ.get("RAFTER_SKILL_CACHE_DIR")
    if override:
        return Path(override)
    return Path.home() / ".rafter" / "skill-cache"


def resolution_path(cache_root: Path, shorthand: str) -> Path:
    digest = hashlib.sha256(shorthand.encode("utf-8")).hexdigest()[:40]
    return cache_root / "resolutions" / f"{digest}.json"


def content_dir(cache_root: Path, key: str) -> Path:
    return cache_root / "content" / key


def _safe_slug(input_: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", input_)[:80]


def content_key_git(parsed: ParsedShorthand, sha: str) -> str:
    owner = _safe_slug(parsed.owner or "unknown")
    repo = _safe_slug(parsed.repo or "unknown")
    return f"git-{parsed.kind}-{owner}-{repo}-{sha[:40]}"


def content_key_npm(pkg: str, version: str) -> str:
    return f"npm-{_safe_slug(pkg)}-{_safe_slug(version)}"


def content_working_tree(cache_root: Path, key: str) -> Path:
    return content_dir(cache_root, key) / "content"


# ── Resolution cache ───────────────────────────────────────────────


@dataclass
class Resolution:
    shorthand: str
    resolved_at: int  # epoch ms
    sha: str | None = None
    version: str | None = None


def read_resolution(cache_root: Path, shorthand: str) -> Resolution | None:
    fpath = resolution_path(cache_root, shorthand)
    if not fpath.exists():
        return None
    try:
        raw = json.loads(fpath.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(raw, dict):
        return None
    if not isinstance(raw.get("shorthand"), str):
        return None
    if not isinstance(raw.get("resolvedAt"), int):
        return None
    return Resolution(
        shorthand=raw["shorthand"],
        resolved_at=raw["resolvedAt"],
        sha=raw.get("sha"),
        version=raw.get("version"),
    )


def write_resolution(cache_root: Path, res: Resolution) -> None:
    fpath = resolution_path(cache_root, res.shorthand)
    fpath.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "shorthand": res.shorthand,
        "resolvedAt": res.resolved_at,
    }
    if res.sha is not None:
        payload["sha"] = res.sha
    if res.version is not None:
        payload["version"] = res.version
    fpath.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def resolution_is_fresh(r: Resolution, ttl_ms: int) -> bool:
    now_ms = int(time.time() * 1000)
    return (now_ms - r.resolved_at) < ttl_ms


# ── Content cache ──────────────────────────────────────────────────


@dataclass
class ContentMeta:
    source: str  # "git" | "npm"
    shorthand: str
    key: str
    fetched_at: int
    sha: str | None = None
    version: str | None = None


def read_content_meta(cache_root: Path, key: str) -> ContentMeta | None:
    dir_ = content_dir(cache_root, key)
    meta = dir_ / "meta.json"
    if not meta.exists():
        return None
    try:
        raw = json.loads(meta.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(raw, dict):
        return None
    if not all(
        isinstance(raw.get(k), (str, int))
        for k in ("source", "shorthand", "key", "fetchedAt")
    ):
        return None
    return ContentMeta(
        source=raw["source"],
        shorthand=raw["shorthand"],
        key=raw["key"],
        fetched_at=raw["fetchedAt"],
        sha=raw.get("sha"),
        version=raw.get("version"),
    )


def content_is_usable(cache_root: Path, key: str) -> bool:
    meta = read_content_meta(cache_root, key)
    if meta is None:
        return False
    tree = content_working_tree(cache_root, key)
    if not tree.exists():
        return False
    try:
        if not any(tree.iterdir()):
            return False
    except OSError:
        return False
    return True


def drop_cache_entry(cache_root: Path, key: str) -> None:
    d = content_dir(cache_root, key)
    shutil.rmtree(d, ignore_errors=True)


# ── Network ops (injectable for tests) ────────────────────────────


class RemoteOps(Protocol):
    def git_ls_remote_head(self, url: str) -> str: ...
    def git_clone_at_sha(self, url: str, sha: str, dest_dir: Path) -> None: ...
    def npm_fetch_metadata(self, pkg: str) -> dict[str, Any]: ...
    def npm_fetch_tarball(self, tarball_url: str, dest_file: Path) -> None: ...


class DefaultRemoteOps:
    """Default implementation of RemoteOps using git + urllib."""

    def git_ls_remote_head(self, url: str) -> str:
        r = subprocess.run(
            ["git", "ls-remote", url, "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.returncode != 0:
            raise RuntimeError(f"ls-remote {url}: {(r.stderr or 'failed').strip()}")
        line = (r.stdout or "").splitlines()[0] if r.stdout else ""
        sha = line.split()[0] if line else ""
        if not re.match(r"^[0-9a-f]{40}$", sha, re.IGNORECASE):
            raise RuntimeError(f"ls-remote {url}: could not parse SHA from '{line}'")
        return sha.lower()

    def git_clone_at_sha(self, url: str, sha: str, dest_dir: Path) -> None:
        dest_dir.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, str(dest_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if r.returncode != 0:
            raise RuntimeError(f"clone {url}: {(r.stderr or 'failed').strip()}")
        head_r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            cwd=str(dest_dir),
        )
        head = (head_r.stdout or "").strip().lower()
        if head != sha:
            fetch_r = subprocess.run(
                ["git", "fetch", "--depth", "1", "origin", sha],
                capture_output=True,
                text=True,
                cwd=str(dest_dir),
                timeout=120,
            )
            if fetch_r.returncode == 0:
                subprocess.run(
                    ["git", "checkout", "--quiet", sha],
                    capture_output=True,
                    text=True,
                    cwd=str(dest_dir),
                )

    def npm_fetch_metadata(self, pkg: str) -> dict[str, Any]:
        encoded = (
            f"@{urllib.request.quote(pkg[1:], safe='')}" if pkg.startswith("@")
            else urllib.request.quote(pkg, safe="")
        )
        url = f"https://registry.npmjs.org/{encoded}"
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read()
        return json.loads(data)

    def npm_fetch_tarball(self, tarball_url: str, dest_file: Path) -> None:
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(tarball_url, timeout=120) as resp:
            data = resp.read()
        dest_file.write_bytes(data)


DEFAULT_OPS: RemoteOps = DefaultRemoteOps()


# ── Extraction helpers ─────────────────────────────────────────────


def extract_npm_tarball(tgz_file: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tgz_file, "r:gz") as tf:
        # npm tarballs have a leading "package/" directory; strip it.
        members = []
        for member in tf.getmembers():
            name = member.name
            # Strip first path component
            parts = name.split("/", 1)
            if len(parts) < 2:
                continue
            member.name = parts[1]
            if not member.name:
                continue
            # Reject path traversal.
            if member.name.startswith("/") or ".." in member.name.split("/"):
                continue
            members.append(member)
        tf.extractall(dest_dir, members=members)  # noqa: S202


# ── Multi-SKILL.md discovery ───────────────────────────────────────


@dataclass
class SkillLocation:
    file: Path  # absolute path to SKILL.md
    dir: Path  # containing directory (audit scope)
    rel_dir: str  # relative to walk root


_SKILL_WALK_SKIP = {".git", "node_modules", ".venv", "__pycache__"}
_SKILL_WALK_MAX = 5000


def find_skill_files(root: Path) -> list[SkillLocation]:
    if not root.exists() or not root.is_dir():
        return []
    out: list[SkillLocation] = []
    visited = 0
    # Use os.walk but prune dirs.
    for dirpath, dirnames, filenames in os.walk(root):
        # In-place prune so os.walk skips unwanted subtrees.
        dirnames[:] = sorted(d for d in dirnames if d not in _SKILL_WALK_SKIP)
        filenames.sort()
        for fname in filenames:
            visited += 1
            if visited > _SKILL_WALK_MAX:
                return out
            if fname.lower() == "skill.md":
                abs_dir = Path(dirpath)
                rel = str(abs_dir.relative_to(root)) or "."
                out.append(
                    SkillLocation(file=abs_dir / fname, dir=abs_dir, rel_dir=rel)
                )
    out.sort(key=lambda s: s.rel_dir)
    return out


# ── Convenience helpers ────────────────────────────────────────────


def parse_cache_ttl(raw: str) -> int:
    m = re.match(r"^(\d+)\s*([smhd]?)$", str(raw).strip(), re.IGNORECASE)
    if not m:
        raise ValueError(f"Invalid --cache-ttl: {raw} (try 24h / 30m / 3600s / 1d)")
    n = int(m.group(1))
    unit = (m.group(2) or "s").lower()
    mult = {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}[unit]
    return n * mult


def _new_tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="rafter-skill-review-"))


# Type alias used by resolve_shorthand: a callable that performs cleanup of
# temp directories once the caller is finished with the resolved content.
CleanupFn = Callable[[], None]


@dataclass
class ResolvedSource:
    kind: str  # "github" | "gitlab" | "npm"
    resolved_path: Path  # where to audit
    tree_root: Path  # root of fetched content (for multi-skill discovery)
    source: dict[str, Any]  # provenance info for target.source
    cleanup: CleanupFn | None


def resolve_shorthand(
    input_: str,
    parsed: ParsedShorthand,
    *,
    no_cache: bool = False,
    cache_ttl_ms: int = DEFAULT_CACHE_TTL_MS,
    cache_root: Path | None = None,
    ops: RemoteOps | None = None,
) -> ResolvedSource:
    cache_root = cache_root or default_cache_root()
    ops = ops or DEFAULT_OPS
    if parsed.kind == "npm":
        return _resolve_npm(input_, parsed, no_cache, cache_ttl_ms, cache_root, ops)
    return _resolve_git(input_, parsed, no_cache, cache_ttl_ms, cache_root, ops)


def _resolve_git(
    input_: str,
    parsed: ParsedShorthand,
    no_cache: bool,
    cache_ttl_ms: int,
    cache_root: Path,
    ops: RemoteOps,
) -> ResolvedSource:
    sha: str | None = None
    if not no_cache:
        r = read_resolution(cache_root, input_)
        if r and resolution_is_fresh(r, cache_ttl_ms) and r.sha:
            sha = r.sha
    if sha is None:
        sha = ops.git_ls_remote_head(parsed.git_url or "")
        if not no_cache:
            write_resolution(
                cache_root,
                Resolution(shorthand=input_, sha=sha, resolved_at=int(time.time() * 1000)),
            )

    key = content_key_git(parsed, sha)
    cache_hit = False
    cleanup: CleanupFn | None = None

    if not no_cache and content_is_usable(cache_root, key):
        tree_root = content_working_tree(cache_root, key)
        cache_hit = True
    else:
        if not no_cache:
            drop_cache_entry(cache_root, key)
        if no_cache:
            tree_root = _new_tmp()

            def _cleanup() -> None:
                shutil.rmtree(tree_root, ignore_errors=True)

            cleanup = _cleanup
            ops.git_clone_at_sha(parsed.git_url or "", sha, tree_root)
        else:
            d = content_dir(cache_root, key)
            d.mkdir(parents=True, exist_ok=True)
            tree_root = content_working_tree(cache_root, key)
            ops.git_clone_at_sha(parsed.git_url or "", sha, tree_root)
            meta = {
                "source": "git",
                "shorthand": input_,
                "key": key,
                "sha": sha,
                "fetchedAt": int(time.time() * 1000),
            }
            (d / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    subpath = parsed.subpath or ""
    resolved_path = tree_root
    if subpath:
        candidate = tree_root / subpath
        if not candidate.exists():
            if cleanup:
                cleanup()
            raise RuntimeError(
                f"Subpath not found in {parsed.kind}:{parsed.owner}/{parsed.repo}: {subpath}"
            )
        resolved_path = candidate
    return ResolvedSource(
        kind=parsed.kind,
        resolved_path=resolved_path,
        tree_root=resolved_path,
        source={
            "url": parsed.git_url,
            "sha": sha,
            "subpath": subpath or None,
            "cacheHit": cache_hit,
        },
        cleanup=cleanup,
    )


def _resolve_npm(
    input_: str,
    parsed: ParsedShorthand,
    no_cache: bool,
    cache_ttl_ms: int,
    cache_root: Path,
    ops: RemoteOps,
) -> ResolvedSource:
    resolved_version: str | None = None
    tarball_url: str | None = None

    if not no_cache:
        r = read_resolution(cache_root, input_)
        if r and resolution_is_fresh(r, cache_ttl_ms) and r.version:
            resolved_version = r.version

    # If we don't have a resolved version OR the content cache for that version
    # is missing, we MUST fetch metadata (to find the tarball URL).
    need_metadata = resolved_version is None or (
        not no_cache
        and not content_is_usable(cache_root, content_key_npm(parsed.pkg or "", resolved_version))
    )
    if need_metadata:
        meta = ops.npm_fetch_metadata(parsed.pkg or "")
        want = parsed.version or "latest"
        concrete: str | None = None
        dist_tags = meta.get("dist-tags") if isinstance(meta, dict) else None
        if want == "latest" and isinstance(dist_tags, dict):
            concrete = dist_tags.get("latest")
        elif isinstance(dist_tags, dict) and want in dist_tags:
            concrete = dist_tags[want]
        else:
            concrete = want
        versions = meta.get("versions") if isinstance(meta, dict) else None
        if not concrete or not isinstance(versions, dict) or concrete not in versions:
            raise RuntimeError(f"npm:{parsed.pkg}: unknown version '{want}'")
        dist = versions[concrete].get("dist") if isinstance(versions[concrete], dict) else None
        if not isinstance(dist, dict) or not dist.get("tarball"):
            raise RuntimeError(f"npm:{parsed.pkg}@{concrete}: no tarball URL")
        tarball_url = dist["tarball"]
        resolved_version = concrete
        if not no_cache:
            write_resolution(
                cache_root,
                Resolution(
                    shorthand=input_,
                    version=concrete,
                    resolved_at=int(time.time() * 1000),
                ),
            )

    assert resolved_version is not None
    key = content_key_npm(parsed.pkg or "", resolved_version)
    cache_hit = False
    cleanup: CleanupFn | None = None

    if not no_cache and content_is_usable(cache_root, key):
        tree_root = content_working_tree(cache_root, key)
        cache_hit = True
    else:
        if not no_cache:
            drop_cache_entry(cache_root, key)
        if tarball_url is None:
            meta = ops.npm_fetch_metadata(parsed.pkg or "")
            versions = meta.get("versions") if isinstance(meta, dict) else None
            if isinstance(versions, dict) and resolved_version in versions:
                dist = versions[resolved_version].get("dist")
                if isinstance(dist, dict):
                    tarball_url = dist.get("tarball")
            if not tarball_url:
                raise RuntimeError(
                    f"npm:{parsed.pkg}@{resolved_version}: no tarball URL"
                )
        if no_cache:
            tree_root = _new_tmp()

            def _cleanup() -> None:
                shutil.rmtree(tree_root, ignore_errors=True)

            cleanup = _cleanup
            tgz = tree_root / "package.tgz"
            ops.npm_fetch_tarball(tarball_url, tgz)
            extract_npm_tarball(tgz, tree_root)
            try:
                tgz.unlink()
            except OSError:
                pass
        else:
            d = content_dir(cache_root, key)
            d.mkdir(parents=True, exist_ok=True)
            tree_root = content_working_tree(cache_root, key)
            tree_root.mkdir(parents=True, exist_ok=True)
            tgz = d / "package.tgz"
            ops.npm_fetch_tarball(tarball_url, tgz)
            extract_npm_tarball(tgz, tree_root)
            try:
                tgz.unlink()
            except OSError:
                pass
            meta_obj = {
                "source": "npm",
                "shorthand": input_,
                "key": key,
                "version": resolved_version,
                "fetchedAt": int(time.time() * 1000),
            }
            (d / "meta.json").write_text(
                json.dumps(meta_obj, indent=2), encoding="utf-8"
            )

    return ResolvedSource(
        kind="npm",
        resolved_path=tree_root,
        tree_root=tree_root,
        source={
            "url": tarball_url,
            "version": resolved_version,
            "cacheHit": cache_hit,
        },
        cleanup=cleanup,
    )
