"""Resolve, fetch, and cache repo-specific security docs from .rafter.yml."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.error import URLError
from urllib.request import Request, urlopen

from ..utils.git import get_git_root
from .config_schema import get_rafter_dir
from .policy_loader import load_policy


DEFAULT_TTL_SECONDS = 86400
_FETCH_TIMEOUT = 15


@dataclass
class ResolvedDoc:
    id: str
    source: str
    source_kind: str  # "path" | "url"
    description: str
    tags: list[str]
    cache_status: str  # "local" | "cached" | "not-cached" | "stale"
    ttl_seconds: int | None = None


@dataclass
class FetchResult:
    content: str
    cached: bool
    stale: bool
    source: str
    source_kind: str


def _cache_dir() -> Path:
    return get_rafter_dir() / "docs-cache"


def _cache_key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]


def _cache_paths(url: str) -> tuple[Path, Path]:
    base = _cache_dir() / _cache_key(url)
    return base.with_suffix(".txt"), base.with_suffix(".meta.json")


def _read_cache(url: str) -> tuple[str, float] | None:
    content_path, meta_path = _cache_paths(url)
    if not content_path.exists() or not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text())
        body = content_path.read_text()
        fetched_at_str = meta.get("fetched_at", "")
        # Parse ISO timestamp (simple fallback using fromisoformat)
        from datetime import datetime
        dt = datetime.fromisoformat(fetched_at_str.replace("Z", "+00:00"))
        return body, dt.timestamp()
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _write_cache(url: str, body: str, content_type: str) -> None:
    from datetime import datetime, timezone
    cache_dir = _cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    content_path, meta_path = _cache_paths(url)
    content_path.write_text(body)
    meta_path.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "content_type": content_type,
    }, indent=2) + "\n")


def _is_expired(fetched_at: float, ttl_seconds: int) -> bool:
    return (time.time() - fetched_at) > ttl_seconds


def _resolve_policy_path(relative: str) -> Path:
    p = Path(relative)
    if p.is_absolute():
        return p
    root = get_git_root() or os.getcwd()
    return Path(root) / p


def list_docs(entries: Iterable[dict] | None = None) -> list[ResolvedDoc]:
    """List docs from the active policy with resolution metadata. No network I/O."""
    if entries is None:
        policy = load_policy() or {}
        entries = policy.get("docs") or []

    resolved: list[ResolvedDoc] = []
    for entry in entries:
        doc_id = entry["id"]
        description = entry.get("description", "")
        tags = list(entry.get("tags") or [])
        if "path" in entry:
            resolved.append(ResolvedDoc(
                id=doc_id,
                source=entry["path"],
                source_kind="path",
                description=description,
                tags=tags,
                cache_status="local",
            ))
            continue
        url = entry["url"]
        ttl = (entry.get("cache") or {}).get("ttl_seconds", DEFAULT_TTL_SECONDS)
        cached = _read_cache(url)
        if cached is None:
            status = "not-cached"
        else:
            status = "stale" if _is_expired(cached[1], ttl) else "cached"
        resolved.append(ResolvedDoc(
            id=doc_id,
            source=url,
            source_kind="url",
            description=description,
            tags=tags,
            cache_status=status,
            ttl_seconds=ttl,
        ))
    return resolved


def resolve_doc_selector(selector: str, entries: Iterable[dict] | None = None) -> list[dict]:
    """Resolve docs matching an id (exact) or tag (any). Returns raw policy entries."""
    if entries is None:
        policy = load_policy() or {}
        entries = list(policy.get("docs") or [])
    else:
        entries = list(entries)

    for entry in entries:
        if entry.get("id") == selector:
            return [entry]
    return [e for e in entries if selector in (e.get("tags") or [])]


def fetch_doc(entry: dict, refresh: bool = False) -> FetchResult:
    """Return content for a doc entry, fetching URL docs on miss/expired/refresh."""
    if "path" in entry:
        path = _resolve_policy_path(entry["path"])
        content = path.read_text()
        return FetchResult(content=content, cached=False, stale=False,
                           source=entry["path"], source_kind="path")

    url = entry["url"]
    ttl = (entry.get("cache") or {}).get("ttl_seconds", DEFAULT_TTL_SECONDS)
    cached = _read_cache(url)
    fresh = cached is not None and not _is_expired(cached[1], ttl)

    if not refresh and fresh:
        return FetchResult(content=cached[0], cached=True, stale=False,
                           source=url, source_kind="url")

    try:
        req = Request(url, headers={"User-Agent": "rafter-cli"})
        with urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
            body_bytes = resp.read()
            content_type = resp.headers.get("content-type", "text/plain")
        body = body_bytes.decode("utf-8", errors="replace")
        _write_cache(url, body, content_type)
        return FetchResult(content=body, cached=False, stale=False,
                           source=url, source_kind="url")
    except (URLError, TimeoutError, OSError) as exc:
        if cached is not None:
            return FetchResult(content=cached[0], cached=True, stale=True,
                               source=url, source_kind="url")
        raise RuntimeError(f"Failed to fetch {url}: {exc}") from exc
