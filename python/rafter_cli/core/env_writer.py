"""Write detected secrets to a project-local .env and protect via .gitignore.

Idempotent: identical name=value entries are not duplicated; if a value is
already present under some name, that name is reused. .env is created in the
given root (typically cwd) — we don't walk up to the git root so we don't
risk writing to a .env shared with other projects.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class SecretToPersist:
    base_name: str
    value: str


@dataclass
class PersistedSecret:
    name: str
    value: str
    already_present: bool


@dataclass
class EnvWriteResult:
    env_file_path: str
    env_file_created: bool
    gitignore_path: str
    gitignore_created: bool
    gitignore_updated: bool
    written: list[PersistedSecret] = field(default_factory=list)


_INVALID_NAME_CHARS_RE = re.compile(r"[^A-Z0-9_]+")
_NEEDS_QUOTING_RE = re.compile(r"[\s=\"'#$`\\]")
_LEADING_TRAILING_UNDERSCORE_RE = re.compile(r"^_+|_+$")
_DOUBLE_UNDERSCORE_RE = re.compile(r"_+")


def persist_secrets(secrets: list[SecretToPersist], root: str | os.PathLike) -> EnvWriteResult:
    root_path = Path(root)
    env_file_path = root_path / ".env"
    gitignore_path = root_path / ".gitignore"

    env_file_created = not env_file_path.exists()
    existing: dict[str, str] = {} if env_file_created else _parse_env_file(env_file_path.read_text(encoding="utf-8"))

    value_to_existing_name: dict[str, str] = {}
    for k, v in existing.items():
        value_to_existing_name.setdefault(v, k)

    written: list[PersistedSecret] = []
    lines_to_append: list[str] = []
    seen_in_call: dict[str, str] = {}  # value -> name

    for secret in secrets:
        reuse = value_to_existing_name.get(secret.value)
        if reuse:
            written.append(PersistedSecret(name=reuse, value=secret.value, already_present=True))
            continue
        same_batch = seen_in_call.get(secret.value)
        if same_batch:
            written.append(PersistedSecret(name=same_batch, value=secret.value, already_present=True))
            continue

        name = _unique_name(secret.base_name, existing, seen_in_call)
        existing[name] = secret.value
        seen_in_call[secret.value] = name
        lines_to_append.append(f"{name}={_quote_value(secret.value)}")
        written.append(PersistedSecret(name=name, value=secret.value, already_present=False))

    if lines_to_append or env_file_created:
        header = "# Created by Rafter prompt-shield. Do not commit this file.\n" if env_file_created else ""
        existing_content = "" if env_file_created else env_file_path.read_text(encoding="utf-8")
        sep = "\n" if existing_content and not existing_content.endswith("\n") else ""
        new_content = existing_content + sep + header + "\n".join(lines_to_append) + ("\n" if lines_to_append else "")
        env_file_path.write_text(new_content, encoding="utf-8")
        # Best-effort restrictive perms; ignore on Windows / non-POSIX.
        try:
            os.chmod(env_file_path, 0o600)
        except OSError:
            pass

    gi_created, gi_updated = ensure_gitignored(gitignore_path, ".env")

    return EnvWriteResult(
        env_file_path=str(env_file_path),
        env_file_created=env_file_created,
        gitignore_path=str(gitignore_path),
        gitignore_created=gi_created,
        gitignore_updated=gi_updated,
        written=written,
    )


def ensure_gitignored(gitignore_path: str | os.PathLike, entry: str) -> tuple[bool, bool]:
    """Return (created, updated)."""
    gp = Path(gitignore_path)
    if not gp.exists():
        gp.write_text(f"{entry}\n", encoding="utf-8")
        return True, True

    content = gp.read_text(encoding="utf-8")
    if _gitignore_covers(content, entry):
        return False, False

    sep = "\n" if content and not content.endswith("\n") else ""
    gp.write_text(f"{content}{sep}{entry}\n", encoding="utf-8")
    return False, True


def _gitignore_covers(content: str, entry: str) -> bool:
    target = entry.lstrip("/").strip()
    for raw in content.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lstrip("/") == target:
            return True
        if line == "*":
            return True
    return False


def _parse_env_file(content: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in content.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        eq = line.find("=")
        if eq <= 0:
            continue
        name = line[:eq].strip()
        value = line[eq + 1:].strip()
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        out[name] = value
    return out


def _unique_name(base: str, existing: dict[str, str], pending: dict[str, str]) -> str:
    sanitized = _sanitize_name(base)
    pending_names = set(pending.values())
    if sanitized not in existing and sanitized not in pending_names:
        return sanitized
    for i in range(1, 1000):
        candidate = f"{sanitized}_{i}"
        if candidate not in existing and candidate not in pending_names:
            return candidate
    import time
    return f"{sanitized}_{int(time.time())}"


def _sanitize_name(base: str) -> str:
    cleaned = _INVALID_NAME_CHARS_RE.sub("_", base.upper())
    cleaned = _LEADING_TRAILING_UNDERSCORE_RE.sub("", cleaned)
    cleaned = _DOUBLE_UNDERSCORE_RE.sub("_", cleaned)
    if not cleaned:
        return "RAFTER_SECRET"
    if cleaned[0].isdigit():
        return f"RAFTER_{cleaned}"
    return cleaned


def _quote_value(value: str) -> str:
    if _NEEDS_QUOTING_RE.search(value):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return value
