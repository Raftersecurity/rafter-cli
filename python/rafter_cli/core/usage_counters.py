"""Local-only usage counters (``~/.rafter/usage/<YYYY-MM-DD>.json``).

Counts are keyed by allowlisted enums, counts and duration buckets only; the
allowlist is shared-docs/usage-counters.json, embedded below and checked
against that file by a test. Nothing here touches the network: the counters
stay on this machine until a person pastes ``rafter telemetry show`` output
somewhere.

Recorders only add to an in-memory buffer; the buffer is written once, when
the process exits, by one read-modify-write of a tiny file (temp file +
rename). Concurrent rafter processes can therefore lose each other's
increments (last rename wins); they never leave a torn file, and an unreadable
file is replaced. Every entry point swallows its own errors and none writes to
stdout.

Mirrors node/src/core/usage-counters.ts. Deleting this file, its Node twin, the
two ``telemetry`` command files and their one-line call sites removes the
feature.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config_schema import get_config_path, get_rafter_dir

USAGE_SCHEMA = 1

#: Same values as shared-docs/usage-counters.json (minus its prose description).
USAGE_ALLOWLIST: dict[str, Any] = {
    "schema": 1,
    "families": {
        "unknown_command": ["unknown_command"],
        "unknown_option": ["unknown_option"],
        "command": ["command_path", "literal:exit", "exit"],
        "hook": ["hook_tool", "hook_decision", "hook_risk"],
        "scan_engine": ["scan_engine", "scan_engine"],
        "scan_fallback": ["scan_fallback"],
        "scan_duration": ["scan_engine", "duration_bucket"],
        "error_class": ["command_path", "error_class"],
    },
    "patterns": {
        "unknown_command": "^[a-z][a-z-]{0,31}$",
        "unknown_option": "^--[a-z][a-z-]{0,31}$",
        "command_path": "^[a-z][a-z0-9-]{0,31}(\\.[a-z][a-z0-9-]{0,31}){0,3}$",
        "error_class": "^([A-Z][A-Za-z0-9]{0,29})?(Error|Exception|Exit|Interrupt)$",
    },
    "pattern_fallback": "other",
    "enums": {
        "exit": ["0", "1", "2", "other"],
        "hook_tool": ["shell", "write", "other"],
        "hook_decision": ["allow", "deny", "defer", "ask", "error"],
        "hook_risk": ["low", "medium", "high", "critical", "none"],
        "scan_engine": ["auto", "betterleaks", "patterns", "both"],
        "scan_fallback": ["missing", "timeout", "error", "stale", "other"],
        "duration_bucket": ["lt1s", "1-5s", "5-30s", "30-120s", "gt120s"],
    },
    "duration_bucket_edges_seconds": [1, 5, 30, 120],
    "retention_days": 7,
}

USAGE_FAMILIES: list[str] = list(USAGE_ALLOWLIST["families"])
USAGE_STORE_DISPLAY = "~/.rafter/usage"
USAGE_NOTICE = "Nothing leaves this machine: these counts are stored locally and rafter has no code to upload them."

# re.ASCII so [A-Za-z0-9] means the same as in JavaScript; fullmatch so "$"
# cannot accept a trailing newline.
_PATTERNS = {k: re.compile(v, re.ASCII) for k, v in USAGE_ALLOWLIST["patterns"].items()}
_FALLBACK = USAGE_ALLOWLIST["pattern_fallback"]


def _patterned(kind: str, value: object) -> str:
    return value if isinstance(value, str) and _PATTERNS[kind].fullmatch(value) else _FALLBACK


def _part_allowed(spec: str, part: str) -> bool:
    if spec.startswith("literal:"):
        return part == spec[len("literal:"):]
    if spec in USAGE_ALLOWLIST["enums"]:
        return part in USAGE_ALLOWLIST["enums"][spec]
    if spec in _PATTERNS:
        return part == _FALLBACK or bool(_PATTERNS[spec].fullmatch(part))
    return False


def is_allowed_key(key: object) -> bool:
    """True if every part of ``key`` is built from the allowlist."""
    if not isinstance(key, str):
        return False
    family, *parts = key.split(":")
    spec = USAGE_ALLOWLIST["families"].get(family)
    if not spec or len(parts) != len(spec):
        return False
    return all(_part_allowed(s, p) for s, p in zip(spec, parts))


# ── in-memory buffer ────────────────────────────────────────────────

_pending: dict[str, int] = {}
_command_path: str | None = None
_discarded = False


def _bump(key: str) -> None:
    if _discarded or not is_allowed_key(key):
        return
    _pending[key] = _pending.get(key, 0) + 1


def pending_counts() -> dict[str, int]:
    """Test hook: the keys buffered so far."""
    return dict(_pending)


def reset_pending() -> None:
    """Test hook: forget buffered counts and the command path."""
    global _command_path, _discarded
    _pending.clear()
    _command_path = None
    _discarded = False


def discard_pending() -> None:
    """Drop everything buffered and stop counting for this process (``telemetry clear``)."""
    global _discarded
    _pending.clear()
    _discarded = True


# ── recorders (each swallows its own errors) ────────────────────────


@dataclass
class Vocabulary:
    """The CLI's own names, derived from its registered command tree: every
    command name, every long option, and the ``-``-separated words of all of
    them. No hand-maintained list."""
    commands: list[str]
    options: list[str]
    words: set[str]


# Injected by typer, not registered by rafter; Node offers completion as a
# command instead, so leaving these out keeps both vocabularies the same.
_FRAMEWORK_OPTIONS = frozenset({"--install-completion", "--show-completion"})


def vocabulary_of(root: Any) -> Vocabulary:
    commands: set[str] = set()
    options: set[str] = set()

    def visit(cmd: Any) -> None:
        for p in getattr(cmd, "params", None) or []:
            # A click on/off pair (``--x/--no-x``) is registered in Node as
            # ``--no-x`` alone; count only that form so both trees match.
            secondary = list(getattr(p, "secondary_opts", []))
            for o in secondary or list(getattr(p, "opts", [])):
                if o.startswith("--") and o not in _FRAMEWORK_OPTIONS:
                    options.add(o)
        for name, sub in (getattr(cmd, "commands", None) or {}).items():
            commands.add(name)
            visit(sub)

    visit(root)
    words = {w for n in [*commands, *(o[2:] for o in options)] for w in n.split("-") if w}
    return Vocabulary(sorted(commands), sorted(options), words)


def edit_distance(a: str, b: str) -> int:
    """Optimal-string-alignment (restricted Damerau-Levenshtein) distance."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def _plausible(token: str, candidates: list[str], words: set[str], prefix: str) -> bool:
    """Near a registered name (distance <= 2), or built entirely from the CLI's own words."""
    if any(abs(len(c) - len(token)) <= 2 and edit_distance(token, c) <= 2 for c in candidates):
        return True
    return all(p and p in words for p in token[len(prefix):].split("-"))


def _vetted(kind: str, token: object, vocab: Vocabulary | None) -> str:
    v = _patterned(kind, token)
    if v == _FALLBACK or vocab is None:
        return _FALLBACK
    if kind == "unknown_command":
        return v if _plausible(v, vocab.commands, vocab.words, "") else _FALLBACK
    return v if _plausible(v, vocab.options, vocab.words, "--") else _FALLBACK


def count_unknown_command(token: object, vocab: Vocabulary | None = None) -> None:
    try:
        _bump(f"unknown_command:{_vetted('unknown_command', token, vocab)}")
    except Exception:
        pass


def count_unknown_option(flag: object, vocab: Vocabulary | None = None) -> None:
    try:
        name = flag.split("=")[0] if isinstance(flag, str) else flag
        _bump(f"unknown_option:{_vetted('unknown_option', name, vocab)}")
    except Exception:
        pass


def set_command_path(names: list[str], vocab: "Vocabulary | None") -> None:
    """Set the resolved command path from registered command names (not argv).
    A name that is not in the vocabulary makes the whole path ``other``."""
    global _command_path
    try:
        if not names:
            _command_path = "root"
        elif vocab is None or not all(n in vocab.commands for n in names):
            _command_path = _FALLBACK
        else:
            _command_path = _patterned("command_path", ".".join(names))
    except Exception:
        pass


def _current_path() -> str:
    return _command_path or "root"


def exit_bucket(code: object) -> str:
    return str(code) if code in (0, 1, 2) and not isinstance(code, bool) else "other"


def count_hook(tool: object, decision: object, risk: object) -> None:
    try:
        e = USAGE_ALLOWLIST["enums"]
        t = tool if tool in e["hook_tool"] else "other"
        d = decision if decision in e["hook_decision"] else "error"
        r = risk if risk in e["hook_risk"] else "none"
        _bump(f"hook:{t}:{d}:{r}")
    except Exception:
        pass


def classify_fallback(reason: object) -> str:
    """Map a free-text fall-back reason onto the enum. The text itself is never stored."""
    s = reason.lower() if isinstance(reason, str) else ""
    if re.search(r"timed out|timeout", s):
        return "timeout"
    if re.search(r"stale|update", s):
        return "stale"
    if re.search(r"not available|unavailable|not found|missing|enoent", s):
        return "missing"
    if re.search(r"fail|error|crash|exit", s):
        return "error"
    return "other"


def duration_bucket(seconds: float) -> str:
    a, b, c, d = USAGE_ALLOWLIST["duration_bucket_edges_seconds"]
    if seconds < a:
        return "lt1s"
    if seconds < b:
        return "1-5s"
    if seconds < c:
        return "5-30s"
    if seconds < d:
        return "30-120s"
    return "gt120s"


def count_scan(report: Any, elapsed_s: float) -> None:
    """Record one local scan from its EngineReport and elapsed seconds."""
    try:
        if report is None:
            return
        _bump(f"scan_engine:{report.requested}:{report.used}")
        if report.degraded:
            _bump(f"scan_fallback:{classify_fallback(report.reason)}")
        _bump(f"scan_duration:{report.used}:{duration_bucket(elapsed_s)}")
    except Exception:
        pass


def count_error(exc: BaseException) -> None:
    """Record an uncaught error by class name only."""
    try:
        _bump(f"error_class:{_current_path()}:{_patterned('error_class', type(exc).__name__)}")
    except Exception:
        pass


# ── settings ────────────────────────────────────────────────────────


def usage_status(env: dict | None = None) -> tuple[bool, str]:
    """Whether counting is on, and why: ``default`` | ``config`` |
    ``env:RAFTER_TELEMETRY`` | ``env:DO_NOT_TRACK``.

    Read only from the environment and the global ~/.rafter/config.json
    (``agent.usage.enabled``); a project .rafter.yml is never consulted.
    """
    env = os.environ if env is None else env
    rt = (env.get("RAFTER_TELEMETRY") or "").strip().lower()
    if rt in ("0", "false", "off"):
        return False, "env:RAFTER_TELEMETRY"
    dnt = (env.get("DO_NOT_TRACK") or "").strip().lower()
    if dnt not in ("", "0", "false"):
        return False, "env:DO_NOT_TRACK"
    try:
        cfg = json.loads(get_config_path().read_text(encoding="utf-8"))
        v = ((cfg.get("agent") or {}).get("usage") or {}).get("enabled")
        if v is False:
            return False, "config"
        if v is True:
            return True, "config"
    except Exception:
        pass  # missing or unreadable config: the default applies
    return True, "default"


# ── store ───────────────────────────────────────────────────────────


def usage_dir() -> Path:
    return get_rafter_dir() / "usage"


def utc_day(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%Y-%m-%d")


_DAY_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.json$", re.ASCII)


def _read_day(file: Path) -> dict[str, int]:
    """Allowlisted, positive-integer counts from one day file; {} if missing or corrupt."""
    out: dict[str, int] = {}
    try:
        raw = json.loads(file.read_text(encoding="utf-8"))
    except Exception:
        return out
    if not isinstance(raw, dict) or raw.get("schema") != USAGE_SCHEMA:
        return out
    for k, v in raw.items():
        if k != "schema" and is_allowed_key(k) and type(v) is int and 0 < v <= 2**53 - 1:
            out[k] = v
    return out


def _prune(directory: Path, today: str) -> None:
    keep = USAGE_ALLOWLIST["retention_days"]
    oldest = (datetime.strptime(today, "%Y-%m-%d") - timedelta(days=keep - 1)).strftime("%Y-%m-%d")
    for entry in directory.iterdir():
        try:
            m = _DAY_FILE.match(entry.name)
            if m and m.group(1) < oldest:
                entry.unlink()
            elif entry.name.endswith(".tmp") and time.time() - entry.stat().st_mtime > 60:
                entry.unlink()
        except OSError:
            pass


def write_counts(counts: dict[str, int], now: datetime | None = None) -> None:
    """Add ``counts`` to today's file. Raises on I/O failure; callers guard."""
    if not counts:
        return
    now = now or datetime.now(timezone.utc)
    directory = usage_dir()
    directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.mkdir(mode=0o700, exist_ok=True)
    day = utc_day(now)
    file = directory / f"{day}.json"
    first_today = not file.exists()
    merged = _read_day(file)
    for k, n in counts.items():
        if is_allowed_key(k) and type(n) is int and n > 0:
            merged[k] = merged.get(k, 0) + n
    body: dict[str, int] = {"schema": USAGE_SCHEMA}
    for k in sorted(merged):
        body[k] = merged[k]
    tmp = directory / f".{day}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(body, indent=2) + "\n")
        os.replace(tmp, file)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    if first_today:
        try:
            directory.chmod(0o700)
        except OSError:
            pass
        _prune(directory, day)


def flush(exit_code: object) -> None:
    """Record the command result and write the buffer, if counting is enabled.
    Called once, at process exit."""
    try:
        if _discarded:
            return
        _bump(f"command:{_current_path()}:exit:{exit_bucket(exit_code)}")
        if not usage_status()[0]:
            return
        write_counts(_pending)
        _pending.clear()
    except Exception:
        pass


def read_counters(days: int, now: datetime | None = None) -> tuple[str, dict[str, dict[str, int]]]:
    """Sum the last ``days`` daily files (today included), grouped by family."""
    now = now or datetime.now(timezone.utc)
    counters: dict[str, dict[str, int]] = {f: {} for f in USAGE_FAMILIES}
    today = datetime.strptime(utc_day(now), "%Y-%m-%d")
    since = utc_day(now)
    for i in range(days):
        day = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        since = day
        for k, n in _read_day(usage_dir() / f"{day}.json").items():
            fam = counters[k.split(":")[0]]
            fam[k] = fam.get(k, 0) + n
    return since, {f: dict(sorted(counters[f].items())) for f in USAGE_FAMILIES}


def clear_store() -> bool:
    """Delete the usage directory. Returns whether it existed."""
    directory = usage_dir()
    existed = directory.exists()
    shutil.rmtree(directory, ignore_errors=True)
    return existed


# ── click / typer wiring ────────────────────────────────────────────


def _registered_path(ctx: Any) -> list[str]:
    names: list[str] = []
    while ctx is not None and ctx.parent is not None:
        names.insert(0, ctx.command.name or "")
        ctx = ctx.parent
    return names


_NO_SUCH_COMMAND = re.compile(r"No such command (['\"])(.*?)\1")


def track_click_tree(root_ctx: Any) -> None:
    """Record the resolved command path from the registered command tree.

    Called from the root callback, which click runs before it builds any
    subcommand context, so wrapping each command object's ``make_context``
    here sees the leaf the CLI actually dispatches to.
    """
    try:
        seen: set[int] = set()
        vocab = vocabulary_of(root_ctx.command)

        def visit(cmd: Any) -> None:
            if id(cmd) in seen:
                return
            seen.add(id(cmd))
            original = cmd.make_context

            def make_context(*args: Any, **kwargs: Any) -> Any:
                sub = original(*args, **kwargs)
                set_command_path(_registered_path(sub), vocab)
                return sub

            cmd.make_context = make_context
            for sub in (getattr(cmd, "commands", None) or {}).values():
                visit(sub)

        set_command_path([], vocab)
        for sub in (getattr(root_ctx.command, "commands", None) or {}).values():
            visit(sub)
    except Exception:
        pass


def note_system_exit(exc: SystemExit) -> None:
    """Count a usage error (unknown command or option) behind a SystemExit.

    Typer handles click's UsageError by printing it and calling ``sys.exit``
    inside the ``except`` block, so the UsageError is the SystemExit's
    ``__context__``. Matched by class name, not identity: newer typer ships
    its own copy of click (``typer._click``), so ``click.UsageError`` is a
    different class there.
    """
    try:
        err = exc.__context__
        names = {k.__name__ for k in type(err).__mro__}
        if "UsageError" not in names:
            return
        ctx = getattr(err, "ctx", None)
        if ctx is None:
            return
        vocab = vocabulary_of(ctx.find_root().command)
        set_command_path(_registered_path(ctx), vocab)
        if "NoSuchOption" in names:
            count_unknown_option(err.option_name, vocab)
            return
        m = _NO_SUCH_COMMAND.search(getattr(err, "message", "") or "")
        if m:
            count_unknown_command(m.group(2), vocab)
    except Exception:
        pass


def run_app(app: Any) -> None:
    """Run the typer app with counting around it: usage errors, uncaught
    errors by class, and one flush with the final exit code."""
    code: object = 0
    try:
        app()
    except SystemExit as exc:
        code = 0 if exc.code is None else exc.code
        note_system_exit(exc)
        raise
    except BaseException as exc:
        code = 1
        if not isinstance(exc, KeyboardInterrupt):
            count_error(exc)
        raise
    finally:
        flush(code)
