"""Betterleaks scanner — wraps system betterleaks binary."""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import NamedTuple

from ..core.pattern_engine import Pattern, PatternMatch
from ..utils.binary_manager import BinaryManager

# Per-invocation timeout for the betterleaks subprocess.
SCAN_TIMEOUT_S = 60

# Budget for the path arguments of one `betterleaks dir` call. Windows caps a
# whole command line at 32,767 characters; elsewhere the limit is far larger.
ARG_CHARS_PER_CALL = 24_000 if sys.platform == "win32" else 500_000

# Config env vars betterleaks consults before the target's own .toml.
CONFIG_ENV_VARS = (
    "BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML",
)


def git_visible_files(dir_path: str) -> list[str] | None:
    """Files under ``dir_path`` that git does not ignore (tracked, plus
    untracked and not ignored), as absolute paths. Returns None when
    ``dir_path`` is not inside a git work tree or git is unavailable, so the
    caller scans the directory whole. Mirrors ``gitVisibleFiles`` in
    node/src/scanners/betterleaks.ts.
    """
    try:
        r = subprocess.run(
            ["git", "-C", dir_path, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "."],
            capture_output=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    files: dict[str, None] = {}
    for rel in r.stdout.decode("utf-8", "surrogateescape").split("\0"):
        if not rel:
            continue
        abs_path = os.path.join(dir_path, rel)
        # Skip deleted-but-tracked paths, submodule dirs and symlinks
        # (betterleaks does not follow symlinks by default either).
        if os.path.isfile(abs_path) and not os.path.islink(abs_path):
            files[abs_path] = None
    return list(files)


def _chunk_by_length(paths: list[str], budget: int) -> list[list[str]]:
    """Split ``paths`` into groups whose joined length stays under ``budget``."""
    chunks: list[list[str]] = []
    cur: list[str] = []
    length = 0
    for p in paths:
        if cur and length + len(p) + 1 > budget:
            chunks.append(cur)
            cur, length = [], 0
        cur.append(p)
        length += len(p) + 1
    if cur:
        chunks.append(cur)
    return chunks


@dataclass
class BetterleaksScanResult:
    file: str
    matches: list[PatternMatch] = field(default_factory=list)


class BetterleaksCheckResult(NamedTuple):
    available: bool
    stdout: str
    stderr: str
    error: str  # OSError / timeout message, empty on success


class BetterleaksScanner:
    def __init__(self) -> None:
        self._binary_manager = BinaryManager()
        # Prefer managed binary, fall back to system PATH
        if self._binary_manager.is_betterleaks_installed():
            self._path: str | None = str(self._binary_manager.get_betterleaks_path())
        else:
            self._path = self._binary_manager.find_betterleaks_on_path()

    def is_available(self) -> bool:
        return self.check().available

    def check(self) -> BetterleaksCheckResult:
        """Run 'betterleaks version' and return structured result with captured output."""
        if not self._path:
            return BetterleaksCheckResult(
                available=False, stdout="", stderr="",
                error="betterleaks not found (not installed via rafter and not on PATH)",
            )
        try:
            result = subprocess.run(
                [self._path, "version"],
                capture_output=True, text=True, timeout=5,
            )
            ok = result.returncode == 0
            return BetterleaksCheckResult(
                available=ok,
                stdout=result.stdout.strip(),
                stderr=result.stderr.strip(),
                error="" if ok else f"exit code {result.returncode}",
            )
        except subprocess.TimeoutExpired:
            return BetterleaksCheckResult(available=False, stdout="", stderr="", error="timed out")
        except (OSError, FileNotFoundError) as exc:
            return BetterleaksCheckResult(available=False, stdout="", stderr="", error=str(exc))

    @staticmethod
    def collect_diagnostics(binary_path: str | None = None) -> str:
        """Collect OS/arch/libc context to help diagnose why a binary fails."""
        lines: list[str] = []

        if binary_path:
            try:
                result = subprocess.run(
                    ["file", binary_path], capture_output=True, text=True, timeout=5
                )
                lines.append(f"  file: {result.stdout.strip()}")
            except Exception:
                lines.append("  file: (unavailable)")

        try:
            result = subprocess.run(
                ["uname", "-a"], capture_output=True, text=True, timeout=5
            )
            lines.append(f"  uname: {result.stdout.strip()}")
        except Exception:
            lines.append("  uname: (unavailable)")

        lines.append(f"  python arch: {platform.machine()}, system: {platform.system()}")

        if platform.system() == "Linux":
            try:
                result = subprocess.run(
                    "ldd --version 2>&1 || true", shell=True, capture_output=True, text=True, timeout=5
                )
                ldd_out = result.stdout + result.stderr
                if "musl" in ldd_out:
                    lines.append(
                        "  libc: musl (betterleaks Linux releases target glibc; "
                        "musl systems need a static/musl build)"
                    )
                elif "GLIBC" in ldd_out or "GNU" in ldd_out:
                    import re
                    m = re.search(r"(\d+\.\d+)", ldd_out)
                    lines.append(f"  libc: glibc {m.group(1) if m else '(version unknown)'}")
                else:
                    lines.append("  libc: unknown")
            except Exception:
                lines.append("  libc: (detection failed)")

        return "\n".join(lines)

    def scan_file(self, file_path: str) -> BetterleaksScanResult:
        results = self._run_scan(file_path)
        return BetterleaksScanResult(
            file=file_path,
            matches=[self._convert(r) for r in results],
        )

    def scan_directory(
        self, dir_path: str, *, use_git: bool = False, respect_gitignore: bool = True,
    ) -> list[BetterleaksScanResult]:
        """Scan a directory: git history with use_git, else the filesystem.

        `betterleaks dir` has no notion of .gitignore, so given a directory it
        walks node_modules, build output and local secret stores (.env) alike:
        slow enough to hit the timeout on an ordinary checkout, and noisy
        (#262). With respect_gitignore (the default, matching the patterns
        engine) and a target inside a git work tree, it is handed git's own
        list of non-ignored files instead.
        """
        files = None if use_git or not respect_gitignore else git_visible_files(dir_path)
        if files is None:
            results = self._run_scan(dir_path, use_git=use_git)
        else:
            # Given file paths instead of a directory, betterleaks no longer
            # finds the target's own .betterleaks.toml / .gitleaks.toml, so pass
            # it explicitly unless an env var already chooses the config.
            config_args: list[str] = []
            if not any(os.environ.get(v) for v in CONFIG_ENV_VARS):
                for name in (".betterleaks.toml", ".gitleaks.toml"):
                    cfg = os.path.join(dir_path, name)
                    if os.path.exists(cfg):
                        config_args = ["-c", cfg]
                        break
            results = []
            for chunk in _chunk_by_length(files, ARG_CHARS_PER_CALL):
                results.extend(self._run_scan(chunk, extra_args=config_args))
        grouped: dict[str, list[PatternMatch]] = {}
        for r in results:
            f = r.get("File", "unknown")
            grouped.setdefault(f, []).append(self._convert(r))
        return [BetterleaksScanResult(file=f, matches=m) for f, m in grouped.items()]

    # ------------------------------------------------------------------

    def _run_scan(
        self, target: str | list[str], *, use_git: bool = False, extra_args: list[str] | None = None,
    ) -> list[dict]:
        if not self._path:
            raise RuntimeError("Betterleaks not available")

        with tempfile.TemporaryDirectory(prefix="betterleaks-") as tmp_dir:
            report_path = os.path.join(tmp_dir, "report.json")
            # betterleaks uses subcommands: `dir <path>` for filesystem,
            # `git <path>` for git history; report destination is --report-path.
            # `--` ensures a target path beginning with `-` isn't parsed as a flag.
            subcommand = "git" if use_git else "dir"
            targets = [target] if isinstance(target, str) else target
            cmd = [
                self._path, subcommand, *(extra_args or []),
                "-f", "json", "--report-path", report_path, "--", *targets,
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=SCAN_TIMEOUT_S)
            except subprocess.TimeoutExpired as exc:
                # An error, never an empty result: returning [] here made the
                # betterleaks-only engine report a scan that never finished as
                # clean (#262).
                raise RuntimeError(f"Betterleaks scan failed (timed out after {SCAN_TIMEOUT_S}s)") from exc
            except (OSError, FileNotFoundError) as exc:
                raise RuntimeError(f"Betterleaks invocation failed: {exc}") from exc

            # Exit-code semantics (mirror Node):
            #   0          = clean (no findings)
            #   1          = findings reported (the `--exit-code` default)
            #   anything else = scanner / runtime error — surface, don't pretend "clean"
            if result.returncode not in (0, 1):
                stderr_tail = (result.stderr or b"").decode("utf-8", "replace").strip()[-500:]
                raise RuntimeError(
                    f"Betterleaks scan failed (exit {result.returncode}): {stderr_tail or '(no stderr)'}"
                )

            if not os.path.exists(report_path):
                # Exit 0 with no report = no findings; exit 1 with no report = unexpected.
                if result.returncode == 1:
                    stderr_tail = (result.stderr or b"").decode("utf-8", "replace").strip()[-500:]
                    raise RuntimeError(
                        f"Betterleaks reported findings (exit 1) but emitted no report: {stderr_tail or '(no stderr)'}"
                    )
                return []

            return self._parse_report(report_path)

    @staticmethod
    def _parse_report(report_path: str) -> list[dict]:
        """Read a betterleaks JSON report into a findings list.

        Mirrors `parseResults` in node/src/scanners/betterleaks.ts — keep the
        two in sync.
        """
        try:
            with open(report_path) as f:
                content = f.read().strip()
            if not content:
                return []
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            print(f"[rafter] Warning: Failed to parse Betterleaks report: {exc}", file=sys.stderr)
            return []

        # #217 — betterleaks >=1.1.2 writes the literal `null` (not `[]`)
        # for a clean scan via the `dir`/`git` subcommands we invoke. That
        # is a valid empty result, not a version mismatch, so it must not
        # reach the warning branch below — otherwise every clean file
        # scanned emits warning noise.
        if parsed is None:
            return []

        if not isinstance(parsed, list):
            # sable-o4k — a stale/incompatible binary emits a non-array
            # shape and would otherwise silently yield zero findings. The
            # managed binary is auto-updated upstream; this covers a stale
            # binary on PATH, which we can't safely overwrite — so point the
            # user at the fix.
            print(
                "[rafter] Warning: Betterleaks output is not an array — possible version mismatch. "
                "Run: rafter agent update-betterleaks",
                file=sys.stderr,
            )
            return []
        return parsed

    @staticmethod
    def _convert(result: dict) -> PatternMatch:
        rule_id = result.get("RuleID", result.get("Description", "unknown"))
        severity = BetterleaksScanner._get_severity(rule_id, result.get("Tags", []))
        secret = result.get("Secret", result.get("Match", ""))
        return PatternMatch(
            pattern=Pattern(
                name=rule_id,
                regex="",
                severity=severity,
                description=result.get("Description", ""),
            ),
            match=secret,
            line=result.get("StartLine"),
            column=result.get("StartColumn"),
            redacted=BetterleaksScanner._redact(secret),
        )

    @staticmethod
    def _get_severity(rule_id: str, tags: list) -> str:
        lower = rule_id.lower()
        tags = tags or []
        # Critical: private keys, passwords, db credentials, access tokens,
        # personal access tokens, or anything tagged as both key+secret.
        if (
            any(k in lower for k in ("private-key", "password", "database", "access-token", "secret-key"))
            or lower.endswith("-pat")
            or ("key" in tags and "secret" in tags)
        ):
            return "critical"
        # High: api keys, generic tokens, or anything tagged 'api'.
        if (
            any(k in lower for k in ("api-key", "-token"))
            or lower.startswith("token-")
            or "api" in tags
        ):
            return "high"
        # Medium: anything advertised as generic.
        if "generic" in lower or "generic" in tags:
            return "medium"
        return "high"

    @staticmethod
    def _redact(match: str) -> str:
        if len(match) <= 8:
            return "*" * len(match)
        v = 4
        return match[:v] + "*" * (len(match) - v * 2) + match[-v:]
