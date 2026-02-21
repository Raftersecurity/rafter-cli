"""Gitleaks scanner — wraps system gitleaks binary."""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import NamedTuple

from ..core.pattern_engine import Pattern, PatternMatch


@dataclass
class GitleaksScanResult:
    file: str
    matches: list[PatternMatch] = field(default_factory=list)


class GitleaksCheckResult(NamedTuple):
    available: bool
    stdout: str
    stderr: str
    error: str  # OSError / timeout message, empty on success


class GitleaksScanner:
    def __init__(self) -> None:
        self._path = shutil.which("gitleaks")

    def is_available(self) -> bool:
        return self.check().available

    def check(self) -> GitleaksCheckResult:
        """Run 'gitleaks version' and return structured result with captured output."""
        if not self._path:
            return GitleaksCheckResult(
                available=False, stdout="", stderr="",
                error="gitleaks not found on PATH",
            )
        try:
            result = subprocess.run(
                [self._path, "version"],
                capture_output=True, text=True, timeout=5,
            )
            ok = "gitleaks version" in result.stdout or result.returncode == 0
            return GitleaksCheckResult(
                available=ok,
                stdout=result.stdout.strip(),
                stderr=result.stderr.strip(),
                error="" if ok else f"exit code {result.returncode}",
            )
        except subprocess.TimeoutExpired:
            return GitleaksCheckResult(available=False, stdout="", stderr="", error="timed out")
        except (OSError, FileNotFoundError) as exc:
            return GitleaksCheckResult(available=False, stdout="", stderr="", error=str(exc))

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
            # Detect glibc vs musl
            try:
                result = subprocess.run(
                    "ldd --version 2>&1 || true", shell=True, capture_output=True, text=True, timeout=5
                )
                ldd_out = result.stdout + result.stderr
                if "musl" in ldd_out:
                    lines.append(
                        "  libc: musl (gitleaks Linux releases target glibc; "
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

    def scan_file(self, file_path: str) -> GitleaksScanResult:
        results = self._run_scan(file_path)
        return GitleaksScanResult(
            file=file_path,
            matches=[self._convert(r) for r in results],
        )

    def scan_directory(self, dir_path: str) -> list[GitleaksScanResult]:
        results = self._run_scan(dir_path)
        grouped: dict[str, list[PatternMatch]] = {}
        for r in results:
            f = r.get("File", "unknown")
            grouped.setdefault(f, []).append(self._convert(r))
        return [GitleaksScanResult(file=f, matches=m) for f, m in grouped.items()]

    # ------------------------------------------------------------------

    def _run_scan(self, target: str) -> list[dict]:
        if not self._path:
            raise RuntimeError("Gitleaks not available")

        fd, report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks-")
        os.close(fd)

        try:
            subprocess.run(
                [self._path, "detect", "--no-git", "-f", "json", "-r", report_path, "-s", target],
                capture_output=True, timeout=60,
            )
            if not os.path.exists(report_path):
                return []
            with open(report_path) as f:
                content = f.read().strip()
            if not content:
                return []
            return json.loads(content)
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            return []
        finally:
            if os.path.exists(report_path):
                os.unlink(report_path)

    @staticmethod
    def _convert(result: dict) -> PatternMatch:
        rule_id = result.get("RuleID", result.get("Description", "unknown"))
        severity = GitleaksScanner._get_severity(rule_id, result.get("Tags", []))
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
            redacted=GitleaksScanner._redact(secret),
        )

    @staticmethod
    def _get_severity(rule_id: str, tags: list) -> str:
        lower = rule_id.lower()
        if any(k in lower for k in ("private-key", "password", "database")):
            return "critical"
        if any(k in lower for k in ("api-key", "access-token", "secret-key")):
            return "high"
        if "generic" in lower:
            return "medium"
        return "high"

    @staticmethod
    def _redact(match: str) -> str:
        if len(match) <= 8:
            return "*" * len(match)
        v = 4
        return match[:v] + "*" * (len(match) - v * 2) + match[-v:]
