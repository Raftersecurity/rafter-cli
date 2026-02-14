"""Gitleaks scanner — wraps system gitleaks binary."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

from ..core.pattern_engine import Pattern, PatternMatch


@dataclass
class GitleaksScanResult:
    file: str
    matches: list[PatternMatch] = field(default_factory=list)


class GitleaksScanner:
    def __init__(self) -> None:
        self._path = shutil.which("gitleaks")

    def is_available(self) -> bool:
        if not self._path:
            return False
        try:
            subprocess.run(
                [self._path, "version"],
                capture_output=True, timeout=5,
            )
            return True
        except Exception:
            return False

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
