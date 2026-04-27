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

from ..core.pattern_engine import Pattern, PatternMatch, fingerprint_for
from ..utils.binary_manager import BinaryManager


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
        self._binary_manager = BinaryManager()
        # Prefer managed binary, fall back to system PATH
        if self._binary_manager.is_gitleaks_installed():
            self._path: str | None = str(self._binary_manager.get_gitleaks_path())
        else:
            self._path = self._binary_manager.find_gitleaks_on_path()

    def is_available(self) -> bool:
        return self.check().available

    def check(self) -> GitleaksCheckResult:
        """Run 'gitleaks version' and return structured result with captured output."""
        if not self._path:
            return GitleaksCheckResult(
                available=False, stdout="", stderr="",
                error="gitleaks not found (not installed via rafter and not on PATH)",
            )
        try:
            result = subprocess.run(
                [self._path, "version"],
                capture_output=True, text=True, timeout=5,
            )
            ok = result.returncode == 0
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

    def scan_directory(self, dir_path: str, *, use_git: bool = False) -> list[GitleaksScanResult]:
        results = self._run_scan(dir_path, use_git=use_git)
        grouped: dict[str, list[PatternMatch]] = {}
        for r in results:
            f = r.get("File", "unknown")
            grouped.setdefault(f, []).append(self._convert(r))
        return [GitleaksScanResult(file=f, matches=m) for f, m in grouped.items()]

    # ------------------------------------------------------------------

    def _run_scan(self, target: str, *, use_git: bool = False) -> list[dict]:
        if not self._path:
            raise RuntimeError("Gitleaks not available")

        with tempfile.TemporaryDirectory(prefix="gitleaks-") as tmp_dir:
            report_path = os.path.join(tmp_dir, "report.json")
            try:
                cmd = [self._path, "detect", "-f", "json", "-r", report_path, "-s", target]
                if not use_git:
                    cmd.insert(2, "--no-git")
                subprocess.run(
                    cmd,
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

    @staticmethod
    def _convert(result: dict) -> PatternMatch:
        rule_id = result.get("RuleID", result.get("Description", "unknown"))
        tags = result.get("Tags", []) or []
        entropy = float(result.get("Entropy", 0.0) or 0.0)
        severity = GitleaksScanner._get_severity(rule_id, tags)
        confidence = GitleaksScanner._get_confidence(rule_id, entropy)
        remediation = GitleaksScanner._get_remediation(rule_id, tags)
        secret = result.get("Secret", result.get("Match", ""))
        redacted = GitleaksScanner._redact(secret)
        # Always compute our own stable hash; Gitleaks's Fingerprint format is
        # `<file>:<rule>:<line>` which leaks path data and isn't a hash.
        fingerprint = fingerprint_for(result.get("File", "") or "", rule_id, redacted)
        return PatternMatch(
            pattern=Pattern(
                name=rule_id,
                regex="",
                severity=severity,
                description=result.get("Description", ""),
                confidence=confidence,
                remediation=remediation,
            ),
            match=secret,
            line=result.get("StartLine"),
            column=result.get("StartColumn"),
            redacted=redacted,
            fingerprint=fingerprint,
            entropy=entropy,
        )

    @staticmethod
    def _get_severity(rule_id: str, tags: list) -> str:
        lower = rule_id.lower()
        if any(k in lower for k in ("private-key", "password", "database", "access-token", "secret-key")) or lower.endswith("-pat"):
            return "critical"
        if any(k in lower for k in ("api-key", "-token", "token-")):
            return "high"
        if "generic" in lower:
            return "medium"
        return "high"

    @staticmethod
    def _get_confidence(rule_id: str, entropy: float) -> str:
        lower = (rule_id or "").lower()
        if "generic" in lower or lower.startswith("token-"):
            return "medium" if entropy >= 4.5 else "low"
        return "high"

    @staticmethod
    def _get_remediation(rule_id: str, tags: list) -> str:
        lower = (rule_id or "").lower()
        t = [x.lower() for x in tags]
        if "private-key" in lower or "private-key" in t:
            return ("Generate a new keypair, deploy the new public key, and revoke the old one. "
                    "Never commit private keys; use ssh-agent or a KMS for storage.")
        if any(k in lower for k in ("aws", "gcp", "azure")):
            return ("Rotate the credential in the provider's console immediately. Reference via env var "
                    "or a secret manager. Git history retains the secret — rotation is mandatory.")
        if any(k in lower for k in ("database", "postgres", "mysql", "mongo")):
            return ("Rotate database credentials immediately. Reference via env var or a secret manager. "
                    "Audit access logs for unauthorized use.")
        if "jwt" in lower:
            return ("If real, rotate the JWT signing key — every token signed with the old key is now "
                    "untrusted. If example/test data, move to a fixture not committed to git.")
        return ("Revoke the credential at the issuer, generate a new one, and reference via env var or "
                "secret manager. Git history retains the secret — rotation is mandatory.")

    @staticmethod
    def _redact(match: str) -> str:
        if len(match) <= 8:
            return "*" * len(match)
        v = 4
        return match[:v] + "*" * (len(match) - v * 2) + match[-v:]
