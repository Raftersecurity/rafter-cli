"""Optional DEEP skill-review engine — wraps the external `skill-scanner` CLI.

PoC (bead sable-7g7). This is the **couple, don't swap** integration: our
zero-dependency deterministic quick scan stays the default for
``rafter audit-skill``; passing ``--deep`` shells out to Cisco AI Defense's
``skill-scanner`` (pip: ``cisco-ai-skill-scanner``) for a deeper pass that
covers prompt injection, taint/dataflow, YARA and .pyc integrity — the blind
spots our regex quick scan cannot see.

Design mirrors ``betterleaks.py``: an external tool both runtimes shell out to
and whose JSON we parse. Critically, we invoke **only the offline/static
default analyzers** (static + bytecode + pipeline). We never pass
``--use-llm``, ``--use-virustotal``, ``--use-aidefense`` (or behavioral, which
is static but kept off for the PoC to stay minimal), so nothing leaves the
machine — preserving Rafter's offline / no-telemetry promise.

Observed ``skill-scanner`` version: 2.0.11.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# PyPI package providing the external `skill-scanner` CLI, and the version we
# pin for reproducibility. skill-scanner's JSON shape is stable but not a
# documented contract, so the managed installer pins this exact version (mirrors
# BETTERLEAKS_VERSION). Bump deliberately after re-validating the JSON mapping.
SKILL_SCANNER_PACKAGE = "cisco-ai-skill-scanner"
SKILL_SCANNER_VERSION = "2.0.11"

# skill-scanner severity (UPPERCASE) -> our tier (lowercase).
# Our tiers: critical / high / medium / low. skill-scanner also emits INFO,
# which we map to "low" (informational, e.g. missing-license policy hints).
_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "low",
}

# Severities that count as actionable "findings" for exit-code purposes.
# INFO/low policy hints (e.g. missing license) do NOT flip the exit code,
# matching the spirit of our quick scan (secrets / high-risk commands only).
_FINDING_SEVERITIES = frozenset({"critical", "high", "medium"})

INSTALL_HINT = (
    "skill-scanner not found. The --deep engine requires Cisco AI Defense's "
    "skill-scanner. Install it with the managed installer:\n"
    "    rafter agent update-skill-scanner\n"
    "  (or manually: uv tool install cisco-ai-skill-scanner)\n"
    "Then re-run with --deep."
)


@dataclass
class DeepFinding:
    """One mapped finding from skill-scanner, in our normalized shape."""
    rule_id: str
    severity: str  # our tier: critical/high/medium/low
    category: str
    title: str
    description: str
    file_path: str | None
    line: int | None
    snippet: str | None
    analyzer: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "file": self.file_path,
            "line": self.line,
            "snippet": self.snippet,
            "analyzer": self.analyzer,
        }


@dataclass
class DeepScanResult:
    available: bool
    findings: list[DeepFinding] = field(default_factory=list)
    max_severity: str | None = None  # our tier or None
    analyzers_used: list[str] = field(default_factory=list)
    error: str = ""  # populated when available is False or scan failed
    raw: dict[str, Any] | None = None  # raw skill-scanner JSON (for --json passthrough)

    @property
    def has_findings(self) -> bool:
        """True if any finding is at/above the actionable severity floor."""
        return any(f.severity in _FINDING_SEVERITIES for f in self.findings)


class SkillScanner:
    """Thin wrapper around the external `skill-scanner` CLI (offline analyzers only)."""

    def __init__(self) -> None:
        self._path: str | None = shutil.which("skill-scanner")

    def is_available(self) -> bool:
        return self._path is not None

    @staticmethod
    def build_argv(
        target_dir: str,
        *,
        binary: str = "skill-scanner",
        skill_file: str | None = None,
        lenient: bool = False,
    ) -> list[str]:
        """Construct the OFFLINE-SAFE argv for a skill-scanner scan.

        Guarantees (asserted by tests): NO network/LLM/cloud flags are ever
        added — no --use-llm, --use-virustotal, --use-aidefense, --use-behavioral.
        Only the default static/bytecode/pipeline analyzers run, all offline.

        We force JSON output and use --fail-on-severity so the process exit
        code reflects findings (skill-scanner otherwise exits 0 even when it
        flags critical issues).
        """
        argv = [
            binary,
            "scan",
            target_dir,
            "--format",
            "json",
            # Exit non-zero when a medium+ finding exists, so our wrapper can
            # corroborate parsed results against the process exit code.
            "--fail-on-severity",
            "medium",
        ]
        if skill_file:
            # Point skill-scanner at a non-SKILL.md metadata file (our
            # audit-skill takes an arbitrary .md path).
            argv += ["--skill-file", skill_file]
        if lenient:
            # Tolerate malformed/Claude-command-style skills.
            argv += ["--lenient"]
        return argv

    def scan_path(self, skill_path: str) -> DeepScanResult:
        """Run an offline deep scan for a skill file or directory.

        skill-scanner operates on a *directory*. ``audit-skill`` receives a
        file path, so when given a file we scan its parent directory and point
        ``--skill-file`` at the filename (plus ``--lenient`` for robustness).
        """
        if not self._path:
            return DeepScanResult(available=False, error=INSTALL_HINT)

        p = Path(skill_path)
        if p.is_dir():
            target_dir = str(p)
            skill_file = None
            lenient = False
        else:
            target_dir = str(p.parent)
            skill_file = p.name
            lenient = True

        argv = self.build_argv(
            target_dir,
            binary=self._path,
            skill_file=skill_file,
            lenient=lenient,
        )

        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return DeepScanResult(available=True, error="skill-scanner scan timed out")
        except (OSError, FileNotFoundError) as exc:
            return DeepScanResult(available=True, error=f"skill-scanner invocation failed: {exc}")

        # skill-scanner exit codes: 0 = clean OR (findings present but below
        # --fail-on-severity floor); 1 = findings at/above floor; 2 = usage
        # error. The JSON report is on stdout regardless. Parse it; only treat
        # a missing/invalid report as an error.
        stdout = (result.stdout or "").strip()
        if not stdout:
            stderr_tail = (result.stderr or "").strip()[-500:]
            return DeepScanResult(
                available=True,
                error=f"skill-scanner produced no JSON (exit {result.returncode}): {stderr_tail or '(no stderr)'}",
            )

        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return DeepScanResult(available=True, error=f"failed to parse skill-scanner JSON: {exc}")

        return self._map(parsed)

    @staticmethod
    def _map(parsed: dict[str, Any]) -> DeepScanResult:
        findings: list[DeepFinding] = []
        for f in parsed.get("findings", []) or []:
            raw_sev = str(f.get("severity", "")).upper()
            tier = _SEVERITY_MAP.get(raw_sev, "low")
            findings.append(
                DeepFinding(
                    rule_id=str(f.get("rule_id") or f.get("id") or "unknown"),
                    severity=tier,
                    category=str(f.get("category") or ""),
                    title=str(f.get("title") or ""),
                    description=str(f.get("description") or ""),
                    file_path=f.get("file_path"),
                    line=f.get("line_number"),
                    snippet=f.get("snippet"),
                    analyzer=str(f.get("analyzer") or ""),
                )
            )

        raw_max = parsed.get("max_severity")
        max_tier = _SEVERITY_MAP.get(str(raw_max).upper()) if raw_max else None

        return DeepScanResult(
            available=True,
            findings=findings,
            max_severity=max_tier,
            analyzers_used=list(parsed.get("analyzers_used") or []),
            raw=parsed,
        )


@dataclass
class InstallResult:
    ok: bool
    message: str
    via: str = ""  # "uv" | "pip" | ""


class SkillScannerInstaller:
    """Managed installer for the optional `skill-scanner` deep engine.

    skill-scanner is a HEAVY PyPI package (it pulls litellm, fastapi, yara-x,
    tokenizers, …), so — unlike a hard dependency — we install it in an
    **isolated** environment that cannot perturb Rafter's own dependency tree:

    1. ``uv tool install cisco-ai-skill-scanner==<version>`` (preferred): uv
       builds a dedicated venv and exposes a ``skill-scanner`` launcher on PATH.
    2. Fallback ``python -m pip install --user cisco-ai-skill-scanner==<version>``
       when uv is absent.

    Security posture (mirrors the betterleaks installer's intent):
    - **Pinned version** for reproducibility (``SKILL_SCANNER_VERSION``).
    - **List-form subprocess**, never ``shell=True`` — no command injection.
    - No elevated privileges; user-scoped install only.
    - Integrity relies on TLS-to-PyPI + the version pin. (Unlike the betterleaks
      single-binary download we cannot pin a SHA256 over the whole transitive
      tree without a lockfile; this is a documented limitation, not a regression.)

    This only *installs* the engine. It does not change the offline-only
    invocation contract enforced by ``SkillScanner.build_argv``.
    """

    @staticmethod
    def uv_path() -> str | None:
        return shutil.which("uv")

    @staticmethod
    def build_install_argv(version: str, *, uv: str | None) -> list[str]:
        """Construct the (list-form) install argv. Version is pinned with ``==``.

        ``version`` must be a plain version string; we never interpolate it into
        a shell, and the ``==`` pin prevents it from being read as extra args.
        """
        spec = f"{SKILL_SCANNER_PACKAGE}=={version}"
        if uv:
            # --force so an existing managed install is replaced (update semantics).
            return [uv, "tool", "install", "--force", spec]
        # Fallback: user-site pip install via the running interpreter.
        py = sys.executable or "python3"
        return [py, "-m", "pip", "install", "--user", "--upgrade", spec]

    def install(
        self,
        version: str = SKILL_SCANNER_VERSION,
        on_progress=None,
    ) -> InstallResult:
        uv = self.uv_path()
        argv = self.build_install_argv(version, uv=uv)
        via = "uv" if uv else "pip"
        if on_progress:
            on_progress(f"Installing {SKILL_SCANNER_PACKAGE}=={version} via {via}…")
        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=900,  # heavy transitive tree; allow generous build time
            )
        except subprocess.TimeoutExpired:
            return InstallResult(False, "skill-scanner install timed out", via)
        except (OSError, FileNotFoundError) as exc:
            return InstallResult(False, f"install invocation failed: {exc}", via)

        if result.returncode != 0:
            tail = (result.stderr or result.stdout or "").strip()[-800:]
            return InstallResult(
                False,
                f"installer exited {result.returncode}: {tail or '(no output)'}",
                via,
            )

        # Verify the launcher is now reachable and runnable.
        path = shutil.which("skill-scanner")
        if not path:
            return InstallResult(
                False,
                "install reported success but `skill-scanner` is not on PATH. "
                "If you used the pip fallback, ensure your user-site bin "
                "directory is on PATH.",
                via,
            )
        return InstallResult(True, path, via)

    @staticmethod
    def build_uninstall_argv(*, uv: str | None) -> list[str]:
        """The (list-form) uninstall argv. Mirrors install: uv tool, pip fallback."""
        if uv:
            return [uv, "tool", "uninstall", SKILL_SCANNER_PACKAGE]
        py = sys.executable or "python3"
        return [py, "-m", "pip", "uninstall", "-y", SKILL_SCANNER_PACKAGE]

    def uninstall(self, on_progress=None) -> InstallResult:
        """Remove the managed skill-scanner. Idempotent: a no-op (success) when
        it isn't installed. Tries `uv tool uninstall` first (how `install`
        prefers to set it up), then a `pip uninstall` fallback — because we don't
        durably record which path installed it."""
        if not shutil.which("skill-scanner"):
            return InstallResult(True, "skill-scanner is not installed (nothing to do)", "")

        attempts: list[str] = []
        uv = self.uv_path()
        methods: list[tuple[str, list[str]]] = []
        if uv:
            methods.append(("uv", self.build_uninstall_argv(uv=uv)))
        methods.append(("pip", self.build_uninstall_argv(uv=None)))
        for via, argv in methods:
            if on_progress:
                on_progress(f"Removing skill-scanner via {via}…")
            try:
                result = subprocess.run(
                    argv, capture_output=True, text=True, timeout=120
                )
                attempts.append(f"{via}:{result.returncode}")
            except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as exc:
                attempts.append(f"{via}:err({exc})")
            if not shutil.which("skill-scanner"):
                return InstallResult(True, f"removed via {via}", via)

        return InstallResult(
            False,
            f"skill-scanner is still on PATH after uninstall attempts ({', '.join(attempts)}). "
            "It may have been installed by another tool; remove it manually.",
            "",
        )


# Severity tiers, low→high — used to escalate a report's severity by deep findings.
_TIER_ORDER: tuple[str, ...] = ("clean", "low", "medium", "high", "critical")


def deep_severity_tier(result: DeepScanResult) -> str:
    """Highest **actionable** tier (medium/high/critical) among findings, or
    'clean'. low/INFO findings never escalate the overall severity / exit code,
    matching the quick-scan contract."""
    tier = "clean"
    for f in result.findings:
        if f.severity in _FINDING_SEVERITIES and _TIER_ORDER.index(f.severity) > _TIER_ORDER.index(tier):
            tier = f.severity
    return tier


def deep_actionable_count(result: DeepScanResult) -> int:
    """Count of actionable (medium+) deep findings."""
    return sum(1 for f in result.findings if f.severity in _FINDING_SEVERITIES)


def ensure_skill_scanner(*, json_out: bool = False) -> "SkillScanner | None":
    """Resolve a usable SkillScanner for an opt-in --deep run, making it **easy**:
    if the engine isn't installed and we're on an interactive TTY (and not in
    --json mode), offer to install it in place. Returns a ready scanner, or None
    when unavailable and the caller should print the install hint + exit 2."""
    scanner = SkillScanner()
    if scanner.is_available():
        return scanner

    interactive = sys.stdin.isatty() and not json_out
    if interactive:
        print("\nThe --deep engine (skill-scanner) is not installed.", file=sys.stderr)
        # Prompt on stderr to keep stdout clean.
        print(
            "  Install it now? (heavy third-party package, isolated via uv/pip) [y/N] ",
            end="",
            file=sys.stderr,
            flush=True,
        )
        try:
            ans = input().strip().lower()
        except EOFError:
            ans = ""
        if ans in ("y", "yes"):
            result = SkillScannerInstaller().install(
                on_progress=lambda m: print(f"  {m}", file=sys.stderr)
            )
            if result.ok:
                s2 = SkillScanner()
                if s2.is_available():
                    print(f"skill-scanner installed ({result.via}).", file=sys.stderr)
                    return s2
            else:
                print(f"Install failed: {result.message}", file=sys.stderr)
    return None
