"""Command interception and risk assessment."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .audit_logger import AuditLogger
from .config_manager import ConfigManager


@dataclass
class CommandEvaluation:
    command: str
    risk_level: str  # low | medium | high | critical
    allowed: bool
    requires_approval: bool
    reason: str | None = None
    matched_pattern: str | None = None


class CommandInterceptor:
    def __init__(self) -> None:
        self._config = ConfigManager()
        self._audit = AuditLogger()

    def evaluate(self, command: str) -> CommandEvaluation:
        cfg = self._config.load_with_policy()
        policy = cfg.agent.command_policy

        # Check blocked patterns
        for pattern in policy.blocked_patterns:
            if self._matches(command, pattern):
                return CommandEvaluation(
                    command=command,
                    risk_level="critical",
                    allowed=False,
                    requires_approval=False,
                    reason=f"Matches blocked pattern: {pattern}",
                    matched_pattern=pattern,
                )

        # Check approval patterns
        for pattern in policy.require_approval:
            if self._matches(command, pattern):
                return CommandEvaluation(
                    command=command,
                    risk_level=self._assess_risk(command),
                    allowed=False,
                    requires_approval=True,
                    reason=f"Matches approval pattern: {pattern}",
                    matched_pattern=pattern,
                )

        # Policy mode
        mode = policy.mode
        if mode == "approve-dangerous":
            risk = self._assess_risk(command)
            if risk in ("high", "critical"):
                return CommandEvaluation(
                    command=command,
                    risk_level=risk,
                    allowed=False,
                    requires_approval=True,
                    reason="High risk command requires approval",
                )

        return CommandEvaluation(
            command=command,
            risk_level=self._assess_risk(command),
            allowed=True,
            requires_approval=False,
        )

    def log_evaluation(self, evaluation: CommandEvaluation, action_taken: str) -> None:
        self._audit.log_command_intercepted(
            evaluation.command,
            evaluation.allowed,
            action_taken,
            evaluation.reason,
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _matches(command: str, pattern: str) -> bool:
        try:
            return bool(re.search(pattern, command))
        except re.error:
            return pattern in command

    @staticmethod
    def _assess_risk(command: str) -> str:
        critical = [
            r"rm\s+-rf\s+/",
            r":\(\)\{\s*:\|:&\s*\};:",
            r"dd\s+if=.*of=/dev/sd",
            r">\s*/dev/sd",
            r"mkfs",
            r"fdisk",
            r"parted",
        ]
        high = [
            r"rm\s+-rf",
            r"sudo\s+rm",
            r"chmod\s+777",
            r"curl.*\|.*sh",
            r"wget.*\|.*sh",
            r"git\s+push\s+--force",
            r"docker\s+system\s+prune",
            r"npm\s+publish",
            r"pypi.*upload",
        ]
        medium = [
            r"sudo", r"chmod", r"chown", r"systemctl",
            r"service", r"kill\s+-9", r"pkill", r"killall",
        ]

        for p in critical:
            if re.search(p, command):
                return "critical"
        for p in high:
            if re.search(p, command):
                return "high"
        for p in medium:
            if re.search(p, command):
                return "medium"
        return "low"
