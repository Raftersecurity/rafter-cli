"""Command interception and risk assessment."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .audit_logger import AuditLogger
from .config_manager import ConfigManager
from .risk_rules import assess_command_risk


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
            return bool(re.search(pattern, command, re.IGNORECASE))
        except re.error:
            return pattern.lower() in command.lower()

    @staticmethod
    def _assess_risk(command: str) -> str:
        return assess_command_risk(command)
