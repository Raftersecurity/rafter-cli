"""Command interception and risk assessment."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .audit_logger import AuditLogger
from .config_manager import ConfigManager
from .risk_rules import (
    assess_command_risk,
    match_critical_pattern,
    sanitize_command_for_matching,
)


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
        risk_level = self._assess_risk(command)

        # Unconditional hard-block: catastrophic destructive commands (rm -rf /,
        # fork bombs, disk wipes, mkfs, …) are NEVER allowed, regardless of the
        # configured policy — or its absence. Security must not depend on a
        # policy being present or on the chosen mode (even allow-all / a custom
        # deny-list cannot opt out of these).
        if risk_level == "critical":
            return CommandEvaluation(
                command=command,
                risk_level="critical",
                allowed=False,
                requires_approval=False,
                reason="Matches built-in blocked pattern (critical destructive command)",
                matched_pattern=match_critical_pattern(command) or "builtin:critical-destructive",
            )

        cfg = self._config.load_with_policy()
        policy = cfg.agent.command_policy

        # Check blocked patterns.
        #
        # A deny-list match denies — that is what a deny-list is for — but it
        # must NOT rewrite the command's risk. Reporting every deny-list hit as
        # "critical" made the hook tell users a `gh pr create` was an
        # irreversible system-damage command. The assessed risk is reported as
        # assessed; the genuinely unconditional hard-blocks are the
        # CRITICAL_PATTERNS handled above, and the default deny-list is exactly
        # that set.
        for pattern in policy.blocked_patterns:
            if self._matches(command, pattern):
                return CommandEvaluation(
                    command=command,
                    risk_level=risk_level,
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
                    risk_level=risk_level,
                    allowed=False,
                    requires_approval=True,
                    reason=f"Matches approval pattern: {pattern}",
                    matched_pattern=pattern,
                )

        # Policy mode. `risk_level` is the assessment made above — critical
        # already returned, so it is high/medium/low here.
        if policy.mode == "approve-dangerous" and risk_level == "high":
            return CommandEvaluation(
                command=command,
                risk_level=risk_level,
                allowed=False,
                requires_approval=True,
                reason="High risk command requires approval",
            )

        return CommandEvaluation(
            command=command,
            risk_level=risk_level,
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
        """Match a command against a policy pattern.

        Matching runs against the SANITIZED command line, not the raw string: the
        policy patterns describe commands, so quoted text a command merely
        consumes as data (a commit message, a PR body) must not match them, while
        text a shell or eval wrapper executes (`bash -c "…"`) must. See
        `sanitize_command_for_matching`.
        """
        target = sanitize_command_for_matching(command)
        try:
            return bool(re.search(pattern, target, re.IGNORECASE))
        except re.error:
            return pattern.lower() in target.lower()

    @staticmethod
    def _assess_risk(command: str) -> str:
        return assess_command_risk(command)
