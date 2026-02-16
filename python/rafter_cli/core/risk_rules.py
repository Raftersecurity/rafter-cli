"""Centralized risk assessment rules.

Single source of truth — imported by command_interceptor, audit_logger, and config_schema.
"""
from __future__ import annotations

import re

CRITICAL_PATTERNS: list[str] = [
    r"rm\s+-rf\s+/",
    r":\(\)\{\s*:\|:&\s*\};:",
    r"dd\s+if=.*of=/dev/sd",
    r">\s*/dev/sd",
    r"mkfs",
    r"fdisk",
    r"parted",
]

HIGH_PATTERNS: list[str] = [
    r"rm\s+-rf",
    r"sudo\s+rm",
    r"chmod\s+777",
    r"curl.*\|\s*(bash|sh|zsh|dash)\b",
    r"wget.*\|\s*(bash|sh|zsh|dash)\b",
    r"git\s+push\s+--force",
    r"docker\s+system\s+prune",
    r"npm\s+publish",
    r"pypi.*upload",
]

MEDIUM_PATTERNS: list[str] = [
    r"sudo", r"chmod", r"chown", r"systemctl",
    r"service", r"kill\s+-9", r"pkill", r"killall",
]

DEFAULT_BLOCKED_PATTERNS: list[str] = [
    "rm -rf /",
    ":(){ :|:& };:",
    "dd if=/dev/zero of=/dev/sda",
    "> /dev/sda",
]

DEFAULT_REQUIRE_APPROVAL: list[str] = [
    "rm -rf",
    "sudo rm",
    r"curl.*\|\s*(bash|sh|zsh|dash)\b",
    r"wget.*\|\s*(bash|sh|zsh|dash)\b",
    "chmod 777",
    "git push --force",
]


def assess_command_risk(command: str) -> str:
    """Assess risk level of a command string."""
    for p in CRITICAL_PATTERNS:
        if re.search(p, command, re.IGNORECASE):
            return "critical"
    for p in HIGH_PATTERNS:
        if re.search(p, command, re.IGNORECASE):
            return "high"
    for p in MEDIUM_PATTERNS:
        if re.search(p, command, re.IGNORECASE):
            return "medium"
    return "low"
