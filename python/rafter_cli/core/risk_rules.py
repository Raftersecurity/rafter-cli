"""Centralized risk assessment rules.

Single source of truth — imported by command_interceptor, audit_logger, and config_schema.
"""
from __future__ import annotations

import re

# Directories where `rm -rf /<dir>` is catastrophic (data loss / unbootable).
_CRITICAL_DIRS = "home|etc|usr|boot|root|sys|proc|lib|lib64|bin|sbin|opt"

CRITICAL_PATTERNS: list[str] = [
    # rm -rf / (root only, any flag order: -rf, -fr, -r -f, -f -r)
    r"rm\s+(-[a-z]*r[a-z]*\s+)*-[a-z]*f[a-z]*\s+/(\s|$)",
    r"rm\s+(-[a-z]*f[a-z]*\s+)*-[a-z]*r[a-z]*\s+/(\s|$)",
    # rm -rf on critical top-level directories
    rf"rm\s+(-[a-z]*r[a-z]*\s+)*-[a-z]*f[a-z]*\s+/({_CRITICAL_DIRS})(/|\s|$)",
    rf"rm\s+(-[a-z]*f[a-z]*\s+)*-[a-z]*r[a-z]*\s+/({_CRITICAL_DIRS})(/|\s|$)",
    r":\(\)\{\s*:\|:&\s*\};:",
    r"dd\s+if=.*of=/dev/sd",
    r">\s*/dev/sd",
    r"mkfs",
    r"fdisk",
    r"parted",
]

HIGH_PATTERNS: list[str] = [
    r"rm\s+(-[a-z]*r[a-z]*\s+)*-[a-z]*f[a-z]*",   # rm -rf, -fr, -r -f, -f -r
    r"rm\s+(-[a-z]*f[a-z]*\s+)*-[a-z]*r[a-z]*",   # reversed order
    r"sudo\s+rm",
    r"chmod\s+777",
    r"curl.*\|\s*(bash|sh|zsh|dash)\b",
    r"wget.*\|\s*(bash|sh|zsh|dash)\b",
    r"git\s+push\b.*\s--force\b",                          # --force anywhere after push
    r"git\s+push\b.*\s-[a-zA-Z]*f\b",                     # -f or combined flags like -vf
    r"git\s+push\b.*\s--force-(with-lease|if-includes)\b", # specific force variants
    r"git\s+push\s+\S*\s+\+",                             # refspec force: git push origin +main
    r"docker\s+system\s+prune",
    r"npm\s+publish",
    r"pypi.*upload",
]

MEDIUM_PATTERNS: list[str] = [
    r"sudo", r"chmod", r"chown", r"systemctl",
    r"service", r"kill\s+-9", r"pkill", r"killall",
]

# Top-level system directories whose deletion is unrecoverable / unbootable.
# Mirrors Node's CATASTROPHIC_TARGET_DIRS (system + macOS-bundle dirs).
_CATASTROPHIC_TARGET_DIRS = (
    "System|Library|Users|etc|var|usr|bin|sbin|private|opt|dev|root|home|boot|sys|proc|lib|lib64"
)

# Patterns that always hard-block at the command-interceptor layer, before
# any approval logic runs. Strings are interpreted as case-insensitive regex
# — end-anchored where possible so `rm -rf node_modules` does NOT match but
# `rm -rf /etc` and `rm -rf $HOME` do.
#
# Tightened 2026-05-23 (sable-9nm) from a user-validated 18-case regex set
# after a real personal-config session found the prior defaults gated
# catastrophic variants instead of hard-blocking them. The HIGH_PATTERNS
# layer still gates routine `rm -rf` via the `approve-dangerous` policy mode
# (and that gate is now opt-outable via commandPolicy.useBuiltinRiskPatterns).
DEFAULT_BLOCKED_PATTERNS: list[str] = [
    # Fork bomb
    r":\(\)\{\s*:\|:&\s*\};:",
    # Block-device clobber
    r"dd\s+if=.*\s+of=/dev/sd",
    r">\s*/dev/sd",
    r"mkfs\b",
    # rm aimed at bare / or / followed by nothing useful
    r"rm\s+(-[a-z]*\s+)*/\s*$",
    r"rm\s+(-[a-z]*\s+)*/\*\s*$",
    # rm aimed at $HOME or ~ — irrecoverable for the running user
    r"rm\s+(-[a-z]*\s+)*\$HOME(/|\s|$)",
    r"rm\s+(-[a-z]*\s+)*~(/|\s|$)",
    # rm aimed at bare wildcard or current directory in a way that's almost certainly accidental
    r"rm\s+(-[a-z]*\s+)*\*\s*$",
    r"rm\s+(-[a-z]*\s+)*\.\s*$",
    # rm -rf targeting top-level system directories (any flag order)
    rf"rm\s+(-[a-z]*r[a-z]*\s+)*-[a-z]*f[a-z]*\s+/({_CATASTROPHIC_TARGET_DIRS})(/|\s|$)",
    rf"rm\s+(-[a-z]*f[a-z]*\s+)*-[a-z]*r[a-z]*\s+/({_CATASTROPHIC_TARGET_DIRS})(/|\s|$)",
]

DEFAULT_REQUIRE_APPROVAL: list[str] = [
    "rm -rf",
    "sudo rm",
    r"curl.*\|\s*(bash|sh|zsh|dash)\b",
    r"wget.*\|\s*(bash|sh|zsh|dash)\b",
    "chmod 777",
    "git push --force",
    "git push -f",
    "git push --force-with-lease",
    "git push --force-if-includes",
    r"git push .* \+",
]


# Read-only commands whose arguments should not trigger risk patterns.
_SAFE_PREFIX = re.compile(r"^(grep|egrep|fgrep|rg|ag|ack|echo|printf)\s", re.IGNORECASE)


def assess_command_risk(command: str) -> str:
    """Assess risk level of a command string."""
    cmd = command.strip()
    if _SAFE_PREFIX.match(cmd):
        return "low"
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
