"""Load and parse .rafter.yml policy files."""
from __future__ import annotations

import re
import sys
from pathlib import Path

from ..utils.git import get_git_root


POLICY_FILENAMES = [".rafter.yml", ".rafter.yaml"]


def find_policy_file() -> Path | None:
    """Walk from cwd up to git root looking for a policy file."""
    cwd = Path.cwd()
    root = get_git_root()
    stop = Path(root) if root else cwd.anchor and Path(cwd.anchor)

    current = cwd
    while True:
        for name in POLICY_FILENAMES:
            candidate = current / name
            if candidate.exists():
                return candidate
        parent = current.parent
        if parent == current:
            break
        if stop and current == Path(stop):
            break
        current = parent

    return None


def load_policy() -> dict | None:
    """Load and parse the policy file, returning None if not found."""
    path = find_policy_file()
    if not path:
        return None
    try:
        import yaml

        raw = yaml.safe_load(path.read_text())
        if not raw or not isinstance(raw, dict):
            return None
        return _validate_policy(_map_policy(raw), raw)
    except yaml.YAMLError as e:
        print(f"Warning: Failed to parse policy file {path}: {e}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"Warning: Cannot read policy file {path}: {e}", file=sys.stderr)
        return None


def _map_policy(raw: dict) -> dict:
    """Map YAML keys to a normalized policy dict (snake_case throughout)."""
    policy: dict = {}

    if raw.get("version"):
        policy["version"] = str(raw["version"])
    if raw.get("risk_level"):
        policy["risk_level"] = raw["risk_level"]

    cp = raw.get("command_policy")
    if isinstance(cp, dict):
        policy["command_policy"] = {}
        if cp.get("mode"):
            policy["command_policy"]["mode"] = cp["mode"]
        if isinstance(cp.get("blocked_patterns"), list):
            policy["command_policy"]["blocked_patterns"] = cp["blocked_patterns"]
        if isinstance(cp.get("require_approval"), list):
            policy["command_policy"]["require_approval"] = cp["require_approval"]

    scan = raw.get("scan")
    if isinstance(scan, dict):
        policy["scan"] = {}
        if isinstance(scan.get("exclude_paths"), list):
            policy["scan"]["exclude_paths"] = scan["exclude_paths"]
        if isinstance(scan.get("custom_patterns"), list):
            policy["scan"]["custom_patterns"] = [
                {"name": p.get("name", ""), "regex": p.get("regex", ""), "severity": p.get("severity", "high")}
                for p in scan["custom_patterns"]
            ]

    audit = raw.get("audit")
    if isinstance(audit, dict):
        policy["audit"] = {}
        if audit.get("retention_days") is not None:
            try:
                policy["audit"]["retention_days"] = int(audit["retention_days"])
            except (ValueError, TypeError):
                print(f'Warning: "audit.retention_days" must be a number — ignoring.', file=sys.stderr)
        if audit.get("log_level"):
            policy["audit"]["log_level"] = audit["log_level"]

    return policy


_VALID_TOP_LEVEL_KEYS = {"version", "risk_level", "command_policy", "scan", "audit"}
_VALID_RISK_LEVELS = {"minimal", "moderate", "aggressive"}
_VALID_COMMAND_MODES = {"allow-all", "approve-dangerous", "deny-list"}
_VALID_LOG_LEVELS = {"debug", "info", "warn", "error"}


def _validate_policy(policy: dict, raw: dict) -> dict:
    """Validate a mapped policy. Warn on stderr for invalid fields and strip them."""

    # 1. Unknown top-level keys
    for key in raw:
        if key not in _VALID_TOP_LEVEL_KEYS:
            print(f'Warning: Unknown policy key "{key}" \u2014 ignoring.', file=sys.stderr)

    # 2. Type checking + strip invalid
    if "version" in policy and not isinstance(policy["version"], str):
        print('Warning: "version" must be a string \u2014 ignoring.', file=sys.stderr)
        del policy["version"]

    if "risk_level" in policy and policy["risk_level"] not in _VALID_RISK_LEVELS:
        print('Warning: "risk_level" must be one of: minimal, moderate, aggressive \u2014 ignoring.', file=sys.stderr)
        del policy["risk_level"]

    cp = policy.get("command_policy")
    if isinstance(cp, dict):
        if "mode" in cp and cp["mode"] not in _VALID_COMMAND_MODES:
            print('Warning: "command_policy.mode" must be one of: allow-all, approve-dangerous, deny-list \u2014 ignoring.', file=sys.stderr)
            del cp["mode"]
        if "blocked_patterns" in cp:
            if not isinstance(cp["blocked_patterns"], list) or not all(isinstance(v, str) for v in cp["blocked_patterns"]):
                print('Warning: "command_policy.blocked_patterns" must be an array of strings \u2014 ignoring.', file=sys.stderr)
                del cp["blocked_patterns"]
        if "require_approval" in cp:
            if not isinstance(cp["require_approval"], list) or not all(isinstance(v, str) for v in cp["require_approval"]):
                print('Warning: "command_policy.require_approval" must be an array of strings \u2014 ignoring.', file=sys.stderr)
                del cp["require_approval"]

    scan = policy.get("scan")
    if isinstance(scan, dict):
        if "exclude_paths" in scan:
            if not isinstance(scan["exclude_paths"], list) or not all(isinstance(v, str) for v in scan["exclude_paths"]):
                print('Warning: "scan.exclude_paths" must be an array of strings \u2014 ignoring.', file=sys.stderr)
                del scan["exclude_paths"]
        if "custom_patterns" in scan:
            valid_patterns = []
            for p in scan["custom_patterns"] if isinstance(scan["custom_patterns"], list) else []:
                if not (isinstance(p, dict) and isinstance(p.get("name"), str) and p.get("name") != "" and isinstance(p.get("regex"), str) and p.get("regex") != "" and isinstance(p.get("severity"), str)):
                    print(f'Warning: skipping malformed custom_patterns entry {p!r} \u2014 must have name, regex, severity.', file=sys.stderr)
                    continue
                try:
                    re.compile(p["regex"])
                except re.error as exc:
                    print(f'Warning: skipping custom pattern {p["name"]!r} \u2014 invalid regex: {exc}', file=sys.stderr)
                    continue
                valid_patterns.append(p)
            if valid_patterns:
                scan["custom_patterns"] = valid_patterns
            else:
                del scan["custom_patterns"]

    audit = policy.get("audit")
    if isinstance(audit, dict):
        if "retention_days" in audit and not isinstance(audit["retention_days"], (int, float)):
            print('Warning: "audit.retention_days" must be a number \u2014 ignoring.', file=sys.stderr)
            del audit["retention_days"]
        if "log_level" in audit and audit["log_level"] not in _VALID_LOG_LEVELS:
            print('Warning: "audit.log_level" must be one of: debug, info, warn, error \u2014 ignoring.', file=sys.stderr)
            del audit["log_level"]

    return policy
