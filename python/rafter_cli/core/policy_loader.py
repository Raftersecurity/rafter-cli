"""Load and parse .rafter.yml policy files."""
from __future__ import annotations

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
        return _map_policy(raw)
    except Exception:
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
            policy["audit"]["retention_days"] = int(audit["retention_days"])
        if audit.get("log_level"):
            policy["audit"]["log_level"] = audit["log_level"]

    return policy
