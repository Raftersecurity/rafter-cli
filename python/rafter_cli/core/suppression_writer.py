"""Persist finding suppressions into the project's .rafter.yml ignore list.

Mirrors node/src/core/suppression-writer.ts — keep both in sync.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..utils.git import get_git_root
from .policy_loader import find_policy_file


def _rule_key(paths: list[str], rules: list[str] | None) -> str:
    """Order- and duplicate-insensitive identity for an ignore rule.

    Two rules are "the same" if they target the same set of paths and the
    same set of rule names. Reason is excluded — re-suppressing the same
    scope just updates the reason.
    """
    def norm(xs: list[str] | None) -> list[str]:
        return sorted({str(x) for x in (xs or [])})

    return json.dumps({"paths": norm(paths), "rules": norm(rules)}, sort_keys=True)


def write_suppression(
    paths: list[str],
    rules: list[str] | None = None,
    reason: str | None = None,
    cwd: str | Path | None = None,
) -> dict:
    """Persist a finding suppression into the project's .rafter.yml ignore list.

    Resolves the policy file via the same precedence the loader uses; if none
    exists, creates a canonical ``.rafter.yml`` at the git root (or ``cwd``).

    Merge semantics: if an existing ignore rule targets the same paths + rules,
    its reason is updated in place rather than appending a duplicate.

    ``cwd`` overrides the base directory for resolution (defaults to the process cwd).

    Returns a dict: {file, action, entry, suppression_count}.
    """
    import yaml

    norm_paths = [str(p) for p in (paths or []) if str(p)]
    if not norm_paths:
        raise ValueError('"paths" must be a non-empty list of file paths or globs.')
    norm_rules = [str(r) for r in rules if str(r)] if isinstance(rules, list) else None
    norm_reason = reason.strip() if isinstance(reason, str) and reason.strip() else None
    base_dir = str(cwd) if cwd else str(Path.cwd())

    target = find_policy_file(base_dir)
    raw: dict = {}

    if target and Path(target).exists():
        parsed = yaml.safe_load(Path(target).read_text())
        raw = parsed if isinstance(parsed, dict) else {}
        action = "appended"
    else:
        root = get_git_root() or base_dir
        target = Path(root) / ".rafter.yml"
        action = "created"

    target = Path(target)
    ignore_list = raw.get("ignore") if isinstance(raw.get("ignore"), list) else []

    new_entry: dict = {"paths": norm_paths}
    if norm_rules:
        new_entry["rules"] = norm_rules
    if norm_reason:
        new_entry["reason"] = norm_reason

    key = _rule_key(norm_paths, norm_rules)
    existing = next(
        (
            e
            for e in ignore_list
            if isinstance(e, dict)
            and isinstance(e.get("paths"), list)
            and _rule_key(e["paths"], e.get("rules")) == key
        ),
        None,
    )

    if existing is not None:
        if norm_reason:
            existing["reason"] = norm_reason
        else:
            existing.pop("reason", None)
        if action != "created":
            action = "updated"
        entry = dict(new_entry)
        if existing.get("reason"):
            entry["reason"] = existing["reason"]
    else:
        ignore_list.append(new_entry)
        entry = new_entry

    raw["ignore"] = ignore_list

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump(raw, sort_keys=False, default_flow_style=False))

    return {
        "file": str(target),
        "action": action,
        "entry": entry,
        "suppression_count": len(ignore_list),
    }
