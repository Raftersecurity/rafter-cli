"""``rafter telemetry show|clear`` — the local usage counters. Mirrors node/src/commands/telemetry.ts."""
from __future__ import annotations

import json
import platform
import re
import sys

import typer

from .. import __version__
from ..core.config_schema import get_config_path
from ..core.usage_counters import (
    USAGE_ALLOWLIST,
    USAGE_FAMILIES,
    USAGE_NOTICE,
    USAGE_STORE_DISPLAY,
    clear_store,
    discard_pending,
    read_counters,
    usage_status,
)

telemetry_app = typer.Typer(
    name="telemetry",
    help=f"Show or clear local usage counters. {USAGE_NOTICE}",
    no_args_is_help=True,
)

_FAMILY_TITLES = {
    "unknown_command": "Unknown commands",
    "unknown_option": "Unknown options",
    "command": "Command results",
    "hook": "Hook decisions",
    "scan_engine": "Scan engines",
    "scan_fallback": "Scan fall-backs",
    "scan_duration": "Scan durations",
    "error_class": "Errors",
}

_VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]{1,32}$", re.ASCII)


def _clean_version(v: object) -> str | None:
    if v is None:
        return None
    return v if isinstance(v, str) and _VERSION_RE.fullmatch(v) else "other"


def _skill_staleness() -> list[dict]:
    """Installed rafter skills vs the versions this CLI ships. Names and platforms are enumerated, never read from disk."""
    from .skill import SKILL_PLATFORMS, _dest_path, _list_bundled, _parse_frontmatter

    rows: list[dict] = []
    for skill in _list_bundled():
        for plat in SKILL_PLATFORMS:
            dest = _dest_path(plat, skill.name)
            if not dest.exists():
                continue
            try:
                fm = _parse_frontmatter(dest.read_text(encoding="utf-8"))
            except OSError:
                fm = {}
            installed = _clean_version(fm.get("version"))
            pinned = _clean_version(fm.get("rafter_cli_version"))
            rows.append({
                "name": skill.name,
                "platform": plat,
                "installed_version": installed,
                "current_version": skill.version,
                "stale": installed != skill.version or (pinned is not None and pinned != __version__),
            })
    try:
        cfg = json.loads(get_config_path().read_text(encoding="utf-8"))
        skills_cfg = (cfg.get("agent") or {}).get("skills") or {}
        openclaw = skills_cfg.get("installedVersion", skills_cfg.get("installed_version"))
    except Exception:
        openclaw = None
    if isinstance(openclaw, str) and openclaw:
        installed = _clean_version(openclaw)
        rows.append({
            "name": "rafter-security",
            "platform": "openclaw",
            "installed_version": installed,
            "current_version": __version__,
            "stale": installed != __version__,
        })
    return sorted(rows, key=lambda r: (r["name"], r["platform"]))


def build_telemetry_report(days: int) -> dict:
    enabled, source = usage_status()
    since, counters = read_counters(days)
    return {
        "schema": USAGE_ALLOWLIST["schema"],
        "notice": USAGE_NOTICE,
        "cli_version": __version__,
        "runtime": "python",
        "runtime_major": int(platform.python_version_tuple()[0]),
        "os": sys.platform,
        "enabled": enabled,
        "enabled_source": source,
        "store": USAGE_STORE_DISPLAY,
        "days": days,
        "since": since,
        "counters": counters,
        "skills": _skill_staleness(),
    }


def _print_text(r: dict) -> None:
    out: list[str] = [
        f"Rafter usage counters, last {r['days']} day(s) (since {r['since']} UTC)",
        r["notice"],
        "",
        f"CLI version:  {r['cli_version']}",
        f"Runtime:      {r['runtime']} {r['runtime_major']}",
        f"OS:           {r['os']}",
        f"Counting:     {'enabled' if r['enabled'] else 'disabled'} ({r['enabled_source']})",
        f"Store:        {r['store']}",
    ]
    any_counts = False
    for fam in USAGE_FAMILIES:
        entries = r["counters"][fam]
        if not entries:
            continue
        any_counts = True
        out += ["", _FAMILY_TITLES.get(fam, fam)]
        out += [f"  {k.ljust(48)} {n}" for k, n in entries.items()]
    if not any_counts:
        out += ["", "No counts recorded."]
    out += ["", "Skills"]
    if not r["skills"]:
        out.append("  (no rafter skills installed)")
    for s in r["skills"]:
        label = f"{s['name']} ({s['platform']})".ljust(36)
        out.append(
            f"  {label} installed {s['installed_version'] or 'unknown'}, current {s['current_version']}: "
            f"{'stale' if s['stale'] else 'up to date'}"
        )
    sys.stdout.write("\n".join(out) + "\n")


@telemetry_app.command("show", help=f"Print the local usage counters for the last N days. {USAGE_NOTICE}")
def show(
    json_output: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    days: str = typer.Option("7", "--days", help="Days to include, 1 to 7"),
):
    limit = USAGE_ALLOWLIST["retention_days"]
    if not re.fullmatch(r"\d+", days, re.ASCII) or not 1 <= int(days) <= limit:
        print(f"Error: --days must be an integer from 1 to {limit}", file=sys.stderr)
        raise typer.Exit(code=2)
    report = build_telemetry_report(int(days))
    if json_output:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        _print_text(report)


@telemetry_app.command("clear", help=f"Delete the local usage counters ({USAGE_STORE_DISPLAY})")
def clear():
    discard_pending()
    existed = clear_store()
    if existed:
        sys.stdout.write(f"Deleted local usage counters ({USAGE_STORE_DISPLAY}).\n")
    else:
        sys.stdout.write(f"No local usage counters to delete ({USAGE_STORE_DISPLAY}).\n")
