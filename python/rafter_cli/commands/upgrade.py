"""Upgrade command — upgrade rafter to the latest version."""
from __future__ import annotations

import os
import subprocess
import sys
from typing import Optional

import typer
from rich import print as rprint

from .. import __version__
from ..utils.formatter import fmt

upgrade_app = typer.Typer(name="upgrade", invoke_without_command=True, no_args_is_help=False)
update_app = typer.Typer(name="update", invoke_without_command=True, no_args_is_help=False)

PYPI_URL = "https://pypi.org/pypi/rafter-cli/json"
PYPI_PACKAGE = "rafter-cli"


def _is_ci() -> bool:
    return any(
        os.environ.get(v)
        for v in (
            "CI",
            "CONTINUOUS_INTEGRATION",
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "CIRCLECI",
            "TRAVIS",
            "JENKINS_URL",
        )
    )


def _is_newer(current: str, latest: str) -> bool:
    def parts(v: str):
        return [int(x) for x in v.split(".")]
    try:
        return parts(latest) > parts(current)
    except ValueError:
        return False


def _fetch_latest_version() -> str:
    import urllib.request
    import json

    with urllib.request.urlopen(PYPI_URL, timeout=5) as resp:
        data = json.loads(resp.read())
    return data["info"]["version"]


def _detect_installer() -> Optional[str]:
    """Return the install command prefix if detectable, else None."""
    executable = sys.executable

    # pipx: executable lives under PIPX_HOME or ~/.local/pipx
    pipx_home = os.environ.get("PIPX_HOME") or os.path.expanduser("~/.local/pipx")
    if executable.startswith(pipx_home) or "pipx" in executable:
        return "pipx"

    # uv virtual env: check for uv.lock in cwd or VIRTUAL_ENV parent
    virtual_env = os.environ.get("VIRTUAL_ENV", "")
    if virtual_env:
        parent = os.path.dirname(virtual_env)
        if os.path.exists(os.path.join(parent, "uv.lock")):
            return "uv"
        if os.path.exists(os.path.join(parent, "poetry.lock")):
            return "poetry"

    # uv tool installs: executable contains "uv" or ".uv"
    if "uv/tools" in executable or os.path.join(".uv", "tools") in executable:
        return "uv"

    return None


def _build_upgrade_command(installer: Optional[str]) -> list[str]:
    if installer == "pipx":
        return [["pipx", "upgrade", PYPI_PACKAGE]]
    if installer == "uv":
        return [["uv", "tool", "upgrade", PYPI_PACKAGE]]
    if installer == "poetry":
        return [["poetry", "add", f"{PYPI_PACKAGE}@latest"]]
    # pip fallback (may need pip3 on some systems)
    return [
        [sys.executable, "-m", "pip", "install", "--upgrade", PYPI_PACKAGE],
    ]


def _upgrade_main(
    check: bool = typer.Option(False, "--check", help="Check for updates without installing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Run the upgrade command automatically"),
) -> None:
    """Upgrade rafter to the latest version."""
    if _is_ci():
        rprint(fmt.info("CI environment detected — skipping upgrade check."))
        raise typer.Exit(0)

    try:
        latest_version = _fetch_latest_version()
    except Exception:
        rprint(fmt.error("Could not reach PyPI. Check your network connection."), file=sys.stderr)
        raise typer.Exit(1)

    if check:
        typer.echo(latest_version)
        return

    rprint(fmt.info(f"Current version: {__version__}"))
    rprint(fmt.info(f"Latest version:  {latest_version}"))
    rprint()

    if not _is_newer(__version__, latest_version):
        rprint(fmt.success("Already up to date."))
        return

    installer = _detect_installer()
    commands = _build_upgrade_command(installer)

    if yes:
        cmd = commands[0]
        rprint(fmt.info(f"Running: {' '.join(cmd)}"))
        rprint()
        result = subprocess.run(cmd)
        if result.returncode != 0:
            rprint(fmt.error("Upgrade failed. Try running the command manually:"))
            rprint(f"  {' '.join(cmd)}")
            raise typer.Exit(1)
        rprint()
        rprint(fmt.success(f"Upgraded to {latest_version}"))
        return

    # Print the command(s) to run
    if len(commands) == 1 and installer is not None:
        rprint(fmt.info("Run to upgrade:"))
        rprint(f"  {' '.join(commands[0])}")
    else:
        rprint(fmt.info("Run one of the following to upgrade:"))
        rprint(f"  pip install --upgrade {PYPI_PACKAGE}")
        rprint(f"  pipx upgrade {PYPI_PACKAGE}")
        rprint(f"  uv tool upgrade {PYPI_PACKAGE}")
        rprint()
        rprint(fmt.info("Or for a npm/pnpm installation:"))
        rprint("  npm install -g @rafter-security/cli@latest")

    rprint()


upgrade_app.callback()(_upgrade_main)
update_app.callback()(_upgrade_main)
