"""Rafter CLI entry point."""
from __future__ import annotations

from typing import Any

import typer
import typer.core

from . import __version__
from .commands.agent import agent_app
from .commands.backend import register_backend_commands
from .commands.brief import brief_app
from .commands.ci import ci_app
from .commands.docs import docs_app
from .commands.hook import hook_app
from .commands.issues.issues_app import issues_app
from .commands.mcp_server import mcp_app
from .commands.notify import notify_app
from .commands.policy import policy_app
from .commands.report import report_main
from .commands.scan import scan_app, secrets_app
from .commands.sites import sites_app
from .commands.skill import skill_app
from .commands.telemetry import telemetry_app
from .core import usage_counters
from .utils.formatter import set_agent_mode

app = typer.Typer(
    name="rafter",
    help="Rafter CLI — the default security agent for AI workflows. Free for individuals and open source. No account required.",
    add_completion=True,
    no_args_is_help=True,
    # Never render frame locals in tracebacks: they hold the API key.
    pretty_exceptions_show_locals=False,
)


def _version_callback(value: bool):
    if value:
        typer.echo(f"rafter {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit.",
        callback=_version_callback, is_eager=True,
    ),
    agent: bool = typer.Option(
        False, "--agent", "-a", help="Plain output for AI agents (no colors/emoji).",
    ),
):
    """Rafter CLI — the default security agent for AI workflows."""
    usage_counters.track_click_tree(ctx)
    if agent:
        set_agent_mode(True)


@app.command("completion")
def completion(
    shell: str = typer.Argument(..., help="Shell type: bash, zsh, or fish"),
):
    """Generate shell completion script.

    \b
    Install:
      bash  — add to ~/.bashrc:   eval "$(rafter completion bash)"
      zsh   — add to ~/.zshrc:    eval "$(rafter completion zsh)"
      fish  — save to completions: rafter completion fish > ~/.config/fish/completions/rafter.fish
    """
    import subprocess
    import sys

    shell = shell.lower()
    if shell not in ("bash", "zsh", "fish"):
        typer.echo(f"Unknown shell: {shell}. Supported: bash, zsh, fish", err=True)
        raise typer.Exit(code=1)

    env_map = {"bash": "bash", "zsh": "zsh", "fish": "fish"}
    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", "--show-completion", env_map[shell]],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        # Fallback: use _RAFTER_COMPLETE env var approach
        import os
        env = os.environ.copy()
        env[f"_RAFTER_COMPLETE"] = f"{shell}_source"
        result = subprocess.run(
            [sys.executable, "-m", "rafter_cli"],
            capture_output=True, text=True, env=env,
        )
    typer.echo(result.stdout, nl=False)


@app.command("version")
def version_cmd():
    """Print version and exit."""
    typer.echo(__version__)


# Remote scan commands (run, get, usage) on root app
register_backend_commands(app)

# Scan command group (default: remote scan; subcommands: local, remote)
app.add_typer(scan_app)

# Secrets — top-level alias for local secret scanning (explicit-scope name)
app.add_typer(secrets_app)

# Sub-apps
app.add_typer(agent_app)
app.add_typer(brief_app)
app.add_typer(ci_app)
app.add_typer(docs_app)
app.add_typer(hook_app)
app.add_typer(issues_app)
app.add_typer(mcp_app)
app.add_typer(notify_app)
app.add_typer(policy_app)
app.add_typer(sites_app)
app.add_typer(skill_app)
app.add_typer(telemetry_app)
app.command("report")(report_main)


def _allow_agent_flag_at_any_depth(cmd: Any) -> None:
    """`-a`/`--agent` is declared only on the root callback above, so Click
    rejects it as an unknown option once it appears after a subcommand name
    (``rafter secrets . -a``). Add a self-contained flag — its own callback
    sets agent mode — to every command/group in the tree so Click accepts it
    at any depth. Skipped on a command that already declares its own
    ``--agent <value>`` option (``agent audit``, ``skill review`` filter by
    agent type) to avoid colliding with that unrelated flag; ``rafter -a
    agent audit ...`` (the flag before the subcommand) still works for those.
    """
    # Typer >=0.16 builds every param as its own `typer.core.TyperOption` /
    # `TyperArgument` on a vendored Click fork — NOT a subclass of the
    # top-level `click.Option` — so `isinstance(p, click.Option)` is always
    # False here and would never see the existing `--agent <type>` params on
    # `agent audit` / `skill review`. Check the flag strings directly.
    has_agent_option = any("--agent" in getattr(p, "opts", []) for p in cmd.params)
    if not has_agent_option:
        def _enable(ctx, param, value: bool) -> None:
            if value:
                set_agent_mode(True)

        # typer >=0.16 vendors its own Click fork (`typer._click`/`typer.core`)
        # with a Context class distinct from the real `click.core.Context` — a
        # plain `click.Option` here parses fine but then crashes inside real
        # Click's `Option.handle_parse_result` (`AttributeError:
        # '...Context' object has no attribute '_param_default_explicit'`)
        # because that Context never went through real Click's own __init__.
        # `typer.core.TyperOption` is built on the same fork as every other
        # param already on `cmd`, so it's the type that has to be used here.
        cmd.params.append(
            typer.core.TyperOption(
                param_decls=["-a", "--agent"],
                is_flag=True,
                expose_value=False,
                is_eager=True,
                help="Plain output for AI agents (no colors/emoji).",
                callback=_enable,
            )
        )
    # Same fork issue: `TyperGroup` isn't a subclass of the public
    # `click.Group` either, so check for `.commands` (every group — Typer's
    # or real Click's — exposes it) instead of `isinstance(cmd, click.Group)`.
    sub_commands = getattr(cmd, "commands", None)
    if sub_commands:
        for sub in sub_commands.values():
            _allow_agent_flag_at_any_depth(sub)


def run() -> None:
    """Console-script entry point (see ``pyproject.toml``): the app, wrapped by
    the local usage counters. Builds the Click command tree once and patches it
    with the any-depth `-a` flag first, since `app()` would rebuild an unpatched
    tree itself.
    """
    command = typer.main.get_command(app)
    _allow_agent_flag_at_any_depth(command)
    usage_counters.run_app(command)


if __name__ == "__main__":
    run()
