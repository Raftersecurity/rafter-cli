"""Rafter CLI entry point."""
from __future__ import annotations

import typer

from . import __version__
from .commands.agent import agent_app
from .commands.backend import register_backend_commands
from .commands.ci import ci_app
from .commands.hook import hook_app
from .commands.mcp_server import mcp_app
from .commands.policy import policy_app
from .utils.formatter import set_agent_mode

app = typer.Typer(
    name="rafter",
    help="Rafter CLI — security for AI builders.",
    add_completion=False,
    no_args_is_help=True,
)


def _version_callback(value: bool):
    if value:
        typer.echo(f"rafter {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit.",
        callback=_version_callback, is_eager=True,
    ),
    agent: bool = typer.Option(
        False, "--agent", "-a", help="Plain output for AI agents (no colors/emoji).",
    ),
):
    """Rafter CLI — security for AI builders."""
    if agent:
        set_agent_mode(True)


# Backend commands (run, get, usage) on root app
register_backend_commands(app)

# Sub-apps
app.add_typer(agent_app)
app.add_typer(ci_app)
app.add_typer(hook_app)
app.add_typer(mcp_app)
app.add_typer(policy_app)

if __name__ == "__main__":
    app()
