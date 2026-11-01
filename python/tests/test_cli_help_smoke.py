"""Smoke test: every command and subcommand's ``--help`` must render.

Regression coverage for sable-it5s: ``rafter skill review --help`` crashed with
``rich.errors.MarkupError`` because its Typer help string contained literal
``[/subpath]`` / ``[@version]``, which Rich's console markup parses as style
tags rather than literal text. One unescaped ``[`` anywhere in a help string
(including a subcommand or group buried deep in the tree) can crash
``--help`` the same way, so this walks the *entire* Typer/Click command tree
rather than special-casing ``skill review``.
"""
from __future__ import annotations

import pytest
import typer.main
from typer.testing import CliRunner

from rafter_cli.__main__ import app

runner = CliRunner()


def _iter_command_paths(cmd, prefix: tuple[str, ...] = ()):
    """Yield every command path (root first) in the Typer/Click tree.

    Duck-types on ``.commands`` rather than ``isinstance(cmd, click.Group)``:
    Typer >=0.16 builds its tree on a vendored Click fork
    (``typer.core.TyperGroup`` / ``typer._click.core.Command``), not the
    public ``click.Group``, so an isinstance check against real ``click``
    silently never matches (see the same gotcha documented in
    ``rafter_cli/__main__.py``'s ``_allow_agent_flag_at_any_depth``).
    """
    yield prefix
    sub_commands = getattr(cmd, "commands", None)
    if sub_commands:
        for name, sub in sub_commands.items():
            yield from _iter_command_paths(sub, prefix + (name,))


_ROOT_COMMAND = typer.main.get_command(app)
ALL_COMMAND_PATHS = sorted(_iter_command_paths(_ROOT_COMMAND))


def _id(path: tuple[str, ...]) -> str:
    return "rafter " + " ".join(path) if path else "rafter"


def test_discovered_more_than_one_command():
    # A regression in the walk itself (e.g. an empty tree from a bad import)
    # would make every parametrized case below vacuously pass. Guard the
    # corpus size the way `bd ready`'s silent cap taught us to.
    assert len(ALL_COMMAND_PATHS) > 60, (
        f"expected the full command tree, got {len(ALL_COMMAND_PATHS)} paths: "
        f"{ALL_COMMAND_PATHS}"
    )


def test_skill_review_help_contains_literal_subpath_bracket():
    """Literal `[/subpath]` text must survive, not be swallowed by Rich markup."""
    result = runner.invoke(app, ["skill", "review", "--help"])
    assert result.exit_code == 0
    assert result.exception is None
    assert "[/subpath]" in result.output
    assert "[@version]" in result.output


@pytest.mark.parametrize("path", ALL_COMMAND_PATHS, ids=_id)
def test_help_does_not_crash(path: tuple[str, ...]):
    result = runner.invoke(app, [*path, "--help"])
    assert result.exit_code == 0, (
        f"`{_id(path)} --help` exited {result.exit_code}:\n{result.output}"
    )
    assert result.exception is None, (
        f"`{_id(path)} --help` raised: {result.exception!r}"
    )
