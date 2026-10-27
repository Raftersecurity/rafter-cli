"""rafter gates — map a codebase's security gates for an audit."""
from __future__ import annotations

import json
import os
import sys

import typer

from ..scanners.gate_scanner import format_gate_map, map_gates


def gates_main(
    path: str = typer.Argument(".", help="Directory or file to map"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    limit: str = typer.Option("60", "--limit", help="Number of ranked gates to show"),
    gitignore: bool = typer.Option(True, "--gitignore/--no-gitignore", help="Honor .gitignore (default: on)"),
) -> None:
    """Map a codebase's security gates (functions that decide whether something is allowed) and their twins, for an audit."""
    if not limit.isdigit() or int(limit) < 1:
        typer.echo(f"Error: --limit must be a positive integer, got: {limit}", err=True)
        raise typer.Exit(code=2)
    resolved = os.path.abspath(path)
    if not os.path.exists(resolved):
        typer.echo(f"Error: Path not found: {resolved}", err=True)
        raise typer.Exit(code=2)
    gate_map = map_gates(resolved, limit=int(limit), respect_gitignore=gitignore)
    if json_output:
        sys.stdout.write(json.dumps(gate_map, indent=2, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(format_gate_map(gate_map))
