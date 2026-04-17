"""Repo-specific security docs declared in .rafter.yml."""
from __future__ import annotations

import json
import sys
from dataclasses import asdict

import typer

from ..core.docs_loader import fetch_doc, list_docs, resolve_doc_selector
from ..core.policy_loader import load_policy


docs_app = typer.Typer(
    name="docs",
    help="Repo-specific security docs declared in .rafter.yml",
    no_args_is_help=True,
)


@docs_app.command("list")
def list_command(
    tag: str | None = typer.Option(None, "--tag", help="Filter to docs matching this tag"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """List security docs declared in .rafter.yml."""
    entries = list_docs()
    if tag:
        entries = [e for e in entries if tag in (e.tags or [])]

    if not entries:
        if json_output:
            typer.echo("[]")
        else:
            typer.echo("No docs configured in .rafter.yml", err=True)
        raise typer.Exit(code=3)

    if json_output:
        typer.echo(json.dumps([_as_list_entry(e) for e in entries], indent=2))
        return

    for e in entries:
        tag_str = f" [{', '.join(e.tags)}]" if e.tags else ""
        cache_str = f" ({e.cache_status})" if e.source_kind == "url" else ""
        desc_str = f" — {e.description}" if e.description else ""
        typer.echo(f"{e.id}  {e.source}{cache_str}{tag_str}{desc_str}")


@docs_app.command("show")
def show_command(
    id_or_tag: str = typer.Argument(..., help="Doc id or tag selector"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch for URL-backed docs"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Print the content of a doc by id or tag."""
    entries = resolve_doc_selector(id_or_tag)
    if not entries:
        policy = load_policy()
        if not policy or not policy.get("docs"):
            typer.echo("No docs configured in .rafter.yml", err=True)
            raise typer.Exit(code=3)
        typer.echo(f"No doc matched id or tag: {id_or_tag}", err=True)
        raise typer.Exit(code=2)

    results: list[dict] = []
    any_error = False
    for entry in entries:
        try:
            fetched = fetch_doc(entry, refresh=refresh)
            results.append({
                "id": entry["id"],
                "source": fetched.source,
                "source_kind": fetched.source_kind,
                "stale": fetched.stale,
                "content": fetched.content,
            })
            if fetched.stale:
                typer.echo(
                    f"Warning: {entry['id']} served from stale cache (fetch failed)",
                    err=True,
                )
        except Exception as exc:
            any_error = True
            typer.echo(f"Error: failed to fetch {entry['id']}: {exc}", err=True)

    if not results:
        raise typer.Exit(code=1)

    if json_output:
        typer.echo(json.dumps(results, indent=2))
    elif len(results) == 1:
        body = results[0]["content"]
        sys.stdout.write(body)
        if not body.endswith("\n"):
            sys.stdout.write("\n")
    else:
        for r in results:
            sys.stdout.write(f"\n===== {r['id']} ({r['source']}) =====\n")
            sys.stdout.write(r["content"])
            if not r["content"].endswith("\n"):
                sys.stdout.write("\n")

    if any_error:
        raise typer.Exit(code=1)


def _as_list_entry(doc) -> dict:
    d = asdict(doc)
    # Normalize keys to snake_case schema used in JSON output
    return {
        "id": d["id"],
        "source": d["source"],
        "source_kind": d["source_kind"],
        "description": d["description"] or "",
        "tags": d["tags"] or [],
        "cache_status": d["cache_status"],
    }
