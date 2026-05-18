"""MCP server exposing Rafter security tools to any MCP-compatible client."""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

import typer

from ..core.audit_logger import AuditLogger
from ..core.command_interceptor import CommandInterceptor
from ..core.config_manager import ConfigManager
from ..core.docs_loader import fetch_doc, list_docs, resolve_doc_selector
from ..scanners.betterleaks import BetterleaksScanner
from ..scanners.regex_scanner import RegexScanner

mcp_app = typer.Typer(
    name="mcp",
    help="MCP server for cross-platform security tools",
    no_args_is_help=True,
)


# ── Tool handler functions (importable for testing) ────────────────────
#
# Each handler accepts optional pre-built component instances so the MCP
# server can construct them once at startup and reuse them across calls.
# When called without overrides (e.g. directly from tests), components are
# built on demand — matching the original per-call behavior.
#
# Disk-backed state (config, audit log, policy) is re-read on each method
# call, so reusing components is safe. Caveat: AuditLogger log path and
# RegexScanner custom patterns are resolved at construction — changing
# those in .rafter.yml requires an MCP server restart to take effect.


def handle_scan_secrets(
    path: str,
    engine: str = "auto",
    betterleaks: Optional[BetterleaksScanner] = None,
    regex_scanner: Optional[RegexScanner] = None,
) -> list[dict]:
    """Scan files or directories for hardcoded secrets."""
    # Try betterleaks if requested or auto
    if engine in ("betterleaks", "auto"):
        bl = betterleaks if betterleaks is not None else BetterleaksScanner()
        if bl.is_available():
            try:
                results = bl.scan_directory(path)
                return [
                    {
                        "file": r.file,
                        "matches": [
                            {
                                "pattern": m.pattern.name,
                                "severity": m.pattern.severity,
                                "line": m.line,
                                "redacted": m.redacted or m.match[:4] + "****",
                            }
                            for m in r.matches
                        ],
                    }
                    for r in results
                ]
            except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
                if engine == "betterleaks":
                    raise
                print(f"rafter: betterleaks scan failed, falling back to patterns: {exc}", file=sys.stderr)
                # Fall through to patterns on auto

        elif engine == "betterleaks":
            raise RuntimeError("Betterleaks not installed")

    # Pattern-based scan
    scanner = regex_scanner if regex_scanner is not None else RegexScanner()
    try:
        results = scanner.scan_directory(path)
    except NotADirectoryError:
        results = [scanner.scan_file(path)]

    return [
        {
            "file": r.file,
            "matches": [
                {
                    "pattern": m.pattern.name,
                    "severity": m.pattern.severity,
                    "line": m.line,
                    "redacted": m.redacted or m.match[:4] + "****",
                }
                for m in r.matches
            ],
        }
        for r in results
    ]


def handle_evaluate_command(
    command: str,
    interceptor: Optional[CommandInterceptor] = None,
) -> dict:
    """Evaluate whether a shell command is allowed by Rafter policy."""
    interceptor = interceptor if interceptor is not None else CommandInterceptor()
    result = interceptor.evaluate(command)
    out: dict = {
        "allowed": result.allowed,
        "risk_level": result.risk_level,
        "requires_approval": result.requires_approval,
    }
    if result.reason:
        out["reason"] = result.reason
    return out


def handle_read_audit_log(
    limit: int = 20,
    event_type: str | None = None,
    since: str | None = None,
    logger: Optional[AuditLogger] = None,
) -> list[dict]:
    """Read Rafter audit log entries."""
    logger = logger if logger is not None else AuditLogger()
    since_dt = None
    if since:
        since_dt = datetime.fromisoformat(since)
        if since_dt.tzinfo is None:
            since_dt = since_dt.replace(tzinfo=timezone.utc)

    return logger.read(
        event_type=event_type,
        since=since_dt,
        limit=limit,
    )


def handle_get_config(
    key: str | None = None,
    manager: Optional[ConfigManager] = None,
) -> dict:
    """Read Rafter configuration."""
    manager = manager if manager is not None else ConfigManager()
    if key:
        return {"key": key, "value": manager.get(key)}
    return asdict(manager.load())


def handle_get_config_resource(manager: Optional[ConfigManager] = None) -> str:
    """Return full config as JSON string."""
    manager = manager if manager is not None else ConfigManager()
    return json.dumps(asdict(manager.load()), indent=2)


def handle_get_policy_resource(manager: Optional[ConfigManager] = None) -> str:
    """Return merged policy as JSON string."""
    manager = manager if manager is not None else ConfigManager()
    return json.dumps(asdict(manager.load_with_policy()), indent=2)


def handle_list_docs(tag: str | None = None) -> list[dict]:
    """List repo-specific security docs from .rafter.yml."""
    entries = list_docs()
    if tag:
        entries = [e for e in entries if tag in (e.tags or [])]
    return [
        {
            "id": e.id,
            "source": e.source,
            "source_kind": e.source_kind,
            "description": e.description or "",
            "tags": e.tags or [],
            "cache_status": e.cache_status,
        }
        for e in entries
    ]


def handle_get_doc(id_or_tag: str, refresh: bool = False) -> list[dict]:
    """Return content for docs matching id or tag."""
    matches = resolve_doc_selector(id_or_tag)
    if not matches:
        raise RuntimeError(f"No doc matched id or tag: {id_or_tag}")
    results = []
    for entry in matches:
        fetched = fetch_doc(entry, refresh=refresh)
        results.append({
            "id": entry["id"],
            "source": fetched.source,
            "source_kind": fetched.source_kind,
            "stale": fetched.stale,
            "content": fetched.content,
        })
    return results


def handle_get_docs_resource() -> str:
    """Return docs list metadata as JSON string."""
    return json.dumps(handle_list_docs(), indent=2)


# ── MCP server factory ────────────────────────────────────────────────


def create_mcp_server():
    """Build and return the FastMCP server instance."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("rafter")

    # Instantiate once per server: constructors do non-trivial work (pattern
    # compilation, log-path resolution). Disk-backed state is re-read on each
    # method call so reuse is safe. Caveat: log path and custom patterns are
    # resolved at construction — changing those in .rafter.yml requires
    # an MCP server restart.
    betterleaks = BetterleaksScanner()
    regex_scanner = RegexScanner()
    interceptor = CommandInterceptor()
    audit_logger = AuditLogger()
    config_manager = ConfigManager()

    @mcp.tool()
    def scan_secrets(path: str, engine: str = "auto") -> str:
        """Scan files or directories for hardcoded secrets and credentials.

        Args:
            path: File or directory path to scan.
            engine: Scan engine — auto (default), betterleaks, or patterns.
        """
        return json.dumps(handle_scan_secrets(
            path, engine,
            betterleaks=betterleaks,
            regex_scanner=regex_scanner,
        ))

    @mcp.tool()
    def evaluate_command(command: str) -> str:
        """Evaluate whether a shell command is allowed by Rafter security policy.

        Args:
            command: Shell command to evaluate.
        """
        return json.dumps(handle_evaluate_command(command, interceptor=interceptor))

    @mcp.tool()
    def read_audit_log(
        limit: int = 20,
        event_type: str | None = None,
        since: str | None = None,
    ) -> str:
        """Read Rafter audit log entries with optional filtering.

        Args:
            limit: Maximum entries to return (default 20).
            event_type: Filter by event type (e.g. command_intercepted, secret_detected).
            since: ISO 8601 timestamp — only return entries after this time.
        """
        return json.dumps(handle_read_audit_log(
            limit, event_type, since, logger=audit_logger,
        ))

    @mcp.tool()
    def get_config(key: str | None = None) -> str:
        """Read Rafter configuration (full config or a specific key).

        Args:
            key: Dot-path config key (e.g. agent.command_policy). Omit for full config.
        """
        return json.dumps(handle_get_config(key, manager=config_manager))

    @mcp.tool()
    def list_docs(tag: str | None = None) -> str:
        """List repo-specific security docs declared in .rafter.yml.

        Call this early in any security-relevant task to discover project-specific
        rules, threat models, or compliance policies the user expects agents to follow.

        Args:
            tag: Filter to docs whose tags include this value.
        """
        return json.dumps(handle_list_docs(tag))

    @mcp.tool()
    def get_doc(id_or_tag: str, refresh: bool = False) -> str:
        """Return the content of a repo-specific security doc by id or tag.

        Args:
            id_or_tag: Doc id or tag selector.
            refresh: Force re-fetch for URL-backed docs (bypass cache).
        """
        return json.dumps(handle_get_doc(id_or_tag, refresh))

    @mcp.resource("rafter://config")
    def config_resource() -> str:
        """Current Rafter configuration."""
        return handle_get_config_resource(manager=config_manager)

    @mcp.resource("rafter://policy")
    def policy_resource() -> str:
        """Active security policy (merged .rafter.yml + config)."""
        return handle_get_policy_resource(manager=config_manager)

    @mcp.resource("rafter://docs")
    def docs_resource() -> str:
        """Repo-specific security docs declared in .rafter.yml (metadata only)."""
        return handle_get_docs_resource()

    return mcp


# ── Typer command ──────────────────────────────────────────────────────


@mcp_app.command("serve")
def serve(
    transport: str = typer.Option("stdio", help="Transport type (currently only stdio)"),
) -> None:
    """Start MCP server over stdio transport."""
    mcp = create_mcp_server()
    mcp.run(transport=transport)
