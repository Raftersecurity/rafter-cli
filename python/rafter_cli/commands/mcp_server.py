"""MCP server exposing Rafter security tools to any MCP-compatible client."""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone

import typer

from ..core.audit_logger import AuditLogger
from ..core.command_interceptor import CommandInterceptor
from ..core.config_manager import ConfigManager
from ..scanners.gitleaks import GitleaksScanner
from ..scanners.regex_scanner import RegexScanner

mcp_app = typer.Typer(
    name="mcp",
    help="MCP server for cross-platform security tools",
    no_args_is_help=True,
)


# ── Tool handler functions (importable for testing) ────────────────────


def handle_scan_secrets(path: str, engine: str = "auto") -> list[dict]:
    """Scan files or directories for hardcoded secrets."""
    # Try gitleaks if requested or auto
    if engine in ("gitleaks", "auto"):
        gl = GitleaksScanner()
        if gl.is_available():
            try:
                results = gl.scan_directory(path)
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
                if engine == "gitleaks":
                    raise
                print(f"rafter: gitleaks scan failed, falling back to patterns: {exc}", file=sys.stderr)
                # Fall through to patterns on auto

        elif engine == "gitleaks":
            raise RuntimeError("Gitleaks not installed")

    # Pattern-based scan
    scanner = RegexScanner()
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


def handle_evaluate_command(command: str) -> dict:
    """Evaluate whether a shell command is allowed by Rafter policy."""
    interceptor = CommandInterceptor()
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
) -> list[dict]:
    """Read Rafter audit log entries."""
    logger = AuditLogger()
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


def handle_get_config(key: str | None = None) -> dict:
    """Read Rafter configuration."""
    manager = ConfigManager()
    if key:
        return {"key": key, "value": manager.get(key)}
    return asdict(manager.load())


def handle_get_config_resource() -> str:
    """Return full config as JSON string."""
    manager = ConfigManager()
    return json.dumps(asdict(manager.load()), indent=2)


def handle_get_policy_resource() -> str:
    """Return merged policy as JSON string."""
    manager = ConfigManager()
    return json.dumps(asdict(manager.load_with_policy()), indent=2)


# ── MCP server factory ────────────────────────────────────────────────


def create_mcp_server():
    """Build and return the FastMCP server instance."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("rafter")

    @mcp.tool()
    def scan_secrets(path: str, engine: str = "auto") -> str:
        """Scan files or directories for hardcoded secrets and credentials.

        Args:
            path: File or directory path to scan.
            engine: Scan engine — auto (default), gitleaks, or patterns.
        """
        return json.dumps(handle_scan_secrets(path, engine))

    @mcp.tool()
    def evaluate_command(command: str) -> str:
        """Evaluate whether a shell command is allowed by Rafter security policy.

        Args:
            command: Shell command to evaluate.
        """
        return json.dumps(handle_evaluate_command(command))

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
        return json.dumps(handle_read_audit_log(limit, event_type, since))

    @mcp.tool()
    def get_config(key: str | None = None) -> str:
        """Read Rafter configuration (full config or a specific key).

        Args:
            key: Dot-path config key (e.g. agent.command_policy). Omit for full config.
        """
        return json.dumps(handle_get_config(key))

    @mcp.resource("rafter://config")
    def config_resource() -> str:
        """Current Rafter configuration."""
        return handle_get_config_resource()

    @mcp.resource("rafter://policy")
    def policy_resource() -> str:
        """Active security policy (merged .rafter.yml + config)."""
        return handle_get_policy_resource()

    return mcp


# ── Typer command ──────────────────────────────────────────────────────


@mcp_app.command("serve")
def serve(
    transport: str = typer.Option("stdio", help="Transport type (currently only stdio)"),
) -> None:
    """Start MCP server over stdio transport."""
    mcp = create_mcp_server()
    mcp.run(transport=transport)
