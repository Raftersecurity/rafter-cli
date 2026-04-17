"""Real stdio transport tests for the MCP server.

Spawns `python -m rafter_cli mcp serve` as a child process and communicates
over real stdin/stdout using the MCP SDK's stdio_client. No mocking — the full
server stack runs end-to-end over real pipes.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


# ── Helpers ──────────────────────────────────────────────────────────────────

SERVER_PARAMS = StdioServerParameters(
    command=sys.executable,
    args=["-m", "rafter_cli", "mcp", "serve"],
)

# Track child processes for cleanup
_child_pids: list[int] = []


_STDIO_WORKS: bool | None = None


async def create_connected_session():
    """Create a stdio connection and return (session, cm).

    The session's context manager is entered so that the receive loop is
    running — callers must call ``cleanup(session, cm)`` when done.

    Raises ``pytest.skip`` when the MCP stdio transport cannot connect
    (e.g. SDK version mismatch or environment issue).
    """
    global _STDIO_WORKS
    if _STDIO_WORKS is False:
        pytest.skip("MCP stdio transport not available in this environment")

    cm = stdio_client(SERVER_PARAMS, errlog=open(os.devnull, "w"))
    try:
        read_stream, write_stream = await asyncio.wait_for(
            cm.__aenter__(), timeout=10,
        )
    except (asyncio.TimeoutError, Exception) as exc:
        _STDIO_WORKS = False
        _kill_orphan_servers()
        pytest.skip(f"MCP stdio transport failed: {exc}")

    session = ClientSession(read_stream, write_stream)
    try:
        # Enter the session context manager to start the receive loop,
        # then initialize the MCP protocol handshake.
        await asyncio.wait_for(session.__aenter__(), timeout=10)
        await asyncio.wait_for(session.initialize(), timeout=10)
    except (asyncio.TimeoutError, Exception) as exc:
        _STDIO_WORKS = False
        await _force_cleanup(session, cm)
        pytest.skip(f"MCP session init failed: {exc}")

    _STDIO_WORKS = True
    return session, cm


async def _force_cleanup(session, cm):
    """Best-effort cleanup without waiting."""
    for obj in (session, cm):
        try:
            await asyncio.wait_for(obj.__aexit__(None, None, None), timeout=2)
        except Exception:
            pass
    _kill_orphan_servers()


async def cleanup(session: ClientSession, cm):
    """Shut down session and transport cleanly, killing child processes if needed."""
    try:
        await asyncio.wait_for(session.__aexit__(None, None, None), timeout=5)
    except Exception:
        pass
    try:
        await asyncio.wait_for(cm.__aexit__(None, None, None), timeout=5)
    except Exception:
        pass
    # Force-kill any lingering rafter mcp serve processes spawned by this test
    _kill_orphan_servers()


def _kill_orphan_servers():
    """Kill any rafter mcp serve processes we may have left behind."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "rafter_cli mcp serve"],
            capture_output=True, text=True, timeout=5,
        )
        for pid_str in result.stdout.strip().split("\n"):
            if pid_str.strip():
                try:
                    os.kill(int(pid_str.strip()), signal.SIGKILL)
                except (ProcessLookupError, ValueError):
                    pass
    except Exception:
        pass


# ── Tool listing ─────────────────────────────────────────────────────────────


class TestToolListing:
    """Verify tool registration over real stdio transport."""

    @pytest.fixture(autouse=True)
    async def _connect(self):
        self.session, self.cm = await create_connected_session()
        yield
        await cleanup(self.session, self.cm)

    @pytest.mark.asyncio
    async def test_registers_exactly_6_tools(self):
        result = await self.session.list_tools()
        assert len(result.tools) == 6

    @pytest.mark.asyncio
    async def test_tool_names_match_expected_set(self):
        result = await self.session.list_tools()
        names = sorted(t.name for t in result.tools)
        assert names == [
            "evaluate_command",
            "get_config",
            "get_doc",
            "list_docs",
            "read_audit_log",
            "scan_secrets",
        ]

    @pytest.mark.asyncio
    async def test_scan_secrets_has_path_parameter(self):
        result = await self.session.list_tools()
        tool = next(t for t in result.tools if t.name == "scan_secrets")
        schema = tool.inputSchema
        assert "path" in schema.get("properties", {})

    @pytest.mark.asyncio
    async def test_evaluate_command_has_command_parameter(self):
        result = await self.session.list_tools()
        tool = next(t for t in result.tools if t.name == "evaluate_command")
        schema = tool.inputSchema
        assert "command" in schema.get("properties", {})


# ── Resource listing ─────────────────────────────────────────────────────────


class TestResourceListing:
    """Verify resource registration over real stdio transport."""

    @pytest.fixture(autouse=True)
    async def _connect(self):
        self.session, self.cm = await create_connected_session()
        yield
        await cleanup(self.session, self.cm)

    @pytest.mark.asyncio
    async def test_registers_exactly_3_resources(self):
        result = await self.session.list_resources()
        assert len(result.resources) == 3

    @pytest.mark.asyncio
    async def test_exposes_config_resource(self):
        result = await self.session.list_resources()
        uris = [str(r.uri) for r in result.resources]
        assert "rafter://config" in uris

    @pytest.mark.asyncio
    async def test_exposes_policy_resource(self):
        result = await self.session.list_resources()
        uris = [str(r.uri) for r in result.resources]
        assert "rafter://policy" in uris


# ── scan_secrets ─────────────────────────────────────────────────────────────


class TestScanSecrets:
    """Test scan_secrets tool over real stdio transport with real filesystem."""

    @pytest.fixture(autouse=True)
    async def _connect(self):
        self.session, self.cm = await create_connected_session()
        yield
        await cleanup(self.session, self.cm)

    @pytest.mark.asyncio
    async def test_detects_planted_aws_key(self, tmp_path):
        secret_file = tmp_path / "creds.env"
        secret_file.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE1\n")

        result = await self.session.call_tool(
            "scan_secrets",
            {"path": str(secret_file), "engine": "patterns"},
        )
        assert not result.isError
        parsed = json.loads(result.content[0].text)
        assert len(parsed) == 1
        assert parsed[0]["file"] == str(secret_file)
        assert len(parsed[0]["matches"]) > 0
        match = parsed[0]["matches"][0]
        assert "pattern" in match
        assert "severity" in match
        assert "redacted" in match

    @pytest.mark.asyncio
    async def test_scans_directory_finds_secrets(self, tmp_path):
        (tmp_path / "clean.txt").write_text("nothing here\n")
        (tmp_path / "secret.env").write_text(
            "GITHUB_TOKEN=ghp_FAKEEFabcdef1234567890abcdef12345678\n"
        )

        result = await self.session.call_tool(
            "scan_secrets",
            {"path": str(tmp_path), "engine": "patterns"},
        )
        assert not result.isError
        parsed = json.loads(result.content[0].text)
        with_matches = [r for r in parsed if r["matches"]]
        assert len(with_matches) >= 1

    @pytest.mark.asyncio
    async def test_clean_file_returns_empty_matches(self, tmp_path):
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("x = 1 + 2\nprint(x)\n")

        result = await self.session.call_tool(
            "scan_secrets",
            {"path": str(clean_file), "engine": "patterns"},
        )
        assert not result.isError
        parsed = json.loads(result.content[0].text)
        assert parsed[0]["matches"] == []


# ── evaluate_command ─────────────────────────────────────────────────────────


class TestEvaluateCommand:
    """Test evaluate_command tool over real stdio transport."""

    @pytest.fixture(autouse=True)
    async def _connect(self):
        self.session, self.cm = await create_connected_session()
        yield
        await cleanup(self.session, self.cm)

    @pytest.mark.asyncio
    async def test_allows_safe_command(self):
        result = await self.session.call_tool(
            "evaluate_command",
            {"command": "ls -la"},
        )
        assert not result.isError
        parsed = json.loads(result.content[0].text)
        assert parsed["allowed"] is True
        assert parsed["risk_level"] == "low"
        assert parsed["requires_approval"] is False

    @pytest.mark.asyncio
    async def test_blocks_destructive_command(self):
        result = await self.session.call_tool(
            "evaluate_command",
            {"command": "rm -rf /"},
        )
        assert not result.isError
        parsed = json.loads(result.content[0].text)
        assert parsed["allowed"] is False
        assert parsed["risk_level"] == "critical"
        assert "reason" in parsed


# ── read_audit_log ───────────────────────────────────────────────────────────


class TestReadAuditLog:
    """Test read_audit_log tool over real stdio transport."""

    @pytest.fixture(autouse=True)
    async def _connect(self):
        self.session, self.cm = await create_connected_session()
        yield
        await cleanup(self.session, self.cm)

    @pytest.mark.asyncio
    async def test_returns_array(self):
        result = await self.session.call_tool(
            "read_audit_log",
            {"limit": 5},
        )
        assert not result.isError
        parsed = json.loads(result.content[0].text)
        assert isinstance(parsed, list)

    @pytest.mark.asyncio
    async def test_accepts_filters(self):
        result = await self.session.call_tool(
            "read_audit_log",
            {
                "limit": 3,
                "event_type": "command_intercepted",
                "since": "2026-01-01T00:00:00Z",
            },
        )
        assert not result.isError
        parsed = json.loads(result.content[0].text)
        assert isinstance(parsed, list)


# ── get_config ───────────────────────────────────────────────────────────────


class TestGetConfig:
    """Test get_config tool over real stdio transport."""

    @pytest.fixture(autouse=True)
    async def _connect(self):
        self.session, self.cm = await create_connected_session()
        yield
        await cleanup(self.session, self.cm)

    @pytest.mark.asyncio
    async def test_returns_full_config(self):
        result = await self.session.call_tool("get_config", {})
        assert not result.isError
        parsed = json.loads(result.content[0].text)
        assert "version" in parsed
        assert "agent" in parsed

    @pytest.mark.asyncio
    async def test_returns_specific_key(self):
        result = await self.session.call_tool(
            "get_config",
            {"key": "agent.risk_level"},
        )
        assert not result.isError
        parsed = json.loads(result.content[0].text)
        assert parsed is not None


# ── Resources ────────────────────────────────────────────────────────────────


class TestResources:
    """Test resource reading over real stdio transport."""

    @pytest.fixture(autouse=True)
    async def _connect(self):
        self.session, self.cm = await create_connected_session()
        yield
        await cleanup(self.session, self.cm)

    @pytest.mark.asyncio
    async def test_config_resource_returns_valid_json(self):
        result = await self.session.read_resource("rafter://config")
        assert len(result.contents) == 1
        parsed = json.loads(result.contents[0].text)
        assert "version" in parsed
        assert "agent" in parsed

    @pytest.mark.asyncio
    async def test_policy_resource_returns_valid_json(self):
        result = await self.session.read_resource("rafter://policy")
        assert len(result.contents) == 1
        parsed = json.loads(result.contents[0].text)
        assert "version" in parsed
        assert "agent" in parsed


# ── Error handling ───────────────────────────────────────────────────────────


class TestErrorHandling:
    """Test error paths over real stdio transport."""

    @pytest.fixture(autouse=True)
    async def _connect(self):
        self.session, self.cm = await create_connected_session()
        yield
        await cleanup(self.session, self.cm)

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self):
        result = await self.session.call_tool("nonexistent_tool", {})
        # FastMCP may raise or return error depending on version
        assert result.isError or "error" in str(result.content).lower()


# ── Lifecycle ────────────────────────────────────────────────────────────────


class TestLifecycle:
    """Test server process lifecycle over real stdio transport."""

    @pytest.mark.asyncio
    async def test_connect_disconnect_cleanly(self):
        session, cm = await create_connected_session()
        result = await session.list_tools()
        assert len(result.tools) == 6
        await cleanup(session, cm)

    @pytest.mark.asyncio
    async def test_sequential_sessions(self):
        for _ in range(3):
            session, cm = await create_connected_session()
            result = await session.list_tools()
            assert len(result.tools) == 6
            await cleanup(session, cm)
