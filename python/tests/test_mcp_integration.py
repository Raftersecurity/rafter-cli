"""MCP integration tests — exercises the Python MCP server over in-memory transport.

Mirrors node/tests/mcp-server-integration.test.ts.  Uses
``mcp.shared.memory.create_connected_server_and_client_session`` so the server
runs the real MCP protocol (JSON-RPC framing, tool/resource registration) without
needing stdio, which hangs in test harnesses.
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime
from unittest.mock import patch

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from rafter_cli.commands.mcp_server import create_mcp_server


# ---------------------------------------------------------------------------
# Helper — creates a fresh connected client for each test
# ---------------------------------------------------------------------------

@asynccontextmanager
async def mcp_client():
    server = create_mcp_server()
    async with create_connected_server_and_client_session(server) as c:
        yield c


# ---------------------------------------------------------------------------
# Tool registration & schema
# ---------------------------------------------------------------------------


class TestToolRegistration:
    @pytest.mark.asyncio
    async def test_registers_exactly_4_tools(self):
        async with mcp_client() as client:
            result = await client.list_tools()
            assert len(result.tools) == 4

    @pytest.mark.asyncio
    async def test_scan_secrets_schema(self):
        async with mcp_client() as client:
            result = await client.list_tools()
            tool = next(t for t in result.tools if t.name == "scan_secrets")
            assert "path" in tool.inputSchema["properties"]
            assert "engine" in tool.inputSchema["properties"]
            assert "path" in tool.inputSchema.get("required", [])

    @pytest.mark.asyncio
    async def test_evaluate_command_schema(self):
        async with mcp_client() as client:
            result = await client.list_tools()
            tool = next(t for t in result.tools if t.name == "evaluate_command")
            assert "command" in tool.inputSchema.get("required", [])

    @pytest.mark.asyncio
    async def test_read_audit_log_schema(self):
        async with mcp_client() as client:
            result = await client.list_tools()
            tool = next(t for t in result.tools if t.name == "read_audit_log")
            props = tool.inputSchema["properties"]
            assert "limit" in props
            assert "event_type" in props
            assert "since" in props

    @pytest.mark.asyncio
    async def test_get_config_schema(self):
        async with mcp_client() as client:
            result = await client.list_tools()
            tool = next(t for t in result.tools if t.name == "get_config")
            assert "key" in tool.inputSchema["properties"]

    @pytest.mark.asyncio
    async def test_tool_names_match_expected_set(self):
        async with mcp_client() as client:
            result = await client.list_tools()
            names = sorted(t.name for t in result.tools)
            assert names == ["evaluate_command", "get_config", "read_audit_log", "scan_secrets"]


# ---------------------------------------------------------------------------
# Resource registration
# ---------------------------------------------------------------------------


class TestResourceRegistration:
    @pytest.mark.asyncio
    async def test_registers_exactly_2_resources(self):
        async with mcp_client() as client:
            result = await client.list_resources()
            assert len(result.resources) == 2

    @pytest.mark.asyncio
    async def test_config_resource_registered(self):
        async with mcp_client() as client:
            result = await client.list_resources()
            uris = [str(r.uri) for r in result.resources]
            assert "rafter://config" in uris

    @pytest.mark.asyncio
    async def test_policy_resource_registered(self):
        async with mcp_client() as client:
            result = await client.list_resources()
            uris = [str(r.uri) for r in result.resources]
            assert "rafter://policy" in uris

    @pytest.mark.asyncio
    async def test_config_resource_returns_valid_json(self):
        async with mcp_client() as client:
            result = await client.read_resource("rafter://config")
            assert len(result.contents) == 1
            parsed = json.loads(result.contents[0].text)
            assert "version" in parsed
            assert "agent" in parsed

    @pytest.mark.asyncio
    async def test_policy_resource_returns_valid_json(self):
        async with mcp_client() as client:
            result = await client.read_resource("rafter://policy")
            assert len(result.contents) == 1
            parsed = json.loads(result.contents[0].text)
            assert "version" in parsed
            assert "agent" in parsed

    @pytest.mark.asyncio
    async def test_unknown_resource_raises(self):
        async with mcp_client() as client:
            with pytest.raises(Exception):
                await client.read_resource("rafter://nonexistent")


# ---------------------------------------------------------------------------
# Tool execution end-to-end
# ---------------------------------------------------------------------------


class TestToolExecution:
    @pytest.mark.asyncio
    async def test_scan_secrets_returns_results(self, tmp_path):
        secret_file = tmp_path / "creds.env"
        secret_file.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE1\n")

        async with mcp_client() as client:
            result = await client.call_tool("scan_secrets", {"path": str(tmp_path), "engine": "patterns"})
            assert not result.isError
            parsed = json.loads(result.content[0].text)
            files_with_matches = [f for f in parsed if f["matches"]]
            assert len(files_with_matches) >= 1
            assert "aws" in files_with_matches[0]["matches"][0]["pattern"].lower()

    @pytest.mark.asyncio
    async def test_scan_secrets_clean_dir(self, tmp_path):
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("x = 1 + 2\n")

        async with mcp_client() as client:
            result = await client.call_tool("scan_secrets", {"path": str(tmp_path), "engine": "patterns"})
            assert not result.isError
            parsed = json.loads(result.content[0].text)
            for entry in parsed:
                assert entry["matches"] == []

    @pytest.mark.asyncio
    async def test_scan_secrets_gitleaks_fallback(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("AKIAIOSFODNN7EXAMPLE1\n")

        with patch("rafter_cli.commands.mcp_server.GitleaksScanner") as mock_gl:
            mock_gl.return_value.is_available.return_value = False
            async with mcp_client() as client:
                result = await client.call_tool("scan_secrets", {"path": str(tmp_path), "engine": "auto"})

        assert not result.isError
        parsed = json.loads(result.content[0].text)
        files_with_matches = [f for f in parsed if f["matches"]]
        assert len(files_with_matches) >= 1

    @pytest.mark.asyncio
    async def test_evaluate_command_allows_safe(self):
        async with mcp_client() as client:
            result = await client.call_tool("evaluate_command", {"command": "ls -la"})
            assert not result.isError
            parsed = json.loads(result.content[0].text)
            assert parsed["allowed"] is True
            assert parsed["risk_level"] == "low"
            assert parsed["requires_approval"] is False

    @pytest.mark.asyncio
    async def test_evaluate_command_blocks_dangerous(self):
        async with mcp_client() as client:
            result = await client.call_tool("evaluate_command", {"command": "rm -rf /"})
            assert not result.isError
            parsed = json.loads(result.content[0].text)
            assert parsed["allowed"] is False
            assert "reason" in parsed

    @pytest.mark.asyncio
    async def test_read_audit_log_returns_entries(self):
        with patch("rafter_cli.commands.mcp_server.AuditLogger") as mock_cls:
            mock_cls.return_value.read.return_value = [
                {"event_type": "command_intercepted", "timestamp": "2026-01-01T00:00:00Z"}
            ]
            async with mcp_client() as client:
                result = await client.call_tool("read_audit_log", {"limit": 10})

        assert not result.isError
        parsed = json.loads(result.content[0].text)
        assert len(parsed) == 1
        assert parsed[0]["event_type"] == "command_intercepted"

    @pytest.mark.asyncio
    async def test_read_audit_log_passes_filters(self):
        with patch("rafter_cli.commands.mcp_server.AuditLogger") as mock_cls:
            mock_cls.return_value.read.return_value = []
            async with mcp_client() as client:
                await client.call_tool("read_audit_log", {
                    "limit": 5,
                    "event_type": "secret_detected",
                    "since": "2026-01-01T00:00:00Z",
                })

            call_kwargs = mock_cls.return_value.read.call_args[1]
            assert call_kwargs["event_type"] == "secret_detected"
            assert call_kwargs["limit"] == 5
            assert isinstance(call_kwargs["since"], datetime)

    @pytest.mark.asyncio
    async def test_get_config_returns_full_config(self):
        async with mcp_client() as client:
            result = await client.call_tool("get_config", {})
            assert not result.isError
            parsed = json.loads(result.content[0].text)
            assert "version" in parsed
            assert "agent" in parsed

    @pytest.mark.asyncio
    async def test_get_config_returns_specific_key(self):
        async with mcp_client() as client:
            result = await client.call_tool("get_config", {"key": "agent.risk_level"})
            assert not result.isError
            parsed = json.loads(result.content[0].text)
            assert parsed["key"] == "agent.risk_level"
            assert parsed["value"] is not None


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_connect_without_errors(self):
        async with mcp_client() as client:
            tools = await client.list_tools()
            assert len(tools.tools) == 4

    @pytest.mark.asyncio
    async def test_multiple_sequential_sessions(self):
        for _ in range(3):
            async with mcp_client() as client:
                tools = await client.list_tools()
                assert len(tools.tools) == 4
