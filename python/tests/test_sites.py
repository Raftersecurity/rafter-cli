"""Tests for `rafter sites` CLI commands and the sites_* MCP tools.

Mirrors node/tests/sites-cli.test.ts and node/tests/mcp-sites.test.ts —
mocked requests only, no live API calls.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from rafter_cli.commands.sites import sites_app
from rafter_cli.commands.mcp_server import (
    handle_sites_create,
    handle_sites_get,
    handle_sites_list,
    handle_sites_scan,
)
from rafter_cli.utils.api import (
    EXIT_GENERAL_ERROR,
    EXIT_INSUFFICIENT_SCOPE,
    EXIT_QUOTA_EXHAUSTED,
    EXIT_SCAN_NOT_FOUND,
    EXIT_SUCCESS,
)

runner = CliRunner()


def _mock_response(status_code: int, json_body: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    resp.text = json.dumps(json_body) if json_body else ""
    return resp


# ── rafter sites create ──────────────────────────────────────────────


class TestSitesCreateCli:
    @patch("rafter_cli.commands.sites.requests.post")
    def test_success(self, mock_post):
        mock_post.return_value = _mock_response(
            200, {"site": {"id": "p1"}, "run": {"id": "r1"}, "created": True}
        )
        result = runner.invoke(
            sites_app, ["create", "https://example.com", "-k", "test-key"]
        )
        assert result.exit_code == EXIT_SUCCESS, result.output
        assert '"created": true' in result.output
        args, kwargs = mock_post.call_args
        assert args[0].endswith("/static/sites")
        assert kwargs["json"] == {"url": "https://example.com"}
        assert kwargs["headers"] == {"x-api-key": "test-key"}

    @patch("rafter_cli.commands.sites.requests.post")
    def test_401(self, mock_post):
        mock_post.return_value = _mock_response(401, {"error": "bad key"})
        result = runner.invoke(
            sites_app, ["create", "https://example.com", "-k", "test-key"]
        )
        assert result.exit_code == EXIT_GENERAL_ERROR

    @patch("rafter_cli.commands.sites.requests.post")
    def test_403_wrong_scope(self, mock_post):
        mock_post.return_value = _mock_response(
            403, {"error": "insufficient scope: requires read-and-scan"}
        )
        result = runner.invoke(
            sites_app, ["create", "https://example.com", "-k", "test-key"]
        )
        assert result.exit_code == EXIT_INSUFFICIENT_SCOPE

    @patch("rafter_cli.commands.sites.requests.post")
    def test_429(self, mock_post):
        mock_post.return_value = _mock_response(429, {"error": "Rate limit exceeded"})
        result = runner.invoke(
            sites_app, ["create", "https://example.com", "-k", "test-key"]
        )
        assert result.exit_code == EXIT_QUOTA_EXHAUSTED

    def test_rejects_format_md(self):
        result = runner.invoke(
            sites_app,
            ["create", "https://example.com", "-k", "test-key", "-f", "md"],
        )
        assert result.exit_code == EXIT_GENERAL_ERROR
        assert "does not support --format md" in result.output


# ── rafter sites scan ─────────────────────────────────────────────────


class TestSitesScanCli:
    @patch("rafter_cli.commands.sites.requests.post")
    def test_sends_project_id_for_bare_id(self, mock_post):
        mock_post.return_value = _mock_response(200, {"run": {"id": "r1"}})
        result = runner.invoke(sites_app, ["scan", "proj-123", "-k", "test-key"])
        assert result.exit_code == EXIT_SUCCESS, result.output
        _, kwargs = mock_post.call_args
        assert kwargs["json"] == {"projectId": "proj-123"}

    @patch("rafter_cli.commands.sites.requests.post")
    def test_sends_url_for_url(self, mock_post):
        mock_post.return_value = _mock_response(200, {"run": {"id": "r1"}})
        result = runner.invoke(
            sites_app, ["scan", "https://example.com", "-k", "test-key"]
        )
        assert result.exit_code == EXIT_SUCCESS
        _, kwargs = mock_post.call_args
        assert kwargs["json"] == {"url": "https://example.com"}

    @patch("rafter_cli.commands.sites.requests.post")
    def test_includes_sections(self, mock_post):
        mock_post.return_value = _mock_response(200, {"run": {"id": "r1"}})
        result = runner.invoke(
            sites_app,
            ["scan", "proj-123", "-k", "test-key", "--sections", "security, dns"],
        )
        assert result.exit_code == EXIT_SUCCESS
        _, kwargs = mock_post.call_args
        assert kwargs["json"] == {"projectId": "proj-123", "sections": ["security", "dns"]}

    @patch("rafter_cli.commands.sites.requests.post")
    def test_rejects_invalid_section(self, mock_post):
        result = runner.invoke(
            sites_app,
            ["scan", "proj-123", "-k", "test-key", "--sections", "bogus"],
        )
        assert result.exit_code == EXIT_GENERAL_ERROR
        mock_post.assert_not_called()

    @patch("rafter_cli.commands.sites.requests.post")
    def test_404_not_owned(self, mock_post):
        mock_post.return_value = _mock_response(404, {"error": "not found"})
        result = runner.invoke(sites_app, ["scan", "proj-123", "-k", "test-key"])
        assert result.exit_code == EXIT_SCAN_NOT_FOUND

    @patch("rafter_cli.commands.sites.requests.post")
    def test_403_run_limit(self, mock_post):
        mock_post.return_value = _mock_response(403, {"error": "run limit reached"})
        result = runner.invoke(sites_app, ["scan", "proj-123", "-k", "test-key"])
        assert result.exit_code == EXIT_INSUFFICIENT_SCOPE


# ── rafter sites list ─────────────────────────────────────────────────


class TestSitesListCli:
    @patch("rafter_cli.commands.sites.requests.get")
    def test_passes_pagination_params(self, mock_get):
        mock_get.return_value = _mock_response(
            200, {"sites": [], "limit": 10, "offset": 5, "has_more": False}
        )
        result = runner.invoke(
            sites_app,
            [
                "list",
                "-k", "test-key",
                "--limit", "10",
                "--offset", "5",
                "--include-archived",
            ],
        )
        assert result.exit_code == EXIT_SUCCESS, result.output
        _, kwargs = mock_get.call_args
        assert kwargs["params"] == {
            "limit": "10",
            "offset": "5",
            "include_archived": "true",
        }

    @patch("rafter_cli.commands.sites.requests.get")
    def test_401(self, mock_get):
        mock_get.return_value = _mock_response(401, {"error": "invalid key"})
        result = runner.invoke(sites_app, ["list", "-k", "test-key"])
        assert result.exit_code == EXIT_GENERAL_ERROR


# ── rafter sites get ──────────────────────────────────────────────────


class TestSitesGetCli:
    @patch("rafter_cli.commands.sites.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(
            200,
            {
                "site": {"id": "p1"},
                "latest_run": None,
                "security": {"critical": 0, "warn": 0, "info": 0, "total": 0},
            },
        )
        result = runner.invoke(sites_app, ["get", "p1", "-k", "test-key"])
        assert result.exit_code == EXIT_SUCCESS, result.output
        args, _ = mock_get.call_args
        assert args[0].endswith("/static/sites/p1")

    @patch("rafter_cli.commands.sites.requests.get")
    def test_404(self, mock_get):
        mock_get.return_value = _mock_response(404, {"error": "not found"})
        result = runner.invoke(sites_app, ["get", "nonexistent", "-k", "test-key"])
        assert result.exit_code == EXIT_SCAN_NOT_FOUND

    @patch("rafter_cli.commands.sites.requests.get")
    def test_429(self, mock_get):
        mock_get.return_value = _mock_response(
            429, {"error": "Rate limit exceeded", "retryAfter": 30}
        )
        result = runner.invoke(sites_app, ["get", "p1", "-k", "test-key"])
        assert result.exit_code == EXIT_QUOTA_EXHAUSTED


# ── MCP tool handlers ─────────────────────────────────────────────────


class TestMcpSitesCreate:
    @patch("rafter_cli.commands.mcp_server.requests.post")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_success(self, _mock_key, mock_post):
        mock_post.return_value = _mock_response(
            200, {"site": {"id": "p1"}, "run": {"id": "r1"}, "created": True}
        )
        result = handle_sites_create("https://example.com")
        assert result["created"] is True
        _, kwargs = mock_post.call_args
        assert kwargs["json"] == {"url": "https://example.com"}

    @patch("rafter_cli.commands.mcp_server.requests.post")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_401_raises(self, _mock_key, mock_post):
        mock_post.return_value = _mock_response(401, {"error": "invalid key"})
        with pytest.raises(RuntimeError, match="Unauthorized"):
            handle_sites_create("https://example.com")

    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value=None)
    def test_missing_key_raises_without_crashing(self, _mock_key):
        with pytest.raises(RuntimeError, match="No API key configured"):
            handle_sites_create("https://example.com")


class TestMcpSitesScan:
    @patch("rafter_cli.commands.mcp_server.requests.post")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_by_project_id(self, _mock_key, mock_post):
        mock_post.return_value = _mock_response(200, {"run": {"id": "r1"}})
        handle_sites_scan(project_id="proj-1")
        _, kwargs = mock_post.call_args
        assert kwargs["json"] == {"projectId": "proj-1"}

    def test_requires_project_id_or_url(self):
        with pytest.raises(RuntimeError, match="Provide projectId or url"):
            handle_sites_scan()

    def test_rejects_both_project_id_and_url(self):
        """Python builds this correctly from the start — the Node MCP tool
        currently doesn't reject the both-given case, only the neither-given
        case (a known bug being fixed concurrently on the Node side)."""
        with pytest.raises(RuntimeError, match="not both"):
            handle_sites_scan(project_id="proj-1", url="https://example.com")

    @patch("rafter_cli.commands.mcp_server.requests.post")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_404_not_owned(self, _mock_key, mock_post):
        mock_post.return_value = _mock_response(404, {"error": "not found"})
        with pytest.raises(RuntimeError, match="Not found"):
            handle_sites_scan(project_id="proj-1")


class TestMcpSitesList:
    @patch("rafter_cli.commands.mcp_server.requests.get")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_success_with_params(self, _mock_key, mock_get):
        mock_get.return_value = _mock_response(
            200, {"sites": [], "limit": 5, "offset": 0, "has_more": False}
        )
        handle_sites_list(limit=5, include_archived=True)
        _, kwargs = mock_get.call_args
        assert kwargs["params"] == {"limit": "5", "include_archived": "true"}

    @patch("rafter_cli.commands.mcp_server.requests.get")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_429_raises(self, _mock_key, mock_get):
        mock_get.return_value = _mock_response(429, {"error": "Rate limit exceeded"})
        with pytest.raises(RuntimeError, match="Rate limited"):
            handle_sites_list()


class TestMcpSitesGet:
    @patch("rafter_cli.commands.mcp_server.requests.get")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_success(self, _mock_key, mock_get):
        mock_get.return_value = _mock_response(
            200,
            {
                "site": {"id": "p1"},
                "latest_run": None,
                "security": {"critical": 0, "warn": 0, "info": 0, "total": 0},
            },
        )
        result = handle_sites_get("p1")
        assert result["site"]["id"] == "p1"

    @patch("rafter_cli.commands.mcp_server.requests.get")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_404_raises(self, _mock_key, mock_get):
        mock_get.return_value = _mock_response(404, {"error": "not found"})
        with pytest.raises(RuntimeError, match="Not found"):
            handle_sites_get("nonexistent")

    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value=None)
    def test_missing_key_raises_without_crashing(self, _mock_key):
        with pytest.raises(RuntimeError, match="No API key configured"):
            handle_sites_get("p1")
