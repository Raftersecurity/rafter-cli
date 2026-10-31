"""Tests for `rafter sites` CLI commands and the sites_* MCP tools.

Mirrors node/tests/sites-cli.test.ts and node/tests/mcp-sites.test.ts —
mocked requests only, no live API calls.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from rafter_cli.commands.sites import sites_app, strip_control_chars_for_display
from rafter_cli.commands.sites_wait import EXIT_WAIT_INTERRUPTED, parse_wait_timeout, wait_for_site_run
from rafter_cli.commands.mcp_server import (
    handle_sites_create,
    handle_sites_get,
    handle_sites_list,
    handle_sites_report,
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


def _mock_text_response(status_code: int, text: str) -> MagicMock:
    """A response whose body is plain text (e.g. `format=md`), not JSON."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def _fake_clock(values: "list[float]"):
    """A clock that returns scripted values in order, and raises rather than
    let a broken guard loop forever if it's read more times than scripted."""
    it = iter(values)

    def _now() -> float:
        try:
            return next(it)
        except StopIteration:
            raise AssertionError("now() called more times than scripted — the poll loop didn't stop")

    return _now


# ── rafter sites create ──────────────────────────────────────────────


class TestSitesCreateCli:
    @patch("rafter_cli.commands.sites.api_post")
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

    @patch("rafter_cli.commands.sites.api_post")
    def test_401(self, mock_post):
        mock_post.return_value = _mock_response(401, {"error": "bad key"})
        result = runner.invoke(
            sites_app, ["create", "https://example.com", "-k", "test-key"]
        )
        assert result.exit_code == EXIT_GENERAL_ERROR

    @patch("rafter_cli.commands.sites.api_post")
    def test_403_wrong_scope(self, mock_post):
        mock_post.return_value = _mock_response(
            403, {"error": "insufficient scope: requires read-and-scan"}
        )
        result = runner.invoke(
            sites_app, ["create", "https://example.com", "-k", "test-key"]
        )
        assert result.exit_code == EXIT_INSUFFICIENT_SCOPE

    @patch("rafter_cli.commands.sites.api_post")
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
    @patch("rafter_cli.commands.sites.api_post")
    def test_sends_project_id_for_bare_id(self, mock_post):
        mock_post.return_value = _mock_response(200, {"run": {"id": "r1"}})
        result = runner.invoke(sites_app, ["scan", "proj-123", "-k", "test-key"])
        assert result.exit_code == EXIT_SUCCESS, result.output
        _, kwargs = mock_post.call_args
        assert kwargs["json"] == {"projectId": "proj-123"}

    @patch("rafter_cli.commands.sites.api_post")
    def test_sends_url_for_url(self, mock_post):
        mock_post.return_value = _mock_response(200, {"run": {"id": "r1"}})
        result = runner.invoke(
            sites_app, ["scan", "https://example.com", "-k", "test-key"]
        )
        assert result.exit_code == EXIT_SUCCESS
        _, kwargs = mock_post.call_args
        assert kwargs["json"] == {"url": "https://example.com"}

    @patch("rafter_cli.commands.sites.api_post")
    def test_includes_sections(self, mock_post):
        mock_post.return_value = _mock_response(200, {"run": {"id": "r1"}})
        result = runner.invoke(
            sites_app,
            ["scan", "proj-123", "-k", "test-key", "--sections", "security, dns"],
        )
        assert result.exit_code == EXIT_SUCCESS
        _, kwargs = mock_post.call_args
        assert kwargs["json"] == {"projectId": "proj-123", "sections": ["security", "dns"]}

    @patch("rafter_cli.commands.sites.api_post")
    def test_rejects_invalid_section(self, mock_post):
        result = runner.invoke(
            sites_app,
            ["scan", "proj-123", "-k", "test-key", "--sections", "bogus"],
        )
        assert result.exit_code == EXIT_GENERAL_ERROR
        mock_post.assert_not_called()

    @patch("rafter_cli.commands.sites.api_post")
    def test_404_not_owned(self, mock_post):
        mock_post.return_value = _mock_response(404, {"error": "not found"})
        result = runner.invoke(sites_app, ["scan", "proj-123", "-k", "test-key"])
        assert result.exit_code == EXIT_SCAN_NOT_FOUND

    @patch("rafter_cli.commands.sites.api_post")
    def test_403_run_limit(self, mock_post):
        mock_post.return_value = _mock_response(403, {"error": "run limit reached"})
        result = runner.invoke(sites_app, ["scan", "proj-123", "-k", "test-key"])
        assert result.exit_code == EXIT_INSUFFICIENT_SCOPE


# ── --wait/--timeout wiring on create/scan ────────────────────────────
#
# These exercise only the CLI-level wiring (resolving site id/run id and
# forwarding --timeout), with wait_for_site_run itself mocked out. The
# polling semantics (succeeded/failed/mismatch/timeout) are unit-tested
# directly against wait_for_site_run below (TestWaitForSiteRun), where a
# fake clock/sleep make them hermetic and fast instead of needing a CLI flag
# that doesn't exist in production.


class TestSitesCreateWait:
    @patch("rafter_cli.commands.sites_wait.wait_for_site_run")
    @patch("rafter_cli.commands.sites.api_post")
    def test_waits_on_the_created_site_and_run(self, mock_post, mock_wait):
        mock_post.return_value = _mock_response(
            200, {"site": {"id": "p1"}, "run": {"id": "r1"}, "created": True}
        )
        mock_wait.return_value = EXIT_SUCCESS
        result = runner.invoke(
            sites_app, ["create", "https://example.com", "-k", "test-key", "--wait"]
        )
        assert result.exit_code == EXIT_SUCCESS, result.output
        args, kwargs = mock_wait.call_args
        assert args[0] == "p1"
        assert args[1] == "r1"
        assert kwargs["timeout_seconds"] == 900

    @patch("rafter_cli.commands.sites_wait.wait_for_site_run")
    @patch("rafter_cli.commands.sites.api_post")
    def test_passes_through_a_custom_timeout(self, mock_post, mock_wait):
        mock_post.return_value = _mock_response(
            200, {"site": {"id": "p1"}, "run": {"id": "r1"}, "created": True}
        )
        mock_wait.return_value = EXIT_SUCCESS
        runner.invoke(
            sites_app,
            ["create", "https://example.com", "-k", "test-key", "--wait", "--timeout", "30"],
        )
        _, kwargs = mock_wait.call_args
        assert kwargs["timeout_seconds"] == 30.0

    @patch("rafter_cli.commands.sites_wait.wait_for_site_run")
    def test_rejects_a_non_positive_timeout_before_any_request(self, mock_wait):
        with patch("rafter_cli.commands.sites.api_post") as mock_post:
            result = runner.invoke(
                sites_app,
                ["create", "https://example.com", "-k", "test-key", "--wait", "--timeout", "0"],
            )
            assert result.exit_code == EXIT_GENERAL_ERROR
            mock_post.assert_not_called()
        mock_wait.assert_not_called()

    @patch("rafter_cli.commands.sites_wait.wait_for_site_run")
    @patch("rafter_cli.commands.sites.api_post")
    def test_no_run_started_skips_waiting_and_returns_plain_result(self, mock_post, mock_wait):
        # Fails if --wait tries to poll when create's `run` came back null
        # (site already existed, or the first scan failed to kick off).
        mock_post.return_value = _mock_response(
            200, {"site": {"id": "p1", "is_archived": False}, "run": None, "created": False}
        )
        result = runner.invoke(
            sites_app, ["create", "https://example.com", "-k", "test-key", "--wait"]
        )
        assert result.exit_code == EXIT_SUCCESS, result.output
        assert "nothing to wait for" in result.output
        mock_wait.assert_not_called()


class TestSitesScanWait:
    @patch("rafter_cli.commands.sites_wait.wait_for_site_run")
    @patch("rafter_cli.commands.sites.api_post")
    def test_waits_using_the_given_project_id(self, mock_post, mock_wait):
        mock_post.return_value = _mock_response(200, {"run": {"id": "r1"}})
        mock_wait.return_value = EXIT_SUCCESS
        result = runner.invoke(
            sites_app, ["scan", "proj-123", "-k", "test-key", "--wait"]
        )
        assert result.exit_code == EXIT_SUCCESS, result.output
        args, _ = mock_wait.call_args
        assert args[0] == "proj-123"
        assert args[1] == "r1"

    @patch("rafter_cli.commands.sites_wait.wait_for_site_run")
    @patch("rafter_cli.commands.sites.api_post")
    def test_uses_run_project_id_when_given_a_url(self, mock_post, mock_wait):
        mock_post.return_value = _mock_response(200, {"run": {"id": "r1", "project_id": "p1"}})
        mock_wait.return_value = EXIT_SUCCESS
        result = runner.invoke(
            sites_app, ["scan", "https://example.com", "-k", "test-key", "--wait"]
        )
        assert result.exit_code == EXIT_SUCCESS, result.output
        args, _ = mock_wait.call_args
        assert args[0] == "p1"

    @patch("rafter_cli.commands.sites_wait.wait_for_site_run")
    @patch("rafter_cli.commands.sites.api_post")
    def test_url_with_no_site_id_in_response_refuses_to_guess(self, mock_post, mock_wait):
        # Fails if --wait silently polls the raw URL as if it were a site id.
        mock_post.return_value = _mock_response(200, {"run": {"id": "r1"}})
        result = runner.invoke(
            sites_app, ["scan", "https://example.com", "-k", "test-key", "--wait"]
        )
        assert result.exit_code == EXIT_GENERAL_ERROR
        mock_wait.assert_not_called()


class TestWaitForSiteRun:
    """Direct, hermetic tests of the polling semantics. sleep/now are
    injected so these run in well under a second with no real waiting."""

    @patch("rafter_cli.commands.sites_wait.api_get")
    def test_polls_until_succeeded_and_prints_final_payload(self, mock_get):
        mock_get.side_effect = [
            _mock_response(200, {"latest_run": {"id": "r1", "status": "running"}}),
            _mock_response(200, {"latest_run": {"id": "r1", "status": "succeeded"}}),
        ]
        code = wait_for_site_run(
            "p1", "r1", "test-key", "json", True,
            timeout_seconds=900, poll_interval_seconds=0,
            sleep=lambda s: None, now=_fake_clock([0, 0]),
        )
        assert code == EXIT_SUCCESS
        assert mock_get.call_args_list[0].args[0].endswith("/static/sites/p1")

    @patch("rafter_cli.commands.sites_wait.api_get")
    def test_exits_1_when_the_run_fails(self, mock_get):
        # A single scripted response: if the terminal-status check ever
        # stops firing, a second (unscripted) call raises immediately
        # instead of looping forever on a mocked GET that never changes.
        mock_get.side_effect = [_mock_response(200, {"latest_run": {"id": "r1", "status": "failed"}})]
        code = wait_for_site_run(
            "p1", "r1", "test-key", "json", True,
            timeout_seconds=900, poll_interval_seconds=0,
            sleep=lambda s: None, now=_fake_clock([0, 0]),
        )
        assert code == EXIT_GENERAL_ERROR

    def test_exits_1_and_names_both_run_ids_on_mismatch(self, capsys):
        # Fails if the loop reports a DIFFERENT run's status as if it were
        # the one we started waiting on.
        with patch("rafter_cli.commands.sites_wait.api_get") as mock_get:
            # One scripted response only — see test_exits_1_when_the_run_fails.
            mock_get.side_effect = [_mock_response(200, {"latest_run": {"id": "r2", "status": "running"}})]
            code = wait_for_site_run(
                "p1", "r1", "test-key", "json", True,
                timeout_seconds=900, poll_interval_seconds=0,
                sleep=lambda s: None, now=_fake_clock([0, 0]),
            )
        assert code == EXIT_GENERAL_ERROR
        err = capsys.readouterr().err
        assert "r1" in err and "r2" in err

    def test_exits_1_naming_run_and_site_id_on_timeout(self, capsys):
        with patch("rafter_cli.commands.sites_wait.api_get") as mock_get:
            # One scripted response only — see test_exits_1_when_the_run_fails.
            mock_get.side_effect = [_mock_response(200, {"latest_run": {"id": "r1", "status": "running"}})]
            # deadline = 0 + 1s = 1; next now() (1.5) is past it.
            code = wait_for_site_run(
                "p1", "r1", "test-key", "json", True,
                timeout_seconds=1, poll_interval_seconds=0,
                sleep=lambda s: None, now=_fake_clock([0, 1.5]),
            )
        assert code == EXIT_GENERAL_ERROR
        err = capsys.readouterr().err
        assert "r1" in err and "p1" in err and "timed out" in err

    def test_ctrl_c_stops_waiting_with_exit_130(self, capsys):
        # Fails if Ctrl-C escapes as a traceback or a generic exit code.
        def interrupted_sleep(_s):
            raise KeyboardInterrupt
        with patch("rafter_cli.commands.sites_wait.api_get") as mock_get:
            mock_get.side_effect = [_mock_response(200, {"latest_run": {"id": "r1", "status": "running"}})]
            code = wait_for_site_run(
                "p1", "r1", "test-key", "json", True,
                timeout_seconds=900, poll_interval_seconds=0,
                sleep=interrupted_sleep, now=_fake_clock([0, 0]),
            )
        assert code == EXIT_WAIT_INTERRUPTED == 130
        assert "rafter sites get p1" in capsys.readouterr().err

    def test_parse_wait_timeout_rejects_non_positive_values(self):
        seconds, error = parse_wait_timeout("0")
        assert error is not None
        seconds, error = parse_wait_timeout("-5")
        assert error is not None
        seconds, error = parse_wait_timeout("not-a-number")
        assert error is not None

    def test_parse_wait_timeout_accepts_a_positive_value(self):
        seconds, error = parse_wait_timeout("30")
        assert error is None
        assert seconds == 30.0

    def test_parse_wait_timeout_defaults_when_omitted(self):
        from rafter_cli.commands.sites_wait import DEFAULT_WAIT_TIMEOUT_SECONDS

        seconds, error = parse_wait_timeout(None)
        assert error is None
        assert seconds == DEFAULT_WAIT_TIMEOUT_SECONDS


# ── rafter sites list ─────────────────────────────────────────────────


class TestSitesListCli:
    @patch("rafter_cli.commands.sites.api_get")
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

    @patch("rafter_cli.commands.sites.api_get")
    def test_401(self, mock_get):
        mock_get.return_value = _mock_response(401, {"error": "invalid key"})
        result = runner.invoke(sites_app, ["list", "-k", "test-key"])
        assert result.exit_code == EXIT_GENERAL_ERROR


# ── rafter sites get ──────────────────────────────────────────────────


class TestSitesGetCli:
    @patch("rafter_cli.commands.sites.api_get")
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

    @patch("rafter_cli.commands.sites.api_get")
    def test_404(self, mock_get):
        mock_get.return_value = _mock_response(404, {"error": "not found"})
        result = runner.invoke(sites_app, ["get", "nonexistent", "-k", "test-key"])
        assert result.exit_code == EXIT_SCAN_NOT_FOUND

    @patch("rafter_cli.commands.sites.api_get")
    def test_429(self, mock_get):
        mock_get.return_value = _mock_response(
            429, {"error": "Rate limit exceeded", "retryAfter": 30}
        )
        result = runner.invoke(sites_app, ["get", "p1", "-k", "test-key"])
        assert result.exit_code == EXIT_QUOTA_EXHAUSTED

    def test_rejects_format_md(self):
        # report is the one sites command where md is valid; get must keep
        # rejecting it — this fails if that rejection ever gets dropped.
        result = runner.invoke(sites_app, ["get", "p1", "-k", "test-key", "-f", "md"])
        assert result.exit_code == EXIT_GENERAL_ERROR
        assert "does not support --format md" in result.output


# ── rafter sites report ────────────────────────────────────────────────


class TestSitesReportCli:
    @patch("rafter_cli.commands.sites.api_get")
    def test_json_requests_format_json_and_writes_the_report_body(self, mock_get):
        mock_get.return_value = _mock_response(
            200, {"report": {"project": "p1", "siteScore": 90}}
        )
        result = runner.invoke(sites_app, ["report", "p1", "-k", "test-key"])
        assert result.exit_code == EXIT_SUCCESS, result.output
        args, kwargs = mock_get.call_args
        assert args[0].endswith("/static/sites/p1/report")
        assert kwargs["params"] == {"format": "json"}
        assert json.loads(result.output) == {"report": {"project": "p1", "siteScore": 90}}

    @patch("rafter_cli.commands.sites.api_get")
    def test_md_requests_format_md_and_writes_the_raw_body(self, mock_get):
        # Fails if report's md path reuses write_payload's `data["markdown"]`
        # branch, which expects a dict and would crash or print nothing for
        # a plain-text response body.
        mock_get.return_value = _mock_text_response(200, "# Report\n\nAll clear.")
        result = runner.invoke(sites_app, ["report", "p1", "-k", "test-key", "-f", "md"])
        assert result.exit_code == EXIT_SUCCESS, result.output
        _, kwargs = mock_get.call_args
        assert kwargs["params"] == {"format": "md"}
        assert result.output == "# Report\n\nAll clear."

    @patch("rafter_cli.commands.sites.api_get")
    def test_does_not_reject_format_md(self, mock_get):
        mock_get.return_value = _mock_text_response(200, "# ok")
        result = runner.invoke(sites_app, ["report", "p1", "-k", "test-key", "-f", "md"])
        assert result.exit_code == EXIT_SUCCESS, result.output
        mock_get.assert_called_once()

    @patch("rafter_cli.commands.sites.api_get")
    def test_md_strips_control_chars_other_than_newline_and_tab(self, mock_get):
        # Report titles/descriptions come from scanning a third-party site
        # and could carry terminal escape sequences; this fails if an ESC or
        # BEL byte reaches the terminal unstripped.
        malicious = "# Report\n\tfinding: \x1b[31mFAKE\x1b[0m\x07 bell"
        mock_get.return_value = _mock_text_response(200, malicious)
        result = runner.invoke(sites_app, ["report", "p1", "-k", "test-key", "-f", "md"])
        assert result.output == "# Report\n\tfinding: [31mFAKE[0m bell"

    @patch("rafter_cli.commands.sites.api_get")
    def test_json_output_is_byte_faithful(self, mock_get):
        mock_get.return_value = _mock_response(200, {"report": {"title": "x\x1by"}})
        result = runner.invoke(sites_app, ["report", "p1", "-k", "test-key"])
        assert json.loads(result.output) == {"report": {"title": "x\x1by"}}

    @patch("rafter_cli.commands.sites.api_get")
    def test_404(self, mock_get):
        mock_get.return_value = _mock_response(404, {"error": "Site not found."})
        result = runner.invoke(sites_app, ["report", "nonexistent", "-k", "test-key"])
        assert result.exit_code == EXIT_SCAN_NOT_FOUND


# ── MCP tool handlers ─────────────────────────────────────────────────


class TestMcpSitesCreate:
    @patch("rafter_cli.commands.mcp_server.api_post")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_success(self, _mock_key, mock_post):
        mock_post.return_value = _mock_response(
            200, {"site": {"id": "p1"}, "run": {"id": "r1"}, "created": True}
        )
        result = handle_sites_create("https://example.com")
        assert result["created"] is True
        _, kwargs = mock_post.call_args
        assert kwargs["json"] == {"url": "https://example.com"}

    @patch("rafter_cli.commands.mcp_server.api_post")
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
    @patch("rafter_cli.commands.mcp_server.api_post")
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

    @patch("rafter_cli.commands.mcp_server.api_post")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_404_not_owned(self, _mock_key, mock_post):
        mock_post.return_value = _mock_response(404, {"error": "not found"})
        with pytest.raises(RuntimeError, match="Not found"):
            handle_sites_scan(project_id="proj-1")


class TestMcpSitesList:
    @patch("rafter_cli.commands.mcp_server.api_get")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_success_with_params(self, _mock_key, mock_get):
        mock_get.return_value = _mock_response(
            200, {"sites": [], "limit": 5, "offset": 0, "has_more": False}
        )
        handle_sites_list(limit=5, include_archived=True)
        _, kwargs = mock_get.call_args
        assert kwargs["params"] == {"limit": "5", "include_archived": "true"}

    @patch("rafter_cli.commands.mcp_server.api_get")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_429_raises(self, _mock_key, mock_get):
        mock_get.return_value = _mock_response(429, {"error": "Rate limit exceeded"})
        with pytest.raises(RuntimeError, match="Rate limited"):
            handle_sites_list()


class TestMcpSitesGet:
    @patch("rafter_cli.commands.mcp_server.api_get")
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

    @patch("rafter_cli.commands.mcp_server.api_get")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_404_raises(self, _mock_key, mock_get):
        mock_get.return_value = _mock_response(404, {"error": "not found"})
        with pytest.raises(RuntimeError, match="Not found"):
            handle_sites_get("nonexistent")

    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value=None)
    def test_missing_key_raises_without_crashing(self, _mock_key):
        with pytest.raises(RuntimeError, match="No API key configured"):
            handle_sites_get("p1")


class TestMcpSitesReport:
    @patch("rafter_cli.commands.mcp_server.api_get")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_json_success(self, _mock_key, mock_get):
        mock_get.return_value = _mock_response(200, {"report": {"project": "p1", "siteScore": 90}})
        result = handle_sites_report("p1")
        assert result == {"report": {"project": "p1", "siteScore": 90}}
        _, kwargs = mock_get.call_args
        assert kwargs["params"] == {"format": "json"}

    @patch("rafter_cli.commands.mcp_server.api_get")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_md_returns_stripped_text(self, _mock_key, mock_get):
        mock_get.return_value = _mock_text_response(200, "# Report\n\x1b[31mFAKE\x1b[0m")
        result = handle_sites_report("p1", format="md")
        assert result == "# Report\n[31mFAKE[0m"
        _, kwargs = mock_get.call_args
        assert kwargs["params"] == {"format": "md"}

    @patch("rafter_cli.commands.mcp_server.api_get")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    def test_404_raises(self, _mock_key, mock_get):
        mock_get.return_value = _mock_response(404, {"error": "Site not found."})
        with pytest.raises(RuntimeError, match="Not found"):
            handle_sites_report("nonexistent")

    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value=None)
    def test_missing_key_raises_without_crashing(self, _mock_key):
        with pytest.raises(RuntimeError, match="No API key configured"):
            handle_sites_report("p1")


# ── RAFTER_API_URL ────────────────────────────────────────────────────


class TestSitesHonorApiUrlOverride:
    """The base used to be fixed at import, so Sites calls ignored RAFTER_API_URL."""

    @patch("rafter_cli.commands.mcp_server.api_get")
    @patch("rafter_cli.commands.mcp_server.resolve_mcp_api_key", return_value="test-key")
    @patch("rafter_cli.commands.sites.api_post")
    def test_cli_and_mcp_use_override(self, mock_post, _mock_key, mock_get, monkeypatch):
        monkeypatch.setenv("RAFTER_API_URL", "http://127.0.0.1:9/api/")
        mock_post.return_value = _mock_response(200, {"site": {"id": "p1"}, "created": True})
        mock_get.return_value = _mock_response(200, {"site": {"id": "p1"}})

        result = runner.invoke(sites_app, ["create", "https://example.com", "-k", "test-key"])
        assert result.exit_code == EXIT_SUCCESS, result.output
        assert mock_post.call_args[0][0] == "http://127.0.0.1:9/api/static/sites"

        handle_sites_get("p1")
        assert mock_get.call_args[0][0] == "http://127.0.0.1:9/api/static/sites/p1"
