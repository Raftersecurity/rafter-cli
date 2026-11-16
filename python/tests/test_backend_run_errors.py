"""Issue #34 — `rafter run` errors go through fmt.error on stderr.

Git and the API are mocked at the `rafter_cli.commands.backend` boundary, so
no repository is read and no request leaves the process.

Mirrors node/tests/backend-run-errors.test.ts.
"""
from __future__ import annotations

import io
import json
from unittest.mock import MagicMock, patch

import pytest
import typer
from rich.console import Console

from rafter_cli.commands.backend import _do_remote_scan
from rafter_cli.utils import formatter
from rafter_cli.utils.api import (
    EXIT_GENERAL_ERROR,
    EXIT_INSUFFICIENT_SCOPE,
    EXIT_QUOTA_EXHAUSTED,
)
from rafter_cli.utils.formatter import set_agent_mode

DETECT_FAILURE = "Could not auto-detect Git repository. Please pass --repo and --branch explicitly."
DETECTED = ("owner/repo", "main", "github", "https://github.com/owner/repo")
BRACKETED = "repo [/] locked [bold]now[/bold]"


def _resp(status_code: int, text: str = "", json_body=None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.json.return_value = json_body if json_body is not None else {}
    return resp


def _run(repo="owner/repo", branch="main") -> int:
    """Run a fast, non-interactive, quiet scan and return the exit code it raised."""
    with pytest.raises(typer.Exit) as exc:
        _do_remote_scan(
            repo=repo,
            branch=branch,
            api_key="test-key",
            fmt="json",
            skip_interactive=True,
            quiet=True,
        )
    return exc.value.exit_code


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    set_agent_mode(False)
    monkeypatch.delenv("RAFTER_API_URL", raising=False)
    monkeypatch.delenv("RAFTER_GITHUB_TOKEN", raising=False)
    yield
    set_agent_mode(False)


@pytest.fixture
def human_stderr(monkeypatch) -> io.StringIO:
    """Real Rich rendering into a buffer: wide and colorless, so assertions are exact."""
    buf = io.StringIO()
    monkeypatch.setattr(
        formatter, "_stderr_console", Console(file=buf, width=300, color_system=None)
    )
    return buf


class TestRepoDetection:
    @patch("rafter_cli.commands.backend.api_post")
    @patch("rafter_cli.commands.backend.detect_repo", side_effect=RuntimeError(DETECT_FAILURE))
    def test_detection_failure_agent_mode(self, _detect, post, capsys):
        set_agent_mode(True)

        assert _run(repo=None, branch=None) == EXIT_GENERAL_ERROR
        assert capsys.readouterr().err == f"[ERROR] {DETECT_FAILURE}\n"
        post.assert_not_called()

    @patch("rafter_cli.commands.backend.api_post")
    @patch("rafter_cli.commands.backend.detect_repo", side_effect=RuntimeError(DETECT_FAILURE))
    def test_detection_failure_human_mode(self, _detect, post, human_stderr):
        assert _run(repo=None, branch=None) == EXIT_GENERAL_ERROR
        assert human_stderr.getvalue() == f"✗ {DETECT_FAILURE}\n"
        post.assert_not_called()

    @patch("rafter_cli.commands.backend.api_post")
    @patch("rafter_cli.commands.backend.remote_branch_sha", return_value=None)
    @patch("rafter_cli.commands.backend.branch_from_env", return_value=None)
    @patch(
        "rafter_cli.commands.backend.detect_repo",
        return_value=("owner/repo", "feature", "github", "https://github.com/owner/repo"),
    )
    def test_unpushed_branch_agent_mode(self, _detect, _env, _sha, post, capsys):
        set_agent_mode(True)

        assert _run(repo=None, branch=None) == EXIT_GENERAL_ERROR
        err = capsys.readouterr().err
        assert err.startswith('[ERROR] Branch "feature" does not exist on the remote (origin).')
        assert err.count("\n") == 1
        post.assert_not_called()


@patch("rafter_cli.commands.backend.detect_repo", return_value=DETECTED)
class TestApiErrors:
    @patch("rafter_cli.commands.backend.api_post", return_value=_resp(429, "quota exhausted"))
    def test_quota_exhausted_agent_mode(self, _post, _detect, capsys):
        set_agent_mode(True)

        assert _run() == EXIT_QUOTA_EXHAUSTED
        assert capsys.readouterr().err == "[ERROR] Quota exhausted\n"

    @patch(
        "rafter_cli.commands.backend.api_post",
        return_value=_resp(500, json.dumps({"error": "scan backend unavailable"})),
    )
    def test_structured_error_agent_mode(self, _post, _detect, capsys):
        set_agent_mode(True)

        assert _run() == EXIT_GENERAL_ERROR
        assert capsys.readouterr().err == "[ERROR] HTTP 500 — scan backend unavailable\n"

    @patch(
        "rafter_cli.commands.backend.api_post",
        return_value=_resp(500, json.dumps({"error": BRACKETED})),
    )
    def test_structured_error_human_mode_keeps_brackets(self, _post, _detect, human_stderr):
        assert _run() == EXIT_GENERAL_ERROR
        assert human_stderr.getvalue() == f"✗ HTTP 500 — {BRACKETED}\n"

    @patch("rafter_cli.commands.backend.api_post", return_value=_resp(403, "forbidden"))
    def test_403_is_left_to_handle_403_and_printed_once(self, _post, _detect, capsys):
        set_agent_mode(True)

        assert _run() == EXIT_INSUFFICIENT_SCOPE
        err = capsys.readouterr().err
        assert err.count("\n") == 1
        assert "[ERROR]" not in err
