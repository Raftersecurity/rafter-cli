"""sable-l10k — transient poll failures must not kill a healthy scan.

A paying customer's GitHub Actions run died on:
  "Rafter scan poll failed: HTTP 500 — Failed to fetch report from storage: Object not found"

A report is not durable the instant a scan flips to completed, so a poll can hit
a 5xx on a scan that is perfectly readable seconds later. These tests pin the
contract: transient read failures are retried, genuinely-missing reports still
fail, and the failure message is one a customer can act on.

Mirrors node/tests/scan-poll-transient-500.test.ts.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests
import typer

from rafter_cli.commands.backend import (
    BASE_BACKOFF_SECONDS,
    MAX_TOTAL_TRANSIENT_POLL_FAILURES,
    MAX_TRANSIENT_POLL_FAILURES,
    _handle_scan_status_interactive,
    backoff_seconds,
    unreadable_report_message,
)
from rafter_cli.utils.api import EXIT_GENERAL_ERROR, EXIT_SCAN_NOT_FOUND, EXIT_SUCCESS

OBJECT_NOT_FOUND_BODY = json.dumps(
    {"error": "Failed to fetch report from storage: Object not found"}
)

HEADERS = {"x-api-key": "test-key"}


def _resp(status_code: int, text: str = "", json_body=None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.json.return_value = json_body if json_body is not None else {}
    return resp


def _processing() -> MagicMock:
    return _resp(200, json_body={"status": "processing"})


def _completed() -> MagicMock:
    return _resp(200, json_body={"status": "completed", "markdown": "# Done"})


def _server_500() -> MagicMock:
    return _resp(500, text=OBJECT_NOT_FOUND_BODY)


@pytest.fixture(autouse=True)
def sleeps():
    """Backoff is real time; tests should not pay for it.

    Yields the mock so tests can assert the SCHEDULE, not just that sleeping
    happened. Backoff is the fix — retrying five times inside a millisecond
    gives an eventually-consistent store no time to converge.
    """
    with patch("rafter_cli.commands.backend.time.sleep") as m:
        yield m


class TestTransientPollFailures:
    def test_backoff_is_exponential_not_flat(self):
        assert BASE_BACKOFF_SECONDS > 0
        assert [backoff_seconds(n) for n in (1, 2, 3, 4)] == [2, 4, 8, 16]

    def test_actually_sleeps_the_backoff_schedule(self, sleeps):
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [_processing()] + [
                _server_500() for _ in range(MAX_TRANSIENT_POLL_FAILURES)
            ]
            with pytest.raises(typer.Exit):
                _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)

        # 10s poll interval, then 2/4/8/16 between the four retries that
        # precede giving up on the fifth failure.
        assert [c.args[0] for c in sleeps.call_args_list] == [10, 2, 4, 8, 16]

    def test_caps_total_failures_so_a_flapping_server_cannot_loop_forever(self):
        # Alternating success/failure resets the consecutive counter every
        # time. Without a total cap, and with no wall-clock deadline in the
        # CLI, that loop never terminates.
        flapping = [_processing()]
        for _ in range(MAX_TOTAL_TRANSIENT_POLL_FAILURES + 5):
            flapping += [_server_500(), _processing()]

        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = flapping
            with pytest.raises(typer.Exit) as exc:
                _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)

        assert exc.value.exit_code == EXIT_GENERAL_ERROR

    def test_consecutive_counter_resets_on_a_successful_poll(self, sleeps):
        # Two blips far apart must NOT add up to a give-up.
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [
                _processing(),
                _server_500(),
                _server_500(),
                _processing(),
                _server_500(),
                _server_500(),
                _completed(),
            ]
            code = _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)

        assert code == EXIT_SUCCESS
        # Backoff restarts at 2s after the reset rather than continuing to 8s.
        assert [c.args[0] for c in sleeps.call_args_list] == [10, 2, 4, 10, 2, 4]

    def test_first_poll_retries_a_transient_500(self):
        # The give-up message tells the user to run `rafter get <id>`, which
        # re-enters at the first poll. If that path did not retry, the remedy
        # we recommend would be defeated by one bad read.
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [_server_500(), _completed()]
            code = _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)

        assert code == EXIT_SUCCESS
        assert get.call_count == 2

    def test_any_2xx_counts_as_success(self):
        # Node's axios accepts any 2xx; Python must not diverge.
        accepted = _resp(202, json_body={"status": "completed", "markdown": "# Done"})
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [accepted]
            code = _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)

        assert code == EXIT_SUCCESS

    def test_retry_notice_goes_to_stderr(self, capsys):
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [_processing(), _server_500(), _completed()]
            _handle_scan_status_interactive("s1", HEADERS, "md", quiet=False)

        err = capsys.readouterr().err
        assert "Report not readable yet" in err
        assert "retrying in 2s" in err

    def test_rides_out_a_single_500_and_completes(self, capsys):
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [_processing(), _server_500(), _completed()]
            code = _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)

        assert code == EXIT_SUCCESS
        assert get.call_count == 3

    def test_rides_out_several_consecutive_500s(self):
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [
                _processing(),
                _server_500(),
                _server_500(),
                _server_500(),
                _completed(),
            ]
            code = _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)

        assert code == EXIT_SUCCESS
        assert get.call_count == 5

    def test_midpoll_404_is_lag_not_a_missing_scan(self):
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [_processing(), _resp(404, text="{}"), _completed()]
            code = _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)

        assert code == EXIT_SUCCESS

    def test_first_poll_404_still_reports_not_found(self):
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [_resp(404, text="{}")]
            with pytest.raises(typer.Exit) as exc:
                _handle_scan_status_interactive("nope", HEADERS, "md", quiet=True)

        assert exc.value.exit_code == EXIT_SCAN_NOT_FOUND
        assert get.call_count == 1

    def test_gives_up_when_report_never_becomes_readable(self, capsys):
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [_processing()] + [
                _server_500() for _ in range(MAX_TRANSIENT_POLL_FAILURES)
            ]
            with pytest.raises(typer.Exit) as exc:
                _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)

        assert exc.value.exit_code == EXIT_GENERAL_ERROR
        assert get.call_count == 1 + MAX_TRANSIENT_POLL_FAILURES

        err = capsys.readouterr().err
        assert "rafter get s1" in err
        assert "Object not found" in err

    def test_does_not_retry_a_non_transient_error(self):
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [
                _processing(),
                _resp(403, text=json.dumps({"error": "Invalid API key"})),
            ]
            with pytest.raises(typer.Exit) as exc:
                _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)

        assert exc.value.exit_code == EXIT_GENERAL_ERROR
        assert get.call_count == 2

    def test_retries_transport_errors(self):
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [
                _processing(),
                requests.ConnectionError("ECONNRESET"),
                _completed(),
            ]
            code = _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)

        assert code == EXIT_SUCCESS

    def test_a_500_body_is_never_mistaken_for_a_report(self):
        """The pre-fix bug: the loop called .json() on the 500 body, got no
        status, fell out of the loop and wrote the error payload out as if it
        were results."""
        with patch("rafter_cli.commands.backend.requests.get") as get:
            get.side_effect = [_processing()] + [
                _server_500() for _ in range(MAX_TRANSIENT_POLL_FAILURES)
            ]
            with pytest.raises(typer.Exit):
                _handle_scan_status_interactive("s1", HEADERS, "md", quiet=True)


class TestUnreadableReportMessage:
    def test_gives_scan_id_and_a_next_step(self):
        msg = unreadable_report_message(
            "scan-abc",
            "HTTP 500 — Failed to fetch report from storage: Object not found",
        )

        assert "scan-abc" in msg
        assert "rafter get scan-abc" in msg
        assert "dashboard" in msg
        # The raw server wording survives as supporting detail...
        assert "Object not found" in msg
        # ...but is not the whole message.
        assert len(msg.splitlines()) > 1
