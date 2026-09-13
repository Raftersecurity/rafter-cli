"""sable-96ex — a 429 during polling is retried only when Retry-After says so.

A 429 used to be classified non-transient, in a codebase that polls every 10
seconds from every customer repo. That is exactly the traffic shape a rate
limiter targets, so the first limiter in front of GET /api/static/scan would
have failed every customer build instantly, on a condition one sleep would have
resolved.

It cannot simply join 408/5xx either: on scan SUBMIT a 429 means "out of
credits" (exit 3), and retrying a quota rejection for half a minute before
failing anyway is worse than failing now. ``Retry-After`` is the disambiguator —
a limiter sends one, a quota rejection does not.

Mirrors node/tests/scan-poll-429-retry-after.test.ts.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import typer

from rafter_cli.commands.backend import (
    MAX_RETRY_AFTER_SECONDS,
    MAX_TRANSIENT_POLL_FAILURES,
    _handle_scan_status_interactive,
    rate_limited_message,
    retry_after_seconds,
)
from rafter_cli.utils.api import EXIT_GENERAL_ERROR, EXIT_SUCCESS

HEADERS = {"x-api-key": "test-key"}

THROTTLED_BODY = json.dumps({"error": "Too many requests"})


def _resp(status_code: int, text: str = "", json_body=None, headers=None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.json.return_value = json_body if json_body is not None else {}
    # A MagicMock's auto-attribute would answer every header lookup with a
    # truthy mock, so the headers of a test double are always explicit.
    resp.headers = {} if headers is None else headers
    return resp


def _processing() -> MagicMock:
    return _resp(200, json_body={"status": "processing"})


def _completed() -> MagicMock:
    return _resp(200, json_body={"status": "completed", "markdown": "# Done"})


def _throttled(retry_after=None) -> MagicMock:
    """A 429 as a limiter sends it: with a delay the client can act on."""
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    return _resp(429, text=THROTTLED_BODY, headers=headers)


@pytest.fixture(autouse=True)
def sleeps():
    """Yields the sleep mock so tests can assert the SCHEDULE, not just that
    sleeping happened — the whole point is obeying the server's number."""
    with patch("rafter_cli.commands.backend.time.sleep") as m:
        yield m


class TestRetryAfterSeconds:
    def test_reads_a_plain_delay_seconds_header(self):
        assert retry_after_seconds(_throttled("5")) == 5

    def test_tolerates_surrounding_whitespace(self):
        assert retry_after_seconds(_throttled(" 5 ")) == 5

    def test_header_lookup_is_case_insensitive(self):
        # requests hands us a CaseInsensitiveDict; the production path must not
        # depend on the server's capitalization.
        import requests

        resp = _resp(429, headers=requests.structures.CaseInsensitiveDict(
            {"retry-after": "7"}
        ))
        assert retry_after_seconds(resp) == 7

    def test_honors_retry_after_zero(self):
        # Distinct from absent, and the failure budget still bounds the loop.
        assert retry_after_seconds(_throttled("0")) == 0

    def test_caps_a_limiter_that_asks_for_an_hour(self):
        assert retry_after_seconds(_throttled("3600")) == MAX_RETRY_AFTER_SECONDS

    def test_clamps_an_absurd_value(self):
        assert retry_after_seconds(_throttled("9" * 400)) == MAX_RETRY_AFTER_SECONDS

    def test_returns_none_for_the_http_date_form(self):
        # Deliberately unparsed: the composite action has to make the same call
        # in bash on whatever `date` the runner ships. Unparseable = fail fast.
        assert retry_after_seconds(_throttled("Wed, 21 Oct 2026 07:28:00 GMT")) is None

    def test_refuses_a_repeated_header(self):
        # requests joins duplicate headers with ", ". An origin's Retry-After
        # and a proxy's are not a delay we can act on, and all three surfaces
        # must agree — see the Node and action.yml halves of this contract.
        assert retry_after_seconds(_throttled("4, 900")) is None

    def test_returns_none_for_negative_or_non_numeric(self):
        assert retry_after_seconds(_throttled("-5")) is None
        assert retry_after_seconds(_throttled("soon")) is None
        assert retry_after_seconds(_throttled("1.5")) is None

    def test_a_unicode_digit_does_not_crash_the_client(self):
        # str.isdigit() is Unicode-aware and int() is not: '²' passes the first
        # and raises ValueError out of the second, from a call site whose only
        # handler is requests.RequestException. One raw \xb2 byte in the header
        # is enough — http.client decodes headers as ISO-8859-1. Node's
        # /^\d+$/ and the action's `case *[!0-9]*` both reject it, so accepting
        # it here would be a divergence as well as a crash.
        for value in ("\u00b2", "\u00b3", "\u00b9", "\uff15", "\u0665"):
            assert retry_after_seconds(_throttled(value)) is None
        # And the whole poll survives one, by failing fast rather than raising.
        with patch("rafter_cli.commands.backend.api_get") as get:
            get.side_effect = [_processing(), _throttled("\u00b2")]
            with pytest.raises(typer.Exit) as exc:
                _handle_scan_status_interactive("s1", HEADERS, "md", True)
            assert exc.value.exit_code == EXIT_GENERAL_ERROR
            assert get.call_count == 2

    def test_returns_none_when_absent(self):
        assert retry_after_seconds(_throttled()) is None
        assert retry_after_seconds(MagicMock(spec=[])) is None


class TestPolling429:
    def test_rides_out_a_429_that_carries_retry_after(self):
        with patch("rafter_cli.commands.backend.api_get") as get:
            get.side_effect = [_processing(), _throttled("5"), _completed()]
            assert (
                _handle_scan_status_interactive("s1", HEADERS, "md", True)
                == EXIT_SUCCESS
            )
            assert get.call_count == 3

    def test_sleeps_the_servers_delay_not_its_own_backoff(self, sleeps):
        # 2 is what the exponential schedule would have chosen for attempt 1.
        # Pinning the number is what lets this fail if the header is read and
        # then ignored.
        with patch("rafter_cli.commands.backend.api_get") as get:
            get.side_effect = [_processing(), _throttled("5"), _completed()]
            _handle_scan_status_interactive("s1", HEADERS, "md", True)
        assert [c.args[0] for c in sleeps.call_args_list] == [10, 5]

    def test_caps_the_honored_delay(self, sleeps):
        with patch("rafter_cli.commands.backend.api_get") as get:
            get.side_effect = [_processing(), _throttled("3600"), _completed()]
            _handle_scan_status_interactive("s1", HEADERS, "md", True)
        assert [c.args[0] for c in sleeps.call_args_list] == [
            10,
            MAX_RETRY_AFTER_SECONDS,
        ]

    def test_fails_fast_on_a_429_with_no_retry_after(self):
        """That is a quota rejection, and waiting will not earn more credits."""
        with patch("rafter_cli.commands.backend.api_get") as get:
            get.side_effect = [_processing(), _throttled()]
            with pytest.raises(typer.Exit) as exc:
                _handle_scan_status_interactive("s1", HEADERS, "md", True)
            assert exc.value.exit_code == EXIT_GENERAL_ERROR
            # The opening poll and the 429. A retry would make this 3 or more.
            assert get.call_count == 2

    def test_fails_fast_on_a_retry_after_it_cannot_parse(self):
        with patch("rafter_cli.commands.backend.api_get") as get:
            get.side_effect = [
                _processing(),
                _throttled("Wed, 21 Oct 2026 07:28:00 GMT"),
            ]
            with pytest.raises(typer.Exit):
                _handle_scan_status_interactive("s1", HEADERS, "md", True)
            assert get.call_count == 2

    def test_spends_the_failure_budget(self):
        """An endlessly-throttling API must not keep the loop alive."""
        with patch("rafter_cli.commands.backend.api_get") as get:
            get.side_effect = [_processing()] + [
                _throttled("1") for _ in range(MAX_TRANSIENT_POLL_FAILURES + 5)
            ]
            with pytest.raises(typer.Exit) as exc:
                _handle_scan_status_interactive("s1", HEADERS, "md", True)
            assert exc.value.exit_code == EXIT_GENERAL_ERROR
            assert get.call_count == 1 + MAX_TRANSIENT_POLL_FAILURES

    def test_says_rate_limited_not_unreadable_report(self, capsys):
        # Sending a throttled customer to look at their scan report — or at a
        # `rafter get` that will be throttled too — wastes their time on the
        # wrong problem entirely.
        with patch("rafter_cli.commands.backend.api_get") as get:
            get.side_effect = [_processing()] + [
                _throttled("1") for _ in range(MAX_TRANSIENT_POLL_FAILURES)
            ]
            with pytest.raises(typer.Exit):
                _handle_scan_status_interactive("scan-abc", HEADERS, "md", True)
        err = capsys.readouterr().err
        assert "rate limited" in err
        assert "scan-abc" in err
        assert "could not read the report" not in err

    def test_a_429_is_retryable_on_the_first_poll_too(self, sleeps):
        # The Retry-After gate is about the header, not about how far into the
        # poll we are — unlike 404, which is fatal on the first poll only.
        with patch("rafter_cli.commands.backend.api_get") as get:
            get.side_effect = [_throttled("2"), _completed()]
            assert (
                _handle_scan_status_interactive("s1", HEADERS, "md", True)
                == EXIT_SUCCESS
            )
        assert [c.args[0] for c in sleeps.call_args_list] == [2]


class TestRateLimitedMessage:
    def test_names_the_scan_the_cause_and_a_next_step(self):
        msg = rate_limited_message("scan-abc", "HTTP 429 — Too many requests", 5)

        assert "rate limited" in msg
        assert "scan-abc" in msg
        assert "rafter get scan-abc" in msg
        assert "dashboard" in msg
        # The raw server wording survives as supporting detail, not as the
        # whole explanation.
        assert "HTTP 429" in msg
        assert len(msg.split("\n")) > 1
