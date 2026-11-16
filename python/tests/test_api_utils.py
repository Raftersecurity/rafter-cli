"""Python counterpart to node/tests/api-utils.test.ts.

Only scenarios not already covered elsewhere live here. The rest:
- resolve_key precedence / no-key exit: test_error_handling_gauntlet.py
  (TestResolveKey) and test_config_secret_handling.py (TestResolveKeyPrecedence)
- write_payload default JSON, md with a markdown field, md without one:
  test_error_handling_gauntlet.py (TestWritePayload)
- exit-code values: test_error_handling_gauntlet.py (TestExitCodeConstants)
"""
from __future__ import annotations

import json

from rafter_cli.utils.api import (
    API_BASE,
    EXIT_CONFIRMATION_REQUIRED,
    EXIT_GENERAL_ERROR,
    EXIT_INSUFFICIENT_SCOPE,
    EXIT_QUOTA_EXHAUSTED,
    EXIT_SCAN_NOT_FOUND,
    EXIT_SUCCESS,
    write_payload,
)


class TestApiConstants:
    def test_api_base_is_rafter_so(self):
        assert API_BASE == "https://rafter.so/api/"

    def test_all_exit_codes_are_distinct_integers(self):
        # test_api_scope.TestExitCodes.test_no_collisions checks only three codes.
        codes = [
            EXIT_SUCCESS,
            EXIT_GENERAL_ERROR,
            EXIT_SCAN_NOT_FOUND,
            EXIT_QUOTA_EXHAUSTED,
            EXIT_INSUFFICIENT_SCOPE,
            EXIT_CONFIRMATION_REQUIRED,
        ]
        assert all(isinstance(c, int) for c in codes)
        assert len(set(codes)) == len(codes)


class TestWritePayloadFormatting:
    def test_pretty_prints_json_when_not_quiet(self, capsys):
        data = {"a": 1, "b": [1, 2]}
        write_payload(data, "json", False)
        out = capsys.readouterr().out
        assert "\n" in out
        assert out == json.dumps(data, indent=2)
        assert json.loads(out) == data

    def test_quiet_json_is_single_line_and_valid(self, capsys):
        # Separator spacing differs from Node.js compact output; byte-level parity remains an open question.
        data = {"a": 1, "b": [1, 2]}
        write_payload(data, "json", True)
        out = capsys.readouterr().out
        assert "\n" not in out
        assert json.loads(out) == data
