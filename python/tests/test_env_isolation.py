"""Asserts the session-wide isolation fixture (conftest.py) actually took
effect. If this goes red, every other test's isolation is suspect too."""
from __future__ import annotations

import os

from rafter_cli.core.config_schema import get_rafter_dir
from rafter_cli.utils.api import api_url

_LIVE_OPT_IN = os.environ.get("RAFTER_TEST_LIVE_API") == "1"


def test_home_is_an_isolated_temp_dir():
    if _LIVE_OPT_IN:
        return
    assert "rafter-test-home-" in os.environ["HOME"]
    assert str(get_rafter_dir()).startswith(os.environ["HOME"])


def test_api_url_is_redirected_away_from_production():
    if _LIVE_OPT_IN:
        return
    url = api_url("static/scan")
    assert url.startswith("http://127.0.0.1:")
    assert not url.startswith("https://rafter.so")
