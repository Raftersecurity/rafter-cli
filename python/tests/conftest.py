"""Session-wide test isolation from the real machine.

Without this, a test that expects "no API key" instead reads the real
``~/.rafter/config.json`` (if the developer running the suite has one) and can
send a REAL authenticated request to the live Rafter backend. Two things make
that possible, and this fixture closes both:

1. ``ConfigManager``/``get_rafter_dir`` resolve ``Path.home()`` at call time,
   so any test that doesn't override ``HOME`` reads the real global config.
2. The API base (``rafter_cli.utils.api._resolve_api_base``) has no override
   in production, so even a correctly "no key" test can fall through to a
   real network call if something upstream of ``resolve_key`` goes wrong.

This fixture runs once per session, as the FIRST test's setup — i.e. after
collection, so module-level code in test files (several capture
``site.getuserbase()`` under the real ``HOME`` to keep subprocess imports of
user-installed packages working once they override ``HOME`` themselves) still
sees the real environment. Only test bodies and subprocesses they spawn see
the isolated one.

Opt out with ``RAFTER_TEST_LIVE_API=1`` to run against the real machine config
and the real backend (e.g. for a deliberate live/manual run). Leave it unset
for every normal test run.
"""
from __future__ import annotations

import os
import tempfile

import pytest

_LIVE_OPT_IN = os.environ.get("RAFTER_TEST_LIVE_API") == "1"

# Nothing should ever listen here, so an API call that escapes isolation
# fails fast (connection refused) instead of reaching the live backend.
_DEFAULT_CLOSED_PORT_URL = "http://127.0.0.1:1/api/"


@pytest.fixture(scope="session", autouse=True)
def _isolated_rafter_env():
    if _LIVE_OPT_IN:
        yield
        return

    saved = dict(os.environ)

    os.environ["HOME"] = tempfile.mkdtemp(prefix="rafter-test-home-")

    # Every RAFTER_* variable is an operator setting (API key, GitHub token,
    # webhook, disable switches) — none of them may leak from the machine
    # running the suite into a test that assumes a clean slate.
    for key in list(os.environ):
        if key.startswith("RAFTER_"):
            del os.environ[key]

    # Re-apply the redirect. A pre-set RAFTER_API_URL (e.g. a proof run
    # pointing at a counting listener) is preserved rather than clobbered.
    os.environ["RAFTER_API_URL"] = saved.get("RAFTER_API_URL") or _DEFAULT_CLOSED_PORT_URL

    yield

    os.environ.clear()
    os.environ.update(saved)
