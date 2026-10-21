"""An unhandled exception must not print the API key.

Typer's pretty tracebacks render every frame's local variables by default,
and the request helpers hold the key in ``api_key`` / ``headers`` locals.
A plain transport failure (here: an unreachable proxy) is enough to raise
out of a command, so the key would land on stderr, which in CI is the
build log.
"""
from __future__ import annotations

import os
import pathlib
import site
import subprocess
import sys

SENTINEL = "RAFTER_TEST_SENTINEL_KEY_9f3c1a"

# Captured under the real HOME so user-site packages (e.g. typer) remain
# importable in the subprocess launched below with HOME overridden.
_USER_BASE = site.getuserbase()

# python/ — must be on PYTHONPATH explicitly. The subprocess below runs with
# cwd=tmp_path (deliberately, so it can't pick up a local .env/config), which
# means `python -m rafter_cli` can no longer rely on cwd to shadow a stale
# editable install elsewhere (e.g. a different checkout of this repo) on
# sys.path. Mirrors node's cross-runtime-parity.test.ts PYTHONPATH handling.
_PROJECT_PYTHON_DIR = str(pathlib.Path(__file__).resolve().parent.parent)


def test_unhandled_exception_does_not_print_api_key(tmp_path):
    env = os.environ.copy()
    env.pop("_TYPER_STANDARD_TRACEBACK", None)
    env.update(
        {
            "HOME": str(tmp_path),
            "PYTHONUSERBASE": _USER_BASE,
            "PYTHONPATH": _PROJECT_PYTHON_DIR,
            "RAFTER_API_KEY": SENTINEL,
            "HTTPS_PROXY": "http://127.0.0.1:1",
            "https_proxy": "http://127.0.0.1:1",
            "NO_PROXY": "",
            "no_proxy": "",
        }
    )
    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", "usage"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
        timeout=60,
    )

    assert result.returncode != 0
    # Positive control: the command did fail with a traceback, so the
    # assertion below is about its content rather than its absence.
    assert "Traceback" in result.stderr or "Error" in result.stderr
    assert SENTINEL not in result.stderr
    assert SENTINEL not in result.stdout
