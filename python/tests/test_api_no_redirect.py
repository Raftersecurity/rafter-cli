"""sable-2s6p — authenticated Rafter calls must not follow redirects.

``requests.sessions.SessionRedirectMixin.rebuild_auth`` strips ``Authorization``
on a host change and leaves arbitrary custom headers intact, so ``x-api-key``
rides a 302 to whatever host it points at. The API base is user-settable
(``--rafter-url``, self-hosted installs), which makes that a real exfiltration
path rather than a theoretical one.

Mirrors node/tests/api-no-redirect.test.ts.
"""
from __future__ import annotations

import pathlib
import re
from unittest.mock import MagicMock, patch

from rafter_cli.utils.api import api_get, api_post, api_request

REPO_PY = pathlib.Path(__file__).resolve().parents[1] / "rafter_cli"


def _resp(status_code: int = 200, headers=None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    return resp


class TestRedirectsRefused:
    def test_api_request_forces_allow_redirects_false(self):
        with patch("rafter_cli.utils.api.requests.request") as req:
            req.return_value = _resp()
            api_request("GET", "https://rafter.so/api/static/scan")

        assert req.call_args.kwargs["allow_redirects"] is False

    def test_callers_cannot_re_enable_redirects(self):
        # Even an explicit allow_redirects=True is overridden — the point is
        # that no call site can opt back into leaking the key.
        with patch("rafter_cli.utils.api.requests.request") as req:
            req.return_value = _resp()
            api_request("GET", "https://rafter.so/x", allow_redirects=True)

        assert req.call_args.kwargs["allow_redirects"] is False

    def test_api_get_and_api_post_use_the_right_verbs(self):
        with patch("rafter_cli.utils.api.requests.request") as req:
            req.return_value = _resp()
            api_get("https://rafter.so/x")
            api_post("https://rafter.so/y")

        assert [c.args[0] for c in req.call_args_list] == ["GET", "POST"]
        assert all(c.kwargs["allow_redirects"] is False for c in req.call_args_list)

    def test_a_refused_redirect_explains_itself(self, capsys):
        with patch("rafter_cli.utils.api.requests.request") as req:
            # ANSI escape included on purpose: an attacker-controlled Location
            # must not be able to rewrite the user's terminal.
            req.return_value = _resp(
                302, {"location": "https://evil.example/collect\x1b[31m"}
            )
            api_get("https://rafter.so/api/static/scan")

        err = capsys.readouterr().err
        assert "evil.example" in err
        assert "does not follow redirects" in err
        assert "self-hosted" in err
        assert "\x1b" not in err


class TestNoCallSiteBypassesTheHelper:
    """A new authenticated call site must not be able to reintroduce the hole."""

    def test_no_bare_requests_call_sends_the_api_key(self):
        offenders = []
        call = re.compile(r"\brequests\.(get|post|put|delete|patch|request)\(")

        for path in REPO_PY.rglob("*.py"):
            if path.name == "api.py" and path.parent.name == "utils":
                continue  # the helper itself is where requests is allowed
            lines = path.read_text().splitlines()
            for i, line in enumerate(lines):
                if not call.search(line):
                    continue
                window = "\n".join(lines[i : i + 6])
                if "x-api-key" in window or "headers=headers" in window:
                    offenders.append(f"{path}:{i + 1}")

        assert offenders == [], (
            "These calls send the API key through bare requests, which replays it "
            "across a cross-host redirect. Use api_get/api_post from "
            f"rafter_cli.utils.api instead:\n" + "\n".join(offenders)
        )


class TestNoSecondSession:
    def test_no_module_builds_its_own_requests_session(self):
        offenders = [
            str(p)
            for p in REPO_PY.rglob("*.py")
            if not (p.name == "api.py" and p.parent.name == "utils")
            and "requests.Session(" in p.read_text()
        ]
        assert offenders == [], (
            "A bare Session follows redirects by default. Use api_get/api_post "
            "from rafter_cli.utils.api:\n" + "\n".join(offenders)
        )


class TestApiUrlConstruction:
    def test_no_module_builds_a_double_slash_url(self):
        # Not cosmetic. API_BASE ends in "/", and f"{API_BASE}/static/..."
        # produced https://rafter.so/api//static/scan, which production answers
        # with a 308. That worked only because the client followed redirects.
        offenders = []
        for path in REPO_PY.rglob("*.py"):
            for i, line in enumerate(path.read_text().splitlines()):
                if "{API_BASE}/" in line:
                    offenders.append(f"{path}:{i + 1}")
        assert offenders == [], (
            "These build a double-slash URL. Use api_url() instead:\n"
            + "\n".join(offenders)
        )

    def test_api_url_joins_cleanly(self):
        from rafter_cli.utils.api import API_BASE, api_url

        assert api_url("static/scan") == "https://rafter.so/api/static/scan"
        assert api_url("/static/scan") == "https://rafter.so/api/static/scan"
        assert API_BASE.endswith("/")  # the trap this guards against
