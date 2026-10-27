"""`rafter gates` end to end. Mirrors node/tests/gates.test.ts."""

import json
import os
import site
import subprocess
import sys

import pytest

_USER_BASE = site.getuserbase()

FIXTURE = {
    "auth/authz.go": (
        "package auth\n\n"
        "func (a *Authorizer) Authorize(user string, action string) bool {\n"
        "\treturn a.roles[user] == action\n"
        "}\n\n"
        "func formatName(s string) string {\n"
        "\treturn s\n"
        "}\n"
    ),
    "auth/authz_test.go": (
        "package auth\n\n"
        "func checkFixtureUser(name string) bool {\n"
        "\treturn name != \"\"\n"
        "}\n"
    ),
    "backends/ldap.py": (
        "def authenticate(conn, username, password):\n"
        "    query = \"(uid=%s)\" % escape_filter_chars(username)\n"
        "    return conn.search(query, password)\n"
    ),
    "backends/local.py": (
        "def authenticate(conn, username, password):\n"
        "    query = \"(uid=%s)\" % username\n"
        "    return conn.search(query, password)\n"
    ),
    "web/middleware.js": (
        "function requireAdmin(req, res, next) {\n"
        "  if (!req.user || !req.user.admin) return res.status(403).end();\n"
        "  next();\n"
        "}\n\n"
        "const isSafeRedirect = (url) => url.startsWith(\"/\");\n\n"
        "function renderPage(req) {\n"
        "  return \"<p>\" + req.path + \"</p>\";\n"
        "}\n"
    ),
    "web/middleware.test.js": "function checkFixtureThing() {\n  return true;\n}\n",
    "node_modules/dep/index.js": "function authorizeVendored() {\n  return true;\n}\n",
}


def rafter(*args):
    env = os.environ.copy()
    env["PYTHONUSERBASE"] = _USER_BASE
    r = subprocess.run(
        [sys.executable, "-m", "rafter_cli", *args],
        capture_output=True, text=True, env=env, timeout=30,
    )
    return r.stdout, r.stderr, r.returncode


@pytest.fixture(scope="module")
def tree(tmp_path_factory):
    root = tmp_path_factory.mktemp("gates")
    for rel, content in FIXTURE.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


def test_finds_gates_skips_tests_and_flags_twin(tree):
    out, _, code = rafter("gates", str(tree), "--json")
    assert code == 0
    data = json.loads(out)
    found = sorted(f"{g['file']}:{g['name']}" for g in data["gates"])
    assert found == [
        "auth/authz.go:Authorize",
        "backends/ldap.py:authenticate",
        "backends/local.py:authenticate",
        "web/middleware.js:isSafeRedirect",
        "web/middleware.js:requireAdmin",
    ]
    assert data["stats"]["files_scanned"] == 4

    twin = next(t for t in data["twins"] if t["key"] == "authenticate")
    assert twin["flagged"] is True
    assert twin["missing"] == ["escape"]
    members = {m["file"]: m for m in twin["members"]}
    assert members["backends/local.py"]["lacks"] == ["escape"]
    assert members["backends/ldap.py"]["guards"]["escape"] == ["escape_filter_chars"]
    assert data["stats"]["flagged_groups"] == 1


def test_text_output_shows_flagged_twin(tree):
    out, _, code = rafter("gates", str(tree))
    assert code == 0
    assert "auth/authz.go:3" in out
    flagged = out.split("Flagged twin groups", 1)[1]
    assert any("backends/local.py:1" in line and "lacks: escape" in line for line in flagged.splitlines())


def test_bad_input_exits_2(tree):
    assert rafter("gates", str(tree / "nope"))[2] == 2
    assert rafter("gates", str(tree), "--limit", "0")[2] == 2
