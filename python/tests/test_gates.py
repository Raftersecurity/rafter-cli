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


# Mirrors LEADS_FIXTURE / LEADS_EXPECTED in node/tests/fixtures/gates-fixture.ts:
# each lead rule has a positive line and a near miss that must not fire.
LEADS_FIXTURE = {
    "net/tls.go": (
        "package net\n\n"
        "import \"crypto/tls\"\n\n"
        "type Options struct {\n"
        "\tSkipVerify    bool\n"
        "\tStrictTimeout int\n"
        "}\n\n"
        "type Peer struct {\n"
        "\tVerifyHostname bool\n"
        "}\n\n"
        "func (p Peer) ok() bool { return p.VerifyHostname }\n\n"
        "func client(o Options) []*tls.Config {\n"
        "\ta := &tls.Config{InsecureSkipVerify: true}\n"
        "\tb := &tls.Config{InsecureSkipVerify: o.SkipVerify}\n"
        "\tc := &tls.Config{InsecureSkipVerify: false}\n"
        "\ts := &tls.Config{ClientAuth: tls.RequireAnyClientCert}\n"
        "\tm := &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}\n"
        "\treturn []*tls.Config{a, b, c, s, m}\n"
        "}\n"
    ),
    "net/body.go": (
        "package net\n\n"
        "func handle(w http.ResponseWriter, r *http.Request, cfg *Config) {\n"
        "\tdata, _ := io.ReadAll(r.Body)\n"
        "\tlimited, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))\n"
        "\tif strings.HasSuffix(r.Host, \"example.com\") {\n"
        "\t}\n"
        "\tif strings.HasSuffix(r.URL.Path, \"/\") || strings.EqualFold(r.Host, cfg.Host) {\n"
        "\t}\n"
        "\tcfg.MaxBodyBytes = -1\n"
        "\tmaxI := -1\n"
        "\t_, _, _ = data, limited, maxI\n"
        "}\n"
    ),
    "web/app.py": (
        "import requests\n\n"
        "MAX_UPLOAD_LIMIT = -1\n"
        "TRUSTED_ORIGIN_STRICT = True\n"
        "ALLOWED_HOSTS = [\"a\"]\n\n\n"
        "def fetch(url, insecure=True):\n"
        "    return requests.get(url, verify=False)\n\n\n"
        "def fetch_ok(url, insecure=False):\n"
        "    return requests.get(url, verify=True)\n\n\n"
        "def allowed(host, role, request):\n"
        "    \"\"\"Example: requests.get(u, verify=False) in a docstring is not a lead.\n\n"
        "    def check_host(h):\n"
        "        return h.endswith(\"example.com\")\n"
        "    \"\"\"\n"
        "    body = request.stream.read()\n"
        "    head = request.stream.read(4096)\n"
        "    if host.endswith(\"example.com\"):\n"
        "        return host in ALLOWED_HOSTS\n"
        "    if \":\" in host:\n"
        "        return False\n"
        "    return \"admin\" in role\n"
    ),
    "web/agent.ts": (
        "import https from \"https\";\n\n"
        "interface Opts {\n"
        "  verifyPeer: boolean;\n"
        "  strictOrigin: boolean;\n"
        "}\n\n"
        "export function agents(o: Opts) {\n"
        "  const a = new https.Agent({ rejectUnauthorized: false });\n"
        "  const b = new https.Agent({ rejectUnauthorized: o.verifyPeer });\n"
        "  const c = new https.Agent({ rejectUnauthorized: true });\n"
        "  return [a, b, c];\n"
        "}\n\n"
        "export function originOk(origin: string, path: string): boolean {\n"
        "  return origin.endsWith(\"example.com\") && !path.endsWith(\"/\");\n"
        "}\n"
    ),
    "web/stream.js": (
        "function collect(req, done) {\n"
        "  let body = \"\";\n"
        "  req.on(\"data\", (chunk) => { body += chunk; });\n"
        "  req.on(\"end\", () => done(body));\n"
        "}\n"
    ),
    "web/stream-limited.js": (
        "function collect(req, done) {\n"
        "  let size = 0;\n"
        "  req.on(\"data\", (chunk) => { size += chunk.length; if (size > 1e6) req.destroy(); });\n"
        "}\n"
    ),
    "jvm/Client.java": (
        "class Client {\n"
        "  Object build() {\n"
        "    return HttpClients.custom().setSSLHostnameVerifier(new NoopHostnameVerifier()).build();\n"
        "  }\n"
        "}\n"
    ),
    "rb/client.rb": (
        "http.verify_mode = OpenSSL::SSL::VERIFY_NONE\n"
        "other.verify_mode = OpenSSL::SSL::VERIFY_PEER\n"
    ),
    "paths/clean.go": (
        "package paths\n\n"
        "func CleanPath(p string) string {\n"
        "\treturn cleanPath(p)\n"
        "}\n\n"
        "func cleanPath(p string) string {\n"
        "\treturn path.Clean(p)\n"
        "}\n"
    ),
}

LEADS_EXPECTED = [
    "jvm/Client.java:3:tls-verify-off",
    "net/body.go:10:limit-disabled",
    "net/body.go:4:unbounded-read",
    "net/body.go:6:loose-match",
    "net/tls.go:11:insecure-default",
    "net/tls.go:17:tls-verify-off",
    "net/tls.go:18:tls-verify-config",
    "net/tls.go:20:client-cert-unverified",
    "net/tls.go:7:config-unread",
    "rb/client.rb:1:tls-verify-off",
    "web/agent.ts:10:tls-verify-config",
    "web/agent.ts:16:loose-match",
    "web/agent.ts:5:config-unread",
    "web/agent.ts:9:tls-verify-off",
    "web/app.py:22:unbounded-read",
    "web/app.py:24:loose-match",
    "web/app.py:28:loose-match",
    "web/app.py:3:config-unread",
    "web/app.py:3:limit-disabled",
    "web/app.py:4:config-unread",
    "web/app.py:8:insecure-default",
    "web/app.py:9:tls-verify-off",
    "web/stream.js:3:unbounded-read",
]


def _write(root, files):
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


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
    _write(root, FIXTURE)
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
    # `url.startsWith("/")` also accepts //evil.com, so a literal "/" still raises a lead on a URL prefix.
    assert [f"{lead['file']}:{lead['line']}:{lead['rule']}" for lead in data["leads"]] == ["web/middleware.js:6:loose-match"]

    twin = next(t for t in data["twins"] if t["key"] == "authenticate")
    assert twin["flagged"] is True
    assert twin["missing"] == ["escape"]
    members = {m["file"]: m for m in twin["members"]}
    assert members["backends/local.py"]["lacks"] == ["escape"]
    assert members["backends/local.py"]["lacks_calls"] == ["escape_filter_chars"]
    assert members["backends/ldap.py"]["guards"]["escape"] == ["escape_filter_chars"]
    assert twin["confidence"] == 4  # escape (3) + members in different files (1)
    assert data["stats"]["flagged_groups"] == 1


def test_text_output_names_the_call_a_twin_lacks(tree):
    out, _, code = rafter("gates", str(tree))
    assert code == 0
    assert "auth/authz.go:3" in out
    flagged = out.split("Flagged twin groups", 1)[1]
    want = "lacks: escape (twins call escape_filter_chars(); this one does not)"
    assert any("backends/local.py:1" in line and want in line for line in flagged.splitlines())


def test_leads_fire_on_positives_not_near_misses(tmp_path):
    _write(tmp_path, LEADS_FIXTURE)
    out, _, code = rafter("gates", str(tmp_path), "--json")
    assert code == 0
    data = json.loads(out)
    got = sorted(f"{lead['file']}:{lead['line']}:{lead['rule']}" for lead in data["leads"])
    assert got == sorted(LEADS_EXPECTED)
    assert data["stats"]["leads_found"] == len(LEADS_EXPECTED)
    # A twin that only calls its sibling is not missing the sibling's guard.
    clean = next(t for t in data["twins"] if t["key"] == "cleanpath")
    assert clean["flagged"] is False
    assert [m["status"] for m in clean["members"]] == ["delegates", "checked"]


def test_leads_capped_per_file_and_in_text(tmp_path):
    line = "var _ = tls.Config{InsecureSkipVerify: true}\n"
    _write(tmp_path, {f"c{i:02d}.go": "package c\n\n" + line * 4 for i in range(10)})
    data = json.loads(rafter("gates", str(tmp_path), "--json")[0])
    assert data["stats"]["leads_found"] == 30
    assert len(data["leads"]) == 30
    text = rafter("gates", str(tmp_path))[0]
    assert text.count("[tls-verify-off]") == 25
    assert "... 5 more, use --json" in text


def test_bad_input_exits_2(tree):
    assert rafter("gates", str(tree / "nope"))[2] == 2
    assert rafter("gates", str(tree), "--limit", "0")[2] == 2
