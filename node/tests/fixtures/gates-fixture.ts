/**
 * A small multi-language tree for `rafter gates`: gates, a non-gate, a test
 * file and a vendored file that must be skipped, and a twin pair where one
 * member lacks the escape call the other makes. Mirrored in
 * python/tests/test_gates.py.
 */
import fs from "fs";
import path from "path";

export const GATES_FIXTURE: Record<string, string> = {
  "auth/authz.go": [
    "package auth",
    "",
    "func (a *Authorizer) Authorize(user string, action string) bool {",
    "\treturn a.roles[user] == action",
    "}",
    "",
    "func formatName(s string) string {",
    "\treturn s",
    "}",
    "",
  ].join("\n"),
  "auth/authz_test.go": [
    "package auth",
    "",
    "func checkFixtureUser(name string) bool {",
    "\treturn name != \"\"",
    "}",
    "",
  ].join("\n"),
  "backends/ldap.py": [
    "def authenticate(conn, username, password):",
    "    query = \"(uid=%s)\" % escape_filter_chars(username)",
    "    return conn.search(query, password)",
    "",
  ].join("\n"),
  "backends/local.py": [
    "def authenticate(conn, username, password):",
    "    query = \"(uid=%s)\" % username",
    "    return conn.search(query, password)",
    "",
  ].join("\n"),
  "web/middleware.js": [
    "function requireAdmin(req, res, next) {",
    "  if (!req.user || !req.user.admin) return res.status(403).end();",
    "  next();",
    "}",
    "",
    "const isSafeRedirect = (url) => url.startsWith(\"/\");",
    "",
    "function renderPage(req) {",
    "  return \"<p>\" + req.path + \"</p>\";",
    "}",
    "",
  ].join("\n"),
  "web/middleware.test.js": "function checkFixtureThing() {\n  return true;\n}\n",
  "node_modules/dep/index.js": "function authorizeVendored() {\n  return true;\n}\n",
};

/**
 * One tree for the `leads` section: each rule has a positive line and a
 * near miss that must not fire, per language; a docstring that must not
 * count; and a twin pair where one member only delegates to the other.
 * LEADS_EXPECTED lists every lead, as file:line:rule. Mirrored in
 * python/tests/test_gates.py.
 */
export const LEADS_FIXTURE: Record<string, string> = {
  "net/tls.go": [
    "package net",
    "",
    'import "crypto/tls"',
    "",
    "type Options struct {",
    "\tSkipVerify    bool",
    "\tStrictTimeout int",
    "}",
    "",
    "type Peer struct {",
    "\tVerifyHostname bool",
    "}",
    "",
    "func (p Peer) ok() bool { return p.VerifyHostname }",
    "",
    "func client(o Options) []*tls.Config {",
    "\ta := &tls.Config{InsecureSkipVerify: true}",
    "\tb := &tls.Config{InsecureSkipVerify: o.SkipVerify}",
    "\tc := &tls.Config{InsecureSkipVerify: false}",
    "\ts := &tls.Config{ClientAuth: tls.RequireAnyClientCert}",
    "\tm := &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}",
    "\treturn []*tls.Config{a, b, c, s, m}",
    "}",
    "",
  ].join("\n"),
  "net/body.go": [
    "package net",
    "",
    "func handle(w http.ResponseWriter, r *http.Request, cfg *Config) {",
    "\tdata, _ := io.ReadAll(r.Body)",
    "\tlimited, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))",
    "\tif strings.HasSuffix(r.Host, \"example.com\") {",
    "\t}",
    "\tif strings.HasSuffix(r.URL.Path, \"/\") || strings.EqualFold(r.Host, cfg.Host) {",
    "\t}",
    "\tcfg.MaxBodyBytes = -1",
    "\tmaxI := -1",
    "\t_, _, _ = data, limited, maxI",
    "}",
    "",
  ].join("\n"),
  "web/app.py": [
    "import requests",
    "",
    "MAX_UPLOAD_LIMIT = -1",
    "TRUSTED_ORIGIN_STRICT = True",
    "ALLOWED_HOSTS = [\"a\"]",
    "",
    "",
    "def fetch(url, insecure=True):",
    "    return requests.get(url, verify=False)",
    "",
    "",
    "def fetch_ok(url, insecure=False):",
    "    return requests.get(url, verify=True)",
    "",
    "",
    "def allowed(host, role, request):",
    "    \"\"\"Example: requests.get(u, verify=False) in a docstring is not a lead.",
    "",
    "    def check_host(h):",
    "        return h.endswith(\"example.com\")",
    "    \"\"\"",
    "    body = request.stream.read()",
    "    head = request.stream.read(4096)",
    "    if host.endswith(\"example.com\"):",
    "        return host in ALLOWED_HOSTS",
    "    if \":\" in host:",
    "        return False",
    "    return \"admin\" in role",
    "",
  ].join("\n"),
  "web/agent.ts": [
    "import https from \"https\";",
    "",
    "interface Opts {",
    "  verifyPeer: boolean;",
    "  strictOrigin: boolean;",
    "}",
    "",
    "export function agents(o: Opts) {",
    "  const a = new https.Agent({ rejectUnauthorized: false });",
    "  const b = new https.Agent({ rejectUnauthorized: o.verifyPeer });",
    "  const c = new https.Agent({ rejectUnauthorized: true });",
    "  return [a, b, c];",
    "}",
    "",
    "export function originOk(origin: string, path: string): boolean {",
    "  return origin.endsWith(\"example.com\") && !path.endsWith(\"/\");",
    "}",
    "",
  ].join("\n"),
  "web/stream.js": [
    "function collect(req, done) {",
    "  let body = \"\";",
    "  req.on(\"data\", (chunk) => { body += chunk; });",
    "  req.on(\"end\", () => done(body));",
    "}",
    "",
  ].join("\n"),
  "web/stream-limited.js": [
    "function collect(req, done) {",
    "  let size = 0;",
    "  req.on(\"data\", (chunk) => { size += chunk.length; if (size > 1e6) req.destroy(); });",
    "}",
    "",
  ].join("\n"),
  "jvm/Client.java": [
    "class Client {",
    "  Object build() {",
    "    return HttpClients.custom().setSSLHostnameVerifier(new NoopHostnameVerifier()).build();",
    "  }",
    "}",
    "",
  ].join("\n"),
  "rb/client.rb": [
    "http.verify_mode = OpenSSL::SSL::VERIFY_NONE",
    "other.verify_mode = OpenSSL::SSL::VERIFY_PEER",
    "",
  ].join("\n"),
  "paths/clean.go": [
    "package paths",
    "",
    "func CleanPath(p string) string {",
    "\treturn cleanPath(p)",
    "}",
    "",
    "func cleanPath(p string) string {",
    "\treturn path.Clean(p)",
    "}",
    "",
  ].join("\n"),
};

export const LEADS_EXPECTED = [
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
];

/** `n` files, each with four TLS-off lines: three survive the per-file cap. */
export function leadsCapFixture(n: number): Record<string, string> {
  const files: Record<string, string> = {};
  for (let i = 0; i < n; i++) {
    files[`c${String(i).padStart(2, "0")}.go`] = "package c\n\n" + "var _ = tls.Config{InsecureSkipVerify: true}\n".repeat(4);
  }
  return files;
}

export function writeFixture(root: string, files: Record<string, string>): void {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
}
