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

const GRIN = "\u{1F600}";

/**
 * Text the two runtimes once read differently: a UTF-8 BOM, U+00A0 where a
 * space would make a definition, non-BMP characters in a line, a signature
 * and a file name. Mirrored in python/tests/test_gates.py.
 */
export const UNICODE_FIXTURE: Record<string, string> = {
  "bom.py": "\uFEFFdef check_auth(user):\n    return verify(user)\n",
  "nbsp.js": "function\u00A0checkAuth() {\n  return verify(x);\n}\n",
  "long.go": `func authorizeUser() { // ${GRIN.repeat(250)}\n\tverify()\n}\n`,
  "sig.go": `func verifyToken(t string) bool { s := "${GRIN.repeat(80)}"; return check(s) }\n`,
  [`${GRIN}.go`]: "func authorizeAdmin() {\n}\n",
  "\uFF5A.go": "func authorizeAdmin() {\n}\n",
};

/**
 * Lines that made the scanner's regexes backtrack for minutes: a 900 KB body
 * line, the same after an unclosed quote, a 900 KB first line full of "Code
 * generated ", and 45,000 definitions whose braces never close.
 */
export function hostileFixture(): Record<string, string> {
  const big = "a".repeat(900_000);
  return {
    "body.js": `function checkAuth() {\n${big}\n}\n`,
    "quote.js": `function checkAuth() {\n"${big}\n}\n`,
    "gen.go": `// ${"Code generated ".repeat(60_000)}\nfunc checkAuth() {\n}\n`,
    "dense.go": Array.from({ length: 45_000 }, (_, i) => `func checkA${i}() {\n`).join(""),
  };
}

export function writeFixture(root: string, files: Record<string, string>): void {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
}
