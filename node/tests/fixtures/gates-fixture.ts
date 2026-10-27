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

export function writeFixture(root: string, files: Record<string, string>): void {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
}
