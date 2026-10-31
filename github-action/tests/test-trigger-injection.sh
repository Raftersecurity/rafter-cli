#!/usr/bin/env bash
#
# rf-7xv0 — a fork's BRANCH NAME must not reach a shell that holds the API key.
#
# `${{ … }}` is expanded by the runner into the script TEXT before bash ever
# sees it, so a value interpolated inside a `run:` block is not data — it is
# source code. The trigger step's env carries RAFTER_API_KEY, and
# `github.head_ref` is chosen by whoever opened the pull request. Anyone can
# open one from a fork.
#
# This probe reproduces the runner's expansion exactly — textual substitution
# into the script, then execute — with a branch name that tries to read the key.
# It asserts two different things, because either alone can pass while the bug
# is live:
#
#   1. INJECTION: the payload must not execute. Canary file must not appear.
#   2. FIDELITY:  a hostile-but-legal branch name must still arrive intact in
#                 the request body. A fix that mangles or drops branch names is
#                 not a fix, it is a different bug.
#
# Corpus: github-action/action.yml. The ROOT action.yml has no head_ref
# interpolation (checked on main and at v1); rf-v2mj is the defect there.
set -uo pipefail

ACTION="$(cd "$(dirname "$0")/.." && pwd)/action.yml"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
failures=0

# The run: block of the trigger step, as the runner would hand it to bash.
extract_trigger() {
  python3 - "$ACTION" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for s in d["runs"]["steps"]:
    if s.get("id") == "scan":
        print(s["run"]); break
else:
    sys.exit("no step with id 'scan'")
PY
}

# The runner also expands `${{ }}` inside the step's env: VALUES and exports
# them. Modelling only the script text would make this probe vacuous after the
# fix — the payload would simply never arrive anywhere, and the test would pass
# because nothing was tested. Emits `export` lines for the step's env.
step_env() {
  python3 - "$ACTION" "$1" <<'PY'
import sys, yaml, re, shlex
d = yaml.safe_load(open(sys.argv[1])); branch = sys.argv[2]
for s in d["runs"]["steps"]:
    if s.get("id") == "scan":
        for k, v in (s.get("env") or {}).items():
            v = str(v)
            v = re.sub(r"\$\{\{\s*github\.head_ref\s*\|\|\s*github\.ref_name\s*\}\}", lambda _: branch, v)
            v = re.sub(r"\$\{\{\s*github\.repository\s*\}\}", "owner/repo", v)
            v = re.sub(r"\$\{\{\s*inputs\.api-key\s*\}\}", "CANARY-KEY-DO-NOT-LEAK", v)
            v = re.sub(r"\$\{\{\s*inputs\.scan-mode\s*\}\}", "fast", v)
            v = re.sub(r"\$\{\{\s*inputs\.rafter-url\s*\}\}", "__URL__", v)
            v = re.sub(r"\$\{\{.*?\}\}", "", v)
            print(f"export {k}={shlex.quote(v)}")
        break
PY
}

# What the runner does: substitute the expression's VALUE into the script text.
expand() {
  python3 - "$1" "$2" <<'PY'
import sys, re
script, branch = open(sys.argv[1]).read(), sys.argv[2]
script = re.sub(r"\$\{\{\s*github\.head_ref\s*\|\|\s*github\.ref_name\s*\}\}",
                lambda _: branch, script)
script = re.sub(r"\$\{\{\s*github\.repository\s*\}\}", "owner/repo", script)
# Any OTHER ${{ }} left in the script would also be runner-expanded; leaving
# them makes bash choke, which would mask the result rather than test it.
script = re.sub(r"\$\{\{.*?\}\}", "", script)
sys.stdout.write(script)
PY
}

run_case() {
  local label="$1" branch="$2"
  extract_trigger > "$TMP/raw.sh" || { echo "FAIL: could not extract the trigger step"; return 1; }
  expand "$TMP/raw.sh" "$branch" > "$TMP/run.sh"
  rm -f "$TMP/CANARY" "$TMP/body.json"
  # No network: point the API at a closed port so curl fails fast. The question
  # is never whether the request succeeds — it is whether the payload RAN.
  step_env "$branch" | sed "s#__URL__#http://127.0.0.1:9#" > "$TMP/env.sh"
  ( cd "$TMP" && \
    RAFTER_API_KEY="CANARY-KEY-DO-NOT-LEAK" \
    RAFTER_URL="http://127.0.0.1:9" \
    SCAN_MODE="fast" \
    GITHUB_OUTPUT="$TMP/gh_output" \
    CANARY_PATH="$TMP/CANARY" \
    timeout 30 bash -c 'set -a; . "$1/env.sh"; set +a; exec bash "$1/run.sh"' _ "$TMP" >"$TMP/out" 2>&1 )
  return 0
}

echo "== rf-7xv0: branch name must not execute in the key's shell =="

# The payload closes the JSON string and the shell's double quote, then writes
# the key to a file. If the file appears, a stranger could have sent it away.
PAYLOAD='x"; printf %s "$RAFTER_API_KEY" > "$CANARY_PATH"; echo "'
run_case "injection" "$PAYLOAD"
if [ -f "$TMP/CANARY" ]; then
  echo "FAIL: INJECTION — a branch name executed and read the API key:"
  echo "      canary contains: $(cat "$TMP/CANARY")"
  failures=$((failures+1))
else
  echo "PASS: a hostile branch name did not execute"
fi

# Command substitution is the other half: it needs no quote-breaking at all.
run_case "subst" 'x$(printf %s "$RAFTER_API_KEY" > "$CANARY_PATH")'
if [ -f "$TMP/CANARY" ]; then
  echo "FAIL: INJECTION via \$( ) — the key was read"
  failures=$((failures+1))
else
  echo "PASS: command substitution in a branch name did not execute"
fi

# Fidelity: a legal branch name with JSON-significant characters must arrive
# INTACT in the request body. Asserted against a real local listener that
# records what was actually sent — an earlier version of this check scraped the
# script text for the old inline-JSON shape, and once the fix replaced that
# shape it silently matched nothing and asserted nothing.
ODD='feature/"quote-and\backslash'
python3 - "$TMP" <<'PY' &
import sys, json
from http.server import BaseHTTPRequestHandler, HTTPServer
tmp = sys.argv[1]
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        open(tmp + "/sent.json", "wb").write(body)
        self.send_response(200); self.send_header("Content-Length", "22"); self.end_headers()
        self.wfile.write(b'{"scan_id":"probe-001"}')
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 8799), H).serve_forever()
PY
LISTENER=$!
for _ in $(seq 1 40); do curl -s -o /dev/null -X POST -d '{}' http://127.0.0.1:8799/ 2>/dev/null && break; sleep 0.1; done
rm -f "$TMP/sent.json"
extract_trigger > "$TMP/raw.sh"
expand "$TMP/raw.sh" "$ODD" > "$TMP/run.sh"
step_env "$ODD" | sed "s#__URL__#http://127.0.0.1:8799#" > "$TMP/env.sh"
( cd "$TMP" && RAFTER_API_KEY="CANARY-KEY-DO-NOT-LEAK" RAFTER_URL="http://127.0.0.1:8799" \
  SCAN_MODE="fast" GITHUB_OUTPUT="$TMP/gh_output" CANARY_PATH="$TMP/CANARY" \
  timeout 30 bash -c 'set -a; . "$1/env.sh"; set +a; exec bash "$1/run.sh"' _ "$TMP" >"$TMP/out2" 2>&1 )
kill $LISTENER 2>/dev/null; wait $LISTENER 2>/dev/null

if [ ! -s "$TMP/sent.json" ]; then
  echo "FAIL: FIDELITY — no request body was captured, so this asserted nothing"
  failures=$((failures+1))
else
  GOT=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('branch_name','(missing)'))" "$TMP/sent.json" 2>/dev/null || echo "(unparseable JSON)")
  if [ "$GOT" = "$ODD" ]; then
    echo "PASS: a branch name with a quote and a backslash arrived intact, as valid JSON"
  else
    echo "FAIL: FIDELITY — branch name was mangled."
    echo "      sent:     $GOT"
    echo "      expected: $ODD"
    failures=$((failures+1))
  fi
fi

echo ""
echo "── results ──────────────────────────────────────────────"
echo "Failures: $failures"
[ "$failures" -eq 0 ] || exit 1
echo "OK: a branch name cannot reach the shell that holds the key"
