#!/usr/bin/env bash
#
# rf-v2mj — an unreadable report must not render as a clean scan.
#
# The root action derives `finding-count` from the scanner's stdout. It used to
# end that derivation with `|| echo "0"`, so a truncated report, an HTML error
# page or an auth failure all produced finding-count=0: the value that means
# CLEAN. A consumer gating on it was told "no findings" precisely when the
# action could not see any output at all.
#
# Corpus: the ROOT action.yml. The separate github-action/action.yml had the
# same class of defect in its five severity counts and was fixed under
# sable-fgk7; this file was never touched by that work. Two action.yml files,
# and only one of them had been fixed.
#
# The control is the point: a fix that fails on everything would pass the first
# case and be useless. A genuinely clean report must still succeed with count 0.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)/action.yml"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
failures=0

# The scan step, with the runner's `${{ inputs.* }}` expansion applied.
render() {
  python3 - "$ROOT" "$1" <<'PY'
import sys, yaml, re
d = yaml.safe_load(open(sys.argv[1])); fmt = sys.argv[2]
for s in d["runs"]["steps"]:
    if s.get("id") == "scan":
        r = s["run"]
        r = re.sub(r"\$\{\{\s*inputs\.format\s*\}\}", fmt, r)
        r = re.sub(r"\$\{\{\s*inputs\.(scan-path|args)\s*\}\}", "", r)
        r = re.sub(r"\$\{\{.*?\}\}", "", r)
        print(r); break
else:
    sys.exit("no step id 'scan'")
PY
}

# A stub `rafter` that emits exactly what we want to test, with a chosen exit code.
stub() {
  mkdir -p "$TMP/bin"
  { echo '#!/usr/bin/env bash'; echo "cat <<'RAFTER_STUB_EOF'"; printf '%s\n' "$1"; echo 'RAFTER_STUB_EOF'; echo "exit ${2}"; } > "$TMP/bin/rafter"
  chmod +x "$TMP/bin/rafter"
}

run_scan() {
  render "$1" > "$TMP/scan.sh"
  : > "$TMP/gh_output"
  ( cd "$TMP" && PATH="$TMP/bin:$PATH" GITHUB_OUTPUT="$TMP/gh_output" \
      timeout 30 bash "$TMP/scan.sh" >"$TMP/out" 2>&1 )
  echo $?
}
count_written() { sed -n 's/^finding-count=\(.*\)$/\1/p' "$TMP/gh_output" | tail -1; }

echo "== rf-v2mj: an unreadable report is not a clean scan =="

# 1. THE BUG. Unparseable stdout with a success exit code — a truncated report,
#    an error page, anything jq cannot read.
stub '<html><body>502 Bad Gateway</body></html>' 0
rc=$(run_scan json); c=$(count_written)
if [ "$rc" -eq 0 ] && [ "$c" = "0" ]; then
  echo "FAIL: an unparseable report produced finding-count=0 and exit 0 — a clean scan"
  failures=$((failures+1))
elif [ "$rc" -eq 0 ]; then
  echo "FAIL: an unparseable report exited 0 (count written: '${c}')"
  failures=$((failures+1))
else
  echo "PASS: an unparseable report fails the step (exit ${rc}, count '${c}')"
fi

# 2. Truncated JSON — the likeliest real shape, and still not a clean scan.
stub '{"results": [{"matches": [{"rule":' 0
rc=$(run_scan json); c=$(count_written)
if [ "$rc" -eq 0 ]; then
  echo "FAIL: truncated JSON exited 0 (count written: '${c}')"
  failures=$((failures+1))
else
  echo "PASS: truncated JSON fails the step (exit ${rc})"
fi

# 3. THE CONTROL. A genuinely clean report must still succeed, with count 0.
#    Without this, "fail on everything" would pass the two cases above.
stub '{"_note":"x","scan_mode":"fast","triage_applied":false,"results":[]}' 0
rc=$(run_scan json); c=$(count_written)
if [ "$rc" -eq 0 ] && [ "$c" = "0" ]; then
  echo "PASS: a genuinely clean report still passes, count 0"
else
  echo "FAIL: CONTROL — a clean report no longer passes (exit ${rc}, count '${c}')"
  failures=$((failures+1))
fi

# 4. Second control: real findings must still be counted, not just tolerated.
stub '{"results":[{"matches":[{"rule":"aws"},{"rule":"gh"}]}]}' 1
rc=$(run_scan json); c=$(count_written)
if [ "$c" = "2" ]; then
  echo "PASS: real findings are counted (2)"
else
  echo "FAIL: CONTROL — findings miscounted: got '${c}', expected 2"
  failures=$((failures+1))
fi

echo ""
echo "── results ──────────────────────────────────────────────"
echo "Failures: $failures"
[ "$failures" -eq 0 ] || exit 1
echo "OK: the count is emitted only when the report was actually read"
