#!/usr/bin/env bash
#
# Unit test for the "Evaluate severity threshold" step in
# github-action/action.yml. Sources github-action/lib/severity.sh — the SAME
# file action.yml sources at run time — and exercises every branch of
# rafter_threshold_fails with deliberate inputs.
#
# This test used to carry its own copy of the case statement, so it could
# pass in full while action.yml was broken (sable-1drb). It now runs the code
# the action runs. The drift detector (test-action-yml-defaults.sh) separately
# asserts that action.yml still sources the library rather than inlining a
# copy again.
#
# Exit 0 = all cases pass. Exit 1 = at least one case failed.

set -u

# shellcheck source=../lib/severity.sh
source "$(cd "$(dirname "$0")/.." && pwd)/lib/severity.sh"

failures=0
total=0

# assert_threshold <name> <expected: fail|pass> <severity> <crit> <high> <med> <low>
assert_threshold() {
  local name="$1"; local expected="$2"
  local threshold="$3" crit="$4" high="$5" med="$6" low="$7"
  total=$((total+1))

  local actual="pass"
  if rafter_threshold_fails "$threshold" "$crit" "$high" "$med" "$low" >/dev/null; then
    actual="fail"
  fi

  if [ "$actual" != "$expected" ]; then
    echo "FAIL: $name — threshold=$threshold crit=$crit high=$high med=$med low=$low → expected build=$expected got $actual"
    failures=$((failures+1))
  else
    echo "PASS: $name"
  fi
}

echo "── 'none' threshold (the default) — must never fail ────────────────"
assert_threshold "none + no findings"          pass  none      0 0 0 0
assert_threshold "none + low only"             pass  none      0 0 0 7
assert_threshold "none + medium only"          pass  none      0 0 3 0
assert_threshold "none + high only"            pass  none      0 5 0 0
assert_threshold "none + critical only"        pass  none      2 0 0 0
assert_threshold "none + everything"           pass  none      9 9 9 9

echo "── 'critical' threshold — fail only on critical ────────────────────"
assert_threshold "critical + clean"            pass  critical  0 0 0 0
assert_threshold "critical + only high"        pass  critical  0 4 0 0
assert_threshold "critical + only medium"      pass  critical  0 0 4 0
assert_threshold "critical + only low"         pass  critical  0 0 0 4
assert_threshold "critical + critical=1"       fail  critical  1 0 0 0
assert_threshold "critical + critical+high"    fail  critical  1 5 0 0

echo "── 'high' threshold — fail on critical or high ─────────────────────"
assert_threshold "high + clean"                pass  high      0 0 0 0
assert_threshold "high + only medium"          pass  high      0 0 4 0
assert_threshold "high + only low"             pass  high      0 0 0 4
assert_threshold "high + critical only"        fail  high      1 0 0 0
assert_threshold "high + high only"            fail  high      0 1 0 0
assert_threshold "high + critical+high"        fail  high      1 1 0 0

echo "── 'medium' threshold — fail on crit/high/medium ───────────────────"
assert_threshold "medium + clean"              pass  medium    0 0 0 0
assert_threshold "medium + only low"           pass  medium    0 0 0 4
assert_threshold "medium + critical only"      fail  medium    1 0 0 0
assert_threshold "medium + high only"          fail  medium    0 1 0 0
assert_threshold "medium + medium only"        fail  medium    0 0 1 0

echo "── 'low' threshold — fail on anything ──────────────────────────────"
assert_threshold "low + clean"                 pass  low       0 0 0 0
assert_threshold "low + only low"              fail  low       0 0 0 1
assert_threshold "low + critical only"         fail  low       1 0 0 0

echo "── unknown threshold — falls back to 'high' behavior ───────────────"
assert_threshold "unknown + clean"             pass  badvalue  0 0 0 0
assert_threshold "unknown + critical"          fail  badvalue  1 0 0 0
assert_threshold "unknown + high"              fail  badvalue  0 1 0 0
assert_threshold "unknown + medium only"       pass  badvalue  0 0 3 0

echo "── unknown threshold — must say so in the log ──────────────────────"
total=$((total+1))
if rafter_threshold_fails badvalue 0 0 0 0 | grep -q "::warning::Unknown severity threshold 'badvalue'"; then
  echo "PASS: unknown threshold emits a ::warning:: naming the value"
else
  echo "FAIL: unknown threshold no longer warns"
  failures=$((failures+1))
fi

echo ""
echo "── results ───────────────────────────────────────────────────────────"
echo "Total: $total   Failures: $failures"
[ "$failures" -eq 0 ] || exit 1
echo "OK: all threshold-eval branches behave as expected"
