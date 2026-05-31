#!/usr/bin/env bash
#
# Unit test for the "Evaluate severity threshold" step in
# github-action/action.yml. Re-implements the case statement verbatim and
# exercises every branch with deliberate inputs.
#
# If you change the case body in action.yml, you MUST change it here too —
# the test-action-yml-defaults check enforces drift detection on the default
# value, but the case body itself is duplicated by design (sourcing bash out
# of YAML at test time is fragile).
#
# Exit 0 = all cases pass. Exit 1 = at least one case failed.

set -u

failures=0
total=0

# Mirror of the case body in github-action/action.yml under the
# "Evaluate severity threshold" step. Returns 1 if the threshold would
# fail the build given the current *_COUNT envs, else 0.
evaluate_threshold() {
  local FAIL=0
  case "$SEVERITY_THRESHOLD" in
    critical)
      [ "$CRITICAL_COUNT" -gt 0 ] && FAIL=1
      ;;
    high)
      [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ] && FAIL=1
      ;;
    medium)
      [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ] || [ "$MEDIUM_COUNT" -gt 0 ] && FAIL=1
      ;;
    low)
      [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ] || [ "$MEDIUM_COUNT" -gt 0 ] || [ "$LOW_COUNT" -gt 0 ] && FAIL=1
      ;;
    none)
      FAIL=0
      ;;
    *)
      [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ] && FAIL=1
      ;;
  esac
  return $FAIL
}

# assert_threshold <name> <expected_exit> <severity> <crit> <high> <med> <low>
assert_threshold() {
  local name="$1"; local expected="$2"
  SEVERITY_THRESHOLD="$3"
  CRITICAL_COUNT="$4"; HIGH_COUNT="$5"; MEDIUM_COUNT="$6"; LOW_COUNT="$7"
  total=$((total+1))

  evaluate_threshold
  local actual=$?

  if [ "$actual" != "$expected" ]; then
    echo "FAIL: $name — threshold=$SEVERITY_THRESHOLD crit=$CRITICAL_COUNT high=$HIGH_COUNT med=$MEDIUM_COUNT low=$LOW_COUNT → expected exit=$expected got $actual"
    failures=$((failures+1))
  else
    echo "PASS: $name"
  fi
}

echo "── 'none' threshold (the new default) — must never fail ─────────────"
assert_threshold "none + no findings"          0  none      0 0 0 0
assert_threshold "none + low only"             0  none      0 0 0 7
assert_threshold "none + medium only"          0  none      0 0 3 0
assert_threshold "none + high only"            0  none      0 5 0 0
assert_threshold "none + critical only"        0  none      2 0 0 0
assert_threshold "none + everything"           0  none      9 9 9 9

echo "── 'critical' threshold — fail only on critical ────────────────────"
assert_threshold "critical + clean"            0  critical  0 0 0 0
assert_threshold "critical + only high"        0  critical  0 4 0 0
assert_threshold "critical + only medium"      0  critical  0 0 4 0
assert_threshold "critical + only low"         0  critical  0 0 0 4
assert_threshold "critical + critical=1"       1  critical  1 0 0 0
assert_threshold "critical + critical+high"    1  critical  1 5 0 0

echo "── 'high' threshold — fail on critical or high ─────────────────────"
assert_threshold "high + clean"                0  high      0 0 0 0
assert_threshold "high + only medium"          0  high      0 0 4 0
assert_threshold "high + only low"             0  high      0 0 0 4
assert_threshold "high + critical only"        1  high      1 0 0 0
assert_threshold "high + high only"            1  high      0 1 0 0
assert_threshold "high + critical+high"        1  high      1 1 0 0

echo "── 'medium' threshold — fail on crit/high/medium ───────────────────"
assert_threshold "medium + clean"              0  medium    0 0 0 0
assert_threshold "medium + only low"           0  medium    0 0 0 4
assert_threshold "medium + critical only"      1  medium    1 0 0 0
assert_threshold "medium + high only"          1  medium    0 1 0 0
assert_threshold "medium + medium only"        1  medium    0 0 1 0

echo "── 'low' threshold — fail on anything ──────────────────────────────"
assert_threshold "low + clean"                 0  low       0 0 0 0
assert_threshold "low + only low"              1  low       0 0 0 1
assert_threshold "low + critical only"         1  low       1 0 0 0

echo "── unknown threshold — falls back to 'high' behavior ───────────────"
assert_threshold "unknown + clean"             0  badvalue  0 0 0 0
assert_threshold "unknown + critical"          1  badvalue  1 0 0 0
assert_threshold "unknown + high"              1  badvalue  0 1 0 0
assert_threshold "unknown + medium only"       0  badvalue  0 0 3 0

echo ""
echo "── results ───────────────────────────────────────────────────────────"
echo "Total: $total   Failures: $failures"
[ "$failures" -eq 0 ] || exit 1
echo "OK: all threshold-eval branches behave as expected"
