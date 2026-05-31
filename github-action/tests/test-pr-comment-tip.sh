#!/usr/bin/env bash
#
# Unit test for the new PR-comment "report-only tip" block in
# github-action/action.yml. Re-implements the if block verbatim and
# exercises every input combination.
#
# The tip should appear iff (FINDINGS_COUNT > 0) AND (SEVERITY_THRESHOLD == 'none').

set -u

failures=0
total=0

# Mirror of the new block under the "Comment on PR" step's COMMENT_FILE builder.
emit_tip_if_applicable() {
  if [ "$FINDINGS_COUNT" -gt 0 ] && [ "$SEVERITY_THRESHOLD" = "none" ]; then
    echo "> :information_source: This run is report-only. To fail the build on critical/high findings, set \`severity-threshold: high\` in your workflow."
    echo ""
  fi
}

TIP_NEEDLE="report-only"

# assert_tip <name> <expected: yes|no> <findings> <threshold>
assert_tip() {
  local name="$1"; local expected="$2"
  FINDINGS_COUNT="$3"; SEVERITY_THRESHOLD="$4"
  total=$((total+1))

  local out
  out=$(emit_tip_if_applicable)
  local has_tip="no"
  if echo "$out" | grep -q "$TIP_NEEDLE"; then has_tip="yes"; fi

  if [ "$has_tip" != "$expected" ]; then
    echo "FAIL: $name — findings=$FINDINGS_COUNT threshold=$SEVERITY_THRESHOLD → expected tip=$expected got $has_tip"
    failures=$((failures+1))
  else
    echo "PASS: $name (tip=$has_tip)"
  fi
}

echo "── report-only tip should appear ────────────────────────────────────"
assert_tip "findings + none"          yes  5  none
assert_tip "single finding + none"    yes  1  none

echo "── report-only tip should NOT appear ────────────────────────────────"
assert_tip "no findings + none"       no   0  none
assert_tip "findings + high"          no   5  high
assert_tip "findings + critical"      no   5  critical
assert_tip "findings + medium"        no   5  medium
assert_tip "findings + low"           no   5  low
assert_tip "no findings + high"       no   0  high
assert_tip "no findings + critical"   no   0  critical

echo ""
echo "── results ───────────────────────────────────────────────────────────"
echo "Total: $total   Failures: $failures"
[ "$failures" -eq 0 ] || exit 1
echo "OK: PR-comment tip appears exactly when (findings > 0) AND (threshold == 'none')"
