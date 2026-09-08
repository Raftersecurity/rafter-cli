#!/usr/bin/env bash
#
# Unit test for the PR-comment "report-only tip" block in
# github-action/action.yml. Sources github-action/lib/severity.sh — the SAME
# file action.yml sources at run time — and exercises every input
# combination of rafter_report_only_tip.
#
# The tip should appear iff (FINDINGS_COUNT > 0) AND (SEVERITY_THRESHOLD == 'none').
#
# This test used to carry its own copy of the if block (sable-1drb). It now
# runs the code the action runs.

set -u

# shellcheck source=../lib/severity.sh
source "$(cd "$(dirname "$0")/.." && pwd)/lib/severity.sh"

failures=0
total=0

TIP_NEEDLE="report-only"

# assert_tip <name> <expected: yes|no> <findings> <threshold>
assert_tip() {
  local name="$1"; local expected="$2"
  local findings="$3" threshold="$4"
  total=$((total+1))

  local out
  out=$(rafter_report_only_tip "$findings" "$threshold")
  local has_tip="no"
  if echo "$out" | grep -q "$TIP_NEEDLE"; then has_tip="yes"; fi

  if [ "$has_tip" != "$expected" ]; then
    echo "FAIL: $name — findings=$findings threshold=$threshold → expected tip=$expected got $has_tip"
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

echo "── the tip must tell the reader what to set ─────────────────────────"
total=$((total+1))
if rafter_report_only_tip 5 none | grep -q 'severity-threshold: high'; then
  echo "PASS: tip names the input to set"
else
  echo "FAIL: tip no longer names severity-threshold: high"
  failures=$((failures+1))
fi

echo ""
echo "── results ───────────────────────────────────────────────────────────"
echo "Total: $total   Failures: $failures"
[ "$failures" -eq 0 ] || exit 1
echo "OK: PR-comment tip appears exactly when (findings > 0) AND (threshold == 'none')"
