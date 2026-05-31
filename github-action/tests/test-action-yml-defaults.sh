#!/usr/bin/env bash
#
# Drift-detection check for github-action/action.yml. Asserts that the
# `severity-threshold` input default is literally 'none' and that the
# PR-comment step still wires SEVERITY_THRESHOLD through as an env var
# (the GitHub-recommended pattern that prevents script injection from
# inputs).
#
# These are the load-bearing properties of the v0.8.3 default flip; if
# someone reverts either, this test fails loudly before the release ships.

set -eu

ACTION_YML="$(cd "$(dirname "$0")/.." && pwd)/action.yml"

if [ ! -f "$ACTION_YML" ]; then
  echo "FAIL: $ACTION_YML not found"
  exit 1
fi

failures=0

# 1. severity-threshold default must be the string 'none'. Match the YAML
#    block scalar exactly to avoid matching the input description text.
if awk '
  /^[[:space:]]*severity-threshold:/ { in_block=1; next }
  in_block && /^[[:space:]]*default:/ { print; exit }
' "$ACTION_YML" | grep -qE "default: *'none'"; then
  echo "PASS: severity-threshold default is 'none'"
else
  echo "FAIL: severity-threshold default is NOT 'none' in $ACTION_YML"
  awk '
    /^[[:space:]]*severity-threshold:/ { in_block=1; next }
    in_block && /^[[:space:]]*default:/ { print "  found: " $0; exit }
  ' "$ACTION_YML"
  failures=$((failures+1))
fi

# 2. SEVERITY_THRESHOLD must be wired through as an env var on the
#    "Comment on PR" step (GitHub-recommended template-injection mitigation).
if grep -qE "SEVERITY_THRESHOLD: *\\\$\\{\\{ *inputs\\.severity-threshold *\\}\\}" "$ACTION_YML"; then
  echo "PASS: SEVERITY_THRESHOLD wired as env var (not script interpolation)"
else
  echo "FAIL: SEVERITY_THRESHOLD env var passthrough missing from $ACTION_YML"
  failures=$((failures+1))
fi

# 3. The report-only tip block must be present and gated on both conditions.
if grep -qE '\[ "\$FINDINGS_COUNT" -gt 0 \] && \[ "\$SEVERITY_THRESHOLD" = "none" \]' "$ACTION_YML"; then
  echo "PASS: report-only tip block gated on (findings > 0) AND (threshold == 'none')"
else
  echo "FAIL: report-only tip block missing or mis-gated in $ACTION_YML"
  failures=$((failures+1))
fi

# 4. The threshold-eval step must still handle 'none' as a no-op
#    (no FAIL=1 in the none branch).
if awk '
  /none\)/ { in_none=1; next }
  in_none && /;;/ { in_none=0; next }
  in_none { print }
' "$ACTION_YML" | grep -qE "FAIL *= *1"; then
  echo "FAIL: 'none' branch of threshold-eval sets FAIL=1 — that would break the default"
  failures=$((failures+1))
else
  echo "PASS: 'none' branch of threshold-eval does not set FAIL=1"
fi

echo ""
echo "── results ───────────────────────────────────────────────────────────"
echo "Failures: $failures"
[ "$failures" -eq 0 ] || exit 1
echo "OK: action.yml load-bearing properties intact"
