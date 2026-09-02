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

# ── sable-l10k: poll-path retry contract ─────────────────────────────────
# These properties are subtle and cheap to "simplify" away. Each one, if
# dropped, reproduces a bug a paying customer already hit.

# 5. 404 must be in the poll loop's TRANSIENT condition. It is safe only
#    because the trigger step already handed us a scan_id, so a missing scan
#    mid-poll is read-after-write lag rather than a wrong id.
if grep -qE '\$HTTP_CODE" -ge 500 \] \|\| \[ "\$HTTP_CODE" -eq 408 \] \|\| \[ "\$HTTP_CODE" -eq 404' "$ACTION_YML"; then
  echo "PASS: poll loop treats 5xx/408/404 as transient"
else
  echo "FAIL: poll loop's transient condition changed — 404/408/5xx must all retry"
  failures=$((failures+1))
fi

# 6. A transport error must count toward the SAME failure budget as a 5xx.
#    When it did not, an unreachable backend reported "scan did not complete
#    within N minutes" — a timeout message for a DNS failure.
if awk '/curl transport error contacting/,/^          \}/' "$ACTION_YML" \
     | grep -q 'TRANSIENT_FAILURES=\$((TRANSIENT_FAILURES+1))'; then
  echo "PASS: transport errors count toward the transient-failure budget"
else
  echo "FAIL: poll loop's transport-error branch no longer counts toward the budget"
  failures=$((failures+1))
fi

# 7. The give-up message must be actionable: name the scan, and offer a next
#    step. Raw storage wording ("Object not found") alone is not a message a
#    customer can act on.
if grep -q 'could not read the report for scan \${SCAN_ID}' "$ACTION_YML" \
   && grep -q 'check it in your dashboard at' "$ACTION_YML"; then
  echo "PASS: give-up message names the scan and offers a next step"
else
  echo "FAIL: give-up message no longer names the scan id or a next step"
  failures=$((failures+1))
fi

# 8. Both give-up paths in the results fetch must record status=unreadable.
#    Without it the declared `status` output falls back to the poll step's
#    `completed`, and a failed report read is reported as a clean scan.
unreadable_writes=$(grep -c 'status=unreadable' "$ACTION_YML" || true)
if [ "$unreadable_writes" -ge 3 ]; then
  echo "PASS: poll and both results-fetch give-up paths record status=unreadable"
else
  echo "FAIL: expected >=3 status=unreadable writes, found ${unreadable_writes}"
  failures=$((failures+1))
fi

# 9. The artifact upload must be gated on the RESULTS step, not the poll step.
#    Gated on the poll step it published the error body as rafter-results.json.
if grep -qE "if: steps\.results\.outputs\.status == 'completed'" "$ACTION_YML"; then
  echo "PASS: artifact upload gated on a successful results fetch"
else
  echo "FAIL: artifact upload is not gated on steps.results.outputs.status"
  failures=$((failures+1))
fi

# 10. Backoff must be exponential. A flat or zeroed backoff gives an
#     eventually-consistent object store no time to converge.
if grep -q 'BACKOFF=\$(( 2 \*\* TRANSIENT_FAILURES ))' "$ACTION_YML" \
   && grep -q 'backoff=\$(( 2 \*\* attempt ))' "$ACTION_YML"; then
  echo "PASS: both retry loops back off exponentially"
else
  echo "FAIL: a retry loop's backoff is no longer exponential"
  failures=$((failures+1))
fi


# 11. Server-controlled error text must be newline-stripped and length-capped
#     before it reaches a workflow command. A newline forges ::add-mask:: /
#     ::stop-commands:: / fabricated ::error:: annotations.
sanitized=$(grep -cF 'cut -c1-' "$ACTION_YML" || true)
stripped=$(grep -cF "tr -d " "$ACTION_YML" || true)
if [ "$sanitized" -ge 5 ] && [ "$stripped" -ge 5 ]; then
  echo "PASS: server-controlled text newline-stripped and capped at ${sanitized} sites"
else
  echo "FAIL: expected >=5 sanitized sites, found cut=${sanitized} tr=${stripped}"
  failures=$((failures+1))
fi

# 12. TIMEOUT_MINUTES is evaluated inside bash arithmetic, where a value like
#     'x[$(cmd)]' executes. It must be validated first.
if grep -q 'case "\$TIMEOUT_MINUTES" in' "$ACTION_YML"; then
  echo "PASS: timeout-minutes validated before arithmetic evaluation"
else
  echo "FAIL: timeout-minutes is no longer validated before arithmetic use"
  failures=$((failures+1))
fi

# 13. The server-controlled scan id must be validated before it reaches
#     \$GITHUB_OUTPUT, where a newline forges step outputs.
if grep -q 'case "\$SCAN_ID" in' "$ACTION_YML"; then
  echo "PASS: scan id validated before it reaches \$GITHUB_OUTPUT"
else
  echo "FAIL: scan id is no longer validated"
  failures=$((failures+1))
fi

# ── sable-96ex: the 429 / Retry-After contract ───────────────────────────
# A 429 is retried on exactly one condition — the server said when to come
# back. Both halves are load-bearing: drop the gate and a quota rejection
# costs every build 30 seconds before failing anyway; drop the retry and the
# day a limiter lands in front of the poll endpoint, every customer build
# fails instantly on a condition a sleep would have resolved.

# 14. The poll loop's 429 branch must be gated on a non-empty Retry-After.
if grep -q '\[ "\$HTTP_CODE" -eq 429 \] && \[ -n "\$RETRY_AFTER" \]' "$ACTION_YML"; then
  echo "PASS: poll loop retries 429 only when Retry-After is present"
else
  echo "FAIL: poll loop's 429 branch is no longer gated on Retry-After"
  failures=$((failures+1))
fi

# 15. Same gate in the results fetch: a 429 stays non-transient there unless
#     Retry-After came with it.
if grep -q '\[ "\$code" -ne 404 \] \\' "$ACTION_YML" \
   && grep -q '&& \[ -z "\$retry_after" \]; then' "$ACTION_YML"; then
  echo "PASS: results fetch retries 429 only when Retry-After is present"
else
  echo "FAIL: results fetch's 429 gate changed"
  failures=$((failures+1))
fi

# 16. Retry-After is server-controlled and becomes a sleep duration. It must be
#     validated as digits AND length-capped in both loops: `[ 1e23 -gt 60 ]` is
#     an error that evaluates false, so an uncapped 23-digit value would reach
#     `sleep` intact and hang the job until the runner times out.
# `set -e` is on: an `x && y` list whose test fails would abort the script
# before it could report anything, so these stay full `if` statements.
digit_guards=0
if grep -qF "''|*[!0-9]*) RETRY_AFTER=\"\" ;;" "$ACTION_YML"; then
  digit_guards=$((digit_guards+1))
fi
if grep -qF "''|*[!0-9]*) retry_after=\"\" ;;" "$ACTION_YML"; then
  digit_guards=$((digit_guards+1))
fi
len_guards=$(grep -cE '\$\{#(RETRY_AFTER|retry_after)\}" -gt 6' "$ACTION_YML" || true)
if [ "$digit_guards" -eq 2 ] && [ "$len_guards" -eq 2 ]; then
  echo "PASS: Retry-After validated (digits + length) in both retry loops"
else
  echo "FAIL: Retry-After validation missing (digit guards=${digit_guards}, length guards=${len_guards}; want 2 and 2)"
  failures=$((failures+1))
fi

# 17. The honored wait must be capped. An unclamped Retry-After lets the server
#     park a CI job for as long as it likes.
if [ "$(grep -cE '(BACKOFF|backoff)" -gt "\$(MAX_RETRY_AFTER|max_retry_after)"' "$ACTION_YML" || true)" -eq 2 ]; then
  echo "PASS: both loops cap the honored Retry-After"
else
  echo "FAIL: a retry loop no longer caps the Retry-After it honors"
  failures=$((failures+1))
fi

# 18. ...and the poll loop's honored delay must also be clamped to what is left
#     of the wall-clock deadline. timeout-minutes became a real deadline in
#     sable-l10k; a 60s Retry-After is long enough to overrun it, and the server
#     does not get to extend a budget the workflow author set.
if grep -q 'REMAINING=$(( DEADLINE - $(date +%s) ))' "$ACTION_YML" \
   && grep -q 'if \[ "$BACKOFF" -gt "$REMAINING" \]' "$ACTION_YML"; then
  echo "PASS: the honored Retry-After cannot outlive the deadline"
else
  echo "FAIL: the honored Retry-After is no longer clamped to the deadline"
  failures=$((failures+1))
fi

# 19. A throttled give-up must not be reported as an unreadable report — that
#     sends the customer to look at their scan instead of their rate limit.
if [ "$(grep -c 'status=rate-limited' "$ACTION_YML" || true)" -ge 2 ]; then
  echo "PASS: both give-up paths distinguish rate-limited from unreadable"
else
  echo "FAIL: status=rate-limited missing from a give-up path"
  failures=$((failures+1))
fi

echo ""
echo "── results ───────────────────────────────────────────────────────────"
echo "Failures: $failures"
[ "$failures" -eq 0 ] || exit 1
echo "OK: action.yml load-bearing properties intact"
