#!/usr/bin/env bash
#
# Severity-threshold logic shared by github-action/action.yml and the tests
# under github-action/tests/. ONE copy, sourced by both, so the tests exercise
# the code the action runs rather than a transcription of it (sable-1drb).
#
# Sourced, never executed: no `set -e`, no side effects at load time. Every
# function takes explicit arguments so a test can call it without staging
# environment variables, and prints only what the action wants in its log.

# rafter_threshold_fails THRESHOLD CRITICAL HIGH MEDIUM LOW
#
# Returns 0 when the findings exceed THRESHOLD (the build should fail) and 1
# otherwise. 'none' never fails. An unrecognised threshold behaves like
# 'high' and says so with a ::warning:: annotation.
rafter_threshold_fails() {
  local threshold="$1" critical="$2" high="$3" medium="$4" low="$5"
  local fail=0
  case "$threshold" in
    critical)
      [ "$critical" -gt 0 ] && fail=1
      ;;
    high)
      [ "$critical" -gt 0 ] || [ "$high" -gt 0 ] && fail=1
      ;;
    medium)
      [ "$critical" -gt 0 ] || [ "$high" -gt 0 ] || [ "$medium" -gt 0 ] && fail=1
      ;;
    low)
      [ "$critical" -gt 0 ] || [ "$high" -gt 0 ] || [ "$medium" -gt 0 ] || [ "$low" -gt 0 ] && fail=1
      ;;
    none)
      fail=0
      ;;
    *)
      echo "::warning::Unknown severity threshold '${threshold}', defaulting to 'high'"
      [ "$critical" -gt 0 ] || [ "$high" -gt 0 ] && fail=1
      ;;
  esac
  [ "$fail" -eq 1 ]
}

# rafter_report_only_tip FINDINGS_COUNT THRESHOLD
#
# Prints the report-only tip block for the PR comment iff there are findings
# AND the threshold is 'none' (the default), i.e. the run reported problems
# but was configured never to fail on them. Prints nothing otherwise.
rafter_report_only_tip() {
  local findings="$1" threshold="$2"
  if [ "$findings" -gt 0 ] && [ "$threshold" = "none" ]; then
    echo "> :information_source: This run is report-only. To fail the build on critical/high findings, set \`severity-threshold: high\` in your workflow."
    echo ""
  fi
}
