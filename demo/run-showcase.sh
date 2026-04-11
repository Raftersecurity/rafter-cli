#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Rafter CLI — Demo Showcase Harness
#
# Runs the full test suite as a scripted presentation, grouping tests
# by feature area with commentary. Designed for live demos, CI badges,
# and investor/partner walkthroughs.
#
# Usage:
#   ./demo/run-showcase.sh              # Full showcase (Node + Python)
#   ./demo/run-showcase.sh --node       # Node.js only
#   ./demo/run-showcase.sh --python     # Python only
#   ./demo/run-showcase.sh --fast       # Skip pauses between acts
#   ./demo/run-showcase.sh --json       # Machine-readable JSON summary
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NODE_DIR="$ROOT_DIR/node"
PYTHON_DIR="$ROOT_DIR/python"

# ── Options ──────────────────────────────────────────────────────────
RUN_NODE=true
RUN_PYTHON=true
FAST=false
JSON_OUTPUT=false
PAUSE_SECS=1

while [[ $# -gt 0 ]]; do
  case $1 in
    --node)    RUN_PYTHON=false; shift ;;
    --python)  RUN_NODE=false;   shift ;;
    --fast)    FAST=true; PAUSE_SECS=0; shift ;;
    --json)    JSON_OUTPUT=true; FAST=true; PAUSE_SECS=0; shift ;;
    -h|--help)
      sed -n '2,/^# ──/{ /^# ──/d; s/^# \?//; p }' "$0"
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

# ── Colors ───────────────────────────────────────────────────────────
if [[ -t 1 ]] && [[ "$JSON_OUTPUT" == false ]]; then
  BOLD='\033[1m'
  DIM='\033[2m'
  GREEN='\033[32m'
  RED='\033[31m'
  YELLOW='\033[33m'
  CYAN='\033[36m'
  MAGENTA='\033[35m'
  RESET='\033[0m'
else
  BOLD='' DIM='' GREEN='' RED='' YELLOW='' CYAN='' MAGENTA='' RESET=''
fi

# ── State ────────────────────────────────────────────────────────────
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
ACT_NUM=0
ACT_RESULTS=()       # "name|pass|fail|skip|time"
START_TIME=$(date +%s)

# ── Helpers ──────────────────────────────────────────────────────────

banner() {
  if [[ "$JSON_OUTPUT" == true ]]; then return; fi
  local width=68
  echo ""
  printf "${CYAN}${BOLD}"
  printf '%.0s─' $(seq 1 $width); echo ""
  printf "  %s\n" "$1"
  if [[ -n "${2:-}" ]]; then
    printf "${RESET}${DIM}  %s${RESET}\n" "$2"
  fi
  printf "${CYAN}${BOLD}"
  printf '%.0s─' $(seq 1 $width)
  printf "${RESET}\n\n"
}

act_header() {
  ACT_NUM=$((ACT_NUM + 1))
  if [[ "$JSON_OUTPUT" == true ]]; then return; fi
  echo ""
  printf "${MAGENTA}${BOLD}  ▸ Act %d: %s${RESET}\n" "$ACT_NUM" "$1"
  if [[ -n "${2:-}" ]]; then
    printf "${DIM}    %s${RESET}\n" "$2"
  fi
  echo ""
}

pause() {
  if [[ "$FAST" == true ]]; then return; fi
  sleep "$PAUSE_SECS"
}

# Run a test group and capture results.
# Usage: run_tests <label> <engine> <pattern-or-args>
#   engine: "vitest" or "pytest"
run_tests() {
  local label="$1"
  local engine="$2"
  shift 2
  local args=("$@")

  local pass=0 fail=0 skip=0 t_start t_end elapsed

  t_start=$(date +%s)

  if [[ "$engine" == "vitest" ]]; then
    local output
    output=$(cd "$NODE_DIR" && npx vitest run "${args[@]}" --reporter=verbose 2>&1) || true
    # Parse vitest output
    pass=$(echo "$output" | grep -cE '^\s*✓|^\s*√' || true)
    fail=$(echo "$output" | grep -cE '^\s*✕|^\s*×|FAIL' || true)
    skip=$(echo "$output" | grep -cE '^\s*↓|skipped' || true)

    # Better parsing from summary line: "Tests  X passed | Y failed"
    local summary_line
    summary_line=$(echo "$output" | grep -E 'Tests\s+[0-9]' | tail -1 || true)
    if [[ -n "$summary_line" ]]; then
      pass=$(echo "$summary_line" | grep -oP '\d+(?=\s+passed)' || echo "$pass")
      fail=$(echo "$summary_line" | grep -oP '\d+(?=\s+failed)' || echo "$fail")
      skip=$(echo "$summary_line" | grep -oP '\d+(?=\s+skipped)' || echo "$skip")
    fi
  elif [[ "$engine" == "pytest" ]]; then
    local output
    output=$(cd "$PYTHON_DIR" && python -m pytest "${args[@]}" -v --tb=short 2>&1) || true
    # Parse pytest summary: "X passed, Y failed, Z skipped"
    local summary_line
    summary_line=$(echo "$output" | grep -E '(passed|failed|error)' | tail -1 || true)
    pass=$(echo "$summary_line" | grep -oP '\d+(?= passed)' || echo "0")
    fail=$(echo "$summary_line" | grep -oP '\d+(?= failed)' || echo "0")
    skip=$(echo "$summary_line" | grep -oP '\d+(?= skipped)' || echo "0")
    # Also count errors as failures
    local errors
    errors=$(echo "$summary_line" | grep -oP '\d+(?= error)' || echo "0")
    fail=$((fail + errors))
  fi

  t_end=$(date +%s)
  elapsed=$((t_end - t_start))

  # Ensure numeric
  pass=${pass:-0}; fail=${fail:-0}; skip=${skip:-0}

  TOTAL_PASS=$((TOTAL_PASS + pass))
  TOTAL_FAIL=$((TOTAL_FAIL + fail))
  TOTAL_SKIP=$((TOTAL_SKIP + skip))
  ACT_RESULTS+=("${label}|${pass}|${fail}|${skip}|${elapsed}s")

  if [[ "$JSON_OUTPUT" == false ]]; then
    local status_color="$GREEN"
    local status_icon="✓"
    if [[ "$fail" -gt 0 ]]; then
      status_color="$RED"
      status_icon="✗"
    elif [[ "$pass" -eq 0 ]]; then
      status_color="$YELLOW"
      status_icon="○"
    fi

    printf "    ${status_color}${status_icon}${RESET} %-40s " "$label"
    printf "${GREEN}%3d passed${RESET}" "$pass"
    if [[ "$fail" -gt 0 ]]; then printf "  ${RED}%d failed${RESET}" "$fail"; fi
    if [[ "$skip" -gt 0 ]]; then printf "  ${DIM}%d skipped${RESET}" "$skip"; fi
    printf "  ${DIM}(%ss)${RESET}\n" "$elapsed"
  fi
}

# ── Preflight ────────────────────────────────────────────────────────
banner "RAFTER CLI — Test Suite Showcase" \
       "Security tooling for AI coding agents • $(date +%Y-%m-%d)"

if [[ "$JSON_OUTPUT" == false ]]; then
  printf "  ${DIM}Checking prerequisites...${RESET}\n"
fi

# Check node
if [[ "$RUN_NODE" == true ]]; then
  if ! command -v node &>/dev/null; then
    echo "  ✗ Node.js not found — skipping Node tests" >&2
    RUN_NODE=false
  else
    node_ver=$(node --version)
    if [[ "$JSON_OUTPUT" == false ]]; then
      printf "  ${GREEN}✓${RESET} Node.js %s\n" "$node_ver"
    fi
  fi
fi

# Check python
if [[ "$RUN_PYTHON" == true ]]; then
  if ! command -v python &>/dev/null && ! command -v python3 &>/dev/null; then
    echo "  ✗ Python not found — skipping Python tests" >&2
    RUN_PYTHON=false
  else
    py_cmd=$(command -v python3 || command -v python)
    py_ver=$($py_cmd --version 2>&1)
    if [[ "$JSON_OUTPUT" == false ]]; then
      printf "  ${GREEN}✓${RESET} %s\n" "$py_ver"
    fi
  fi
fi

# Build Node if needed
if [[ "$RUN_NODE" == true ]]; then
  if [[ "$JSON_OUTPUT" == false ]]; then
    printf "  ${DIM}Building Node.js...${RESET}"
  fi
  (cd "$NODE_DIR" && pnpm run build 2>&1) >/dev/null || true
  if [[ "$JSON_OUTPUT" == false ]]; then
    printf "\r  ${GREEN}✓${RESET} Node.js built        \n"
  fi
fi

pause

# ═══════════════════════════════════════════════════════════════════
# ACT 1 — Secret Scanning
# ═══════════════════════════════════════════════════════════════════
act_header "Secret Scanning" \
  "21+ regex patterns • Gitleaks integration • SARIF output"

if [[ "$RUN_NODE" == true ]]; then
  run_tests "Node: secret patterns"        vitest tests/secret-patterns.test.ts
  run_tests "Node: regex scanner"          vitest tests/regex-scanner.test.ts
  run_tests "Node: pattern engine"         vitest tests/pattern-engine.test.ts
  run_tests "Node: gitleaks severity"      vitest tests/gitleaks-severity.test.ts
  run_tests "Node: SARIF output"           vitest tests/scan-sarif.test.ts
fi
if [[ "$RUN_PYTHON" == true ]]; then
  run_tests "Python: regex scanner"        pytest tests/test_regex_scanner.py
  run_tests "Python: pattern engine"       pytest tests/test_pattern_engine.py
  run_tests "Python: gitleaks severity"    pytest tests/test_gitleaks_severity.py
fi
pause

# ═══════════════════════════════════════════════════════════════════
# ACT 2 — Command Interception & Risk Classification
# ═══════════════════════════════════════════════════════════════════
act_header "Command Interception" \
  "4 risk tiers • pattern matching • policy enforcement"

if [[ "$RUN_NODE" == true ]]; then
  run_tests "Node: command interceptor"    vitest tests/command-interceptor.test.ts
  run_tests "Node: risk rules"             vitest tests/risk-rules.test.ts
  run_tests "Node: risk rules (comprehensive)" vitest tests/risk-rules-comprehensive.test.ts
  run_tests "Node: risk bypass"            vitest tests/risk-rules-bypass.test.ts
fi
if [[ "$RUN_PYTHON" == true ]]; then
  run_tests "Python: command interceptor"  pytest tests/test_command_interceptor.py
  run_tests "Python: risk rules"           pytest tests/test_risk_rules.py
fi
pause

# ═══════════════════════════════════════════════════════════════════
# ACT 3 — Policy Engine
# ═══════════════════════════════════════════════════════════════════
act_header "Policy Engine" \
  ".rafter.yml policy-as-code • validation • loader"

if [[ "$RUN_NODE" == true ]]; then
  run_tests "Node: policy validation"      vitest tests/policy-validation.test.ts
  run_tests "Node: policy loader"          vitest tests/policy-loader.test.ts
fi
if [[ "$RUN_PYTHON" == true ]]; then
  run_tests "Python: policy"               pytest tests/test_policy.py
fi
pause

# ═══════════════════════════════════════════════════════════════════
# ACT 4 — Configuration & Audit
# ═══════════════════════════════════════════════════════════════════
act_header "Configuration & Audit Trail" \
  "Config merging • JSONL audit logs • read/write lifecycle"

if [[ "$RUN_NODE" == true ]]; then
  run_tests "Node: config manager"         vitest tests/config-manager.test.ts
  run_tests "Node: audit logger"           vitest tests/audit-logger.test.ts
  run_tests "Node: audit logger (read)"    vitest tests/audit-logger-read.test.ts
  run_tests "Node: audit share"            vitest tests/audit-share.test.ts
  run_tests "Node: audit skill"            vitest tests/audit-skill.test.ts
fi
if [[ "$RUN_PYTHON" == true ]]; then
  run_tests "Python: config manager"       pytest tests/test_config_manager.py
fi
pause

# ═══════════════════════════════════════════════════════════════════
# ACT 5 — Agent Integration
# ═══════════════════════════════════════════════════════════════════
act_header "Agent Integration" \
  "Claude Code • Codex • OpenClaw • 8 platform adapters"

if [[ "$RUN_NODE" == true ]]; then
  run_tests "Node: agent compatibility"    vitest tests/agent-compatibility.test.ts
  run_tests "Node: Claude Code integration" vitest tests/claude-code-integration.test.ts
  run_tests "Node: Codex integration"      vitest tests/codex-integration.test.ts
  run_tests "Node: OpenClaw integration"   vitest tests/openclaw-integration.test.ts
  run_tests "Node: platform integration"   vitest tests/platform-integration.test.ts
fi
if [[ "$RUN_PYTHON" == true ]]; then
  run_tests "Python: agent init"           pytest tests/test_agent_init.py
  run_tests "Python: agent hook install"   pytest tests/test_agent_install_hook.py
  run_tests "Python: agent verify"         pytest tests/test_agent_verify.py
  run_tests "Python: agent baseline"       pytest tests/test_agent_baseline.py
fi
pause

# ═══════════════════════════════════════════════════════════════════
# ACT 6 — MCP Server
# ═══════════════════════════════════════════════════════════════════
act_header "MCP Server" \
  "4 tools • 2 resources • stdio transport"

if [[ "$RUN_NODE" == true ]]; then
  run_tests "Node: MCP server"             vitest tests/mcp-server.test.ts
  run_tests "Node: MCP integration"        vitest tests/mcp-server-integration.test.ts
fi
if [[ "$RUN_PYTHON" == true ]]; then
  run_tests "Python: MCP server"           pytest tests/test_mcp_server.py
fi
pause

# ═══════════════════════════════════════════════════════════════════
# ACT 7 — Hooks & CI
# ═══════════════════════════════════════════════════════════════════
act_header "Hooks & CI" \
  "Pre-tool • pre-commit • hook formats • CI init"

if [[ "$RUN_NODE" == true ]]; then
  run_tests "Node: hook formats"           vitest tests/hook-formats.test.ts
  run_tests "Node: post-tool hook"         vitest tests/posttool.test.ts
  run_tests "Node: CI init"               vitest tests/ci-init.test.ts
fi
if [[ "$RUN_PYTHON" == true ]]; then
  run_tests "Python: hooks"                pytest tests/test_hook.py
  run_tests "Python: CI"                   pytest tests/test_ci.py
fi
pause

# ═══════════════════════════════════════════════════════════════════
# ACT 8 — Notifications & Reports
# ═══════════════════════════════════════════════════════════════════
act_header "Notifications & Reports" \
  "Slack/Discord webhooks • HTML reports • formatters"

if [[ "$RUN_NODE" == true ]]; then
  run_tests "Node: notifications"          vitest tests/notifications.test.ts
  run_tests "Node: notify"                 vitest tests/notify.test.ts
  run_tests "Node: report"                 vitest tests/report.test.ts
  run_tests "Node: formatter"             vitest tests/formatter.test.ts
fi
if [[ "$RUN_PYTHON" == true ]]; then
  run_tests "Python: notifications"        pytest tests/test_notifications.py
  run_tests "Python: notify"               pytest tests/test_notify.py
fi
pause

# ═══════════════════════════════════════════════════════════════════
# ACT 9 — Backend & API
# ═══════════════════════════════════════════════════════════════════
act_header "Backend & API" \
  "Remote scanning • API scoping • utilities"

if [[ "$RUN_NODE" == true ]]; then
  run_tests "Node: backend API"            vitest tests/backend-api.test.ts
  run_tests "Node: API scope"              vitest tests/api-scope.test.ts
  run_tests "Node: API utilities"          vitest tests/api-utils.test.ts
  run_tests "Node: baseline"               vitest tests/baseline.test.ts
fi
if [[ "$RUN_PYTHON" == true ]]; then
  run_tests "Python: API scope"            pytest tests/test_api_scope.py
  run_tests "Python: handle 403"           pytest tests/test_handle_403.py
fi
pause

# ═══════════════════════════════════════════════════════════════════
# ACT 10 — End-to-End & Misc
# ═══════════════════════════════════════════════════════════════════
act_header "End-to-End & Utilities" \
  "Full CLI e2e • git utils • binary manager"

if [[ "$RUN_NODE" == true ]]; then
  run_tests "Node: e2e CLI"                vitest tests/e2e-cli.test.ts
  run_tests "Node: git utilities"          vitest tests/git-utils.test.ts
  run_tests "Node: binary manager"         vitest tests/binary-manager.test.ts
fi
pause

# ═══════════════════════════════════════════════════════════════════
# FINALE — Summary
# ═══════════════════════════════════════════════════════════════════
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))
TOTAL_TESTS=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))

if [[ "$JSON_OUTPUT" == true ]]; then
  # Machine-readable JSON output
  echo "{"
  echo "  \"total\": $TOTAL_TESTS,"
  echo "  \"passed\": $TOTAL_PASS,"
  echo "  \"failed\": $TOTAL_FAIL,"
  echo "  \"skipped\": $TOTAL_SKIP,"
  echo "  \"duration_seconds\": $TOTAL_TIME,"
  echo "  \"node\": $RUN_NODE,"
  echo "  \"python\": $RUN_PYTHON,"
  echo "  \"acts\": ["
  first=true
  for result in "${ACT_RESULTS[@]}"; do
    IFS='|' read -r name pass fail skip time <<< "$result"
    if [[ "$first" != true ]]; then echo ","; fi
    printf '    {"name": "%s", "passed": %d, "failed": %d, "skipped": %d, "time": "%s"}' \
      "$name" "$pass" "$fail" "$skip" "$time"
    first=false
  done
  echo ""
  echo "  ]"
  echo "}"
  exit $(( TOTAL_FAIL > 0 ? 1 : 0 ))
fi

banner "SHOWCASE COMPLETE"

# Results table
printf "  ${BOLD}%-44s %6s %6s %7s %7s${RESET}\n" "Feature Area" "Pass" "Fail" "Skip" "Time"
printf "  %-44s %6s %6s %7s %7s\n" \
  "────────────────────────────────────────────" "──────" "──────" "───────" "───────"

for result in "${ACT_RESULTS[@]}"; do
  IFS='|' read -r name pass fail skip time <<< "$result"
  fail_color="$RESET"
  if [[ "$fail" -gt 0 ]]; then fail_color="$RED"; fi
  printf "  %-44s ${GREEN}%6d${RESET} ${fail_color}%6d${RESET} ${DIM}%7d${RESET} ${DIM}%7s${RESET}\n" \
    "$name" "$pass" "$fail" "$skip" "$time"
done

echo ""
printf "  %-44s %6s %6s %7s %7s\n" \
  "────────────────────────────────────────────" "──────" "──────" "───────" "───────"

# Totals
if [[ "$TOTAL_FAIL" -gt 0 ]]; then
  printf "  ${BOLD}%-44s ${GREEN}%6d${RESET} ${RED}${BOLD}%6d${RESET} ${DIM}%7d${RESET}   ${DIM}%ds${RESET}\n" \
    "TOTAL" "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_SKIP" "$TOTAL_TIME"
else
  printf "  ${BOLD}%-44s ${GREEN}%6d${RESET} %6d ${DIM}%7d${RESET}   ${DIM}%ds${RESET}\n" \
    "TOTAL" "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_SKIP" "$TOTAL_TIME"
fi

echo ""

# Final verdict
if [[ "$TOTAL_FAIL" -eq 0 ]]; then
  printf "  ${GREEN}${BOLD}▸ ALL %d TESTS PASSED${RESET}" "$TOTAL_PASS"
  printf " ${DIM}across Node.js + Python in %ds${RESET}\n" "$TOTAL_TIME"
  echo ""
  printf "  ${DIM}Rafter CLI — security tooling that works.${RESET}\n"
else
  printf "  ${RED}${BOLD}▸ %d FAILURES${RESET}" "$TOTAL_FAIL"
  printf " ${DIM}(%d passed, %d skipped)${RESET}\n" "$TOTAL_PASS" "$TOTAL_SKIP"
fi
echo ""

exit $(( TOTAL_FAIL > 0 ? 1 : 0 ))
