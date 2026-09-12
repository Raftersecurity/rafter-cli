"""sable-lbyp (from rf-ss67) -- the hook sees through rafter's own binary.

``rafter agent exec <operand>`` RUNS its operand. Before this the sanitizer
treated rafter as an unrecognised evaluator, so a quoted multi-word operand
was prose and ``rafter agent exec --force "rm -rf /tmp/x"`` classified ``low``
while exec ran a HIGH-tier command. The level assertions live in the shared
battery (rf-6pqx-newline-heredoc-battery.json, "lbyp:" rows) so both runtimes
prove them; this file pins the SHAPE of the sanitized text and the one
exemption. Mirrors node/tests/risk-rules-rafter-exec.test.ts.
"""
from __future__ import annotations

import pytest

from rafter_cli.core.risk_rules import (
    assess_command_risk,
    sanitize_command_for_matching,
)


def test_inlines_the_quoted_operand():
    cmd = 'rafter agent exec --force "rm -rf /tmp/x"'
    assert "rm -rf /tmp/x" in sanitize_command_for_matching(cmd)
    assert assess_command_risk(cmd) == "high"


@pytest.mark.parametrize("cmd", [
    '/usr/local/bin/rafter agent exec "chmod 777 /etc/passwd"',
    'npx @rafter-security/cli agent exec "chmod 777 /etc/passwd"',
    'bunx rafter agent exec "chmod 777 /etc/passwd"',
    'sudo -E rafter agent exec "chmod 777 /etc/passwd"',
    'env RAFTER_X=1 rafter-cli agent exec "chmod 777 /etc/passwd"',
])
def test_resolves_binary_by_basename_runner_and_wrapper(cmd):
    assert "chmod 777 /etc/passwd" in sanitize_command_for_matching(cmd)
    assert assess_command_risk(cmd) == "high"


def test_dry_run_operand_stays_data():
    cmd = 'rafter agent exec --dry-run "rm -rf /"'
    assert "rm -rf /" not in sanitize_command_for_matching(cmd)
    assert assess_command_risk(cmd) == "low"


def test_quoted_dry_run_is_not_the_flag():
    assert assess_command_risk('rafter agent exec "--dry-run" "rm -rf /"') == "critical"


def test_only_agent_exec_is_code_carrying():
    assert assess_command_risk('rafter secrets "my project/src"') == "low"
    assert assess_command_risk('rafter agent config get "agent risk level"') == "low"
    assert assess_command_risk("echo 'rafter agent exec \"rm -rf /\"'") == "low"


@pytest.mark.parametrize("cmd", [
    'script -q -c "rafter agent exec \'echo hi\'" /dev/null',
    'unbuffer rafter agent exec "echo hi"',
    "expect -c 'spawn rafter agent exec \"echo hi\"; send \"yes\\r\"'",
    "python3 -c \"import pty; pty.spawn(['rafter','agent','exec','echo hi'])\"",
])
def test_pty_wrapper_around_rafter_exec_is_high(cmd):
    assert assess_command_risk(cmd) == "high"


def test_pty_wrapper_without_rafter_is_not_the_signal():
    assert assess_command_risk('script -q -c "ls -la" /dev/null') == "low"
