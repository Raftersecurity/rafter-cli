"""Regression tests for the rm terminator gap (sable-5adm).

The critical rm rules terminated the path on whitespace or end-of-string. A
shell operator needs no whitespace before it, so appending one character dropped
an UNCONDITIONAL hard-block to "high" — a tier policy, mode, and deny-list can
all opt out of — while the command ran exactly the same.

Every command here is valid, executable shell. ``rm -rf /;`` does what
``rm -rf /`` does.

These fail on the pre-fix detector: each one assessed "high" before.

Mirrors node/tests/risk-rules-terminator-gap.test.ts.
"""
import re

import pytest

from rafter_cli.core.risk_rules import (
    CRITICAL_PATTERNS,
    DEFAULT_BLOCKED_PATTERNS,
    assess_command_risk,
)

TERMINATORS = [
    ("semicolon", ";"),
    ("semicolon + command", "; echo done"),
    ("semicolon, no space", ";ls"),
    ("and-and", "&& ls"),
    ("and-and, no space", "&&ls"),
    ("or-or", "|| ls"),
    ("pipe", "|cat"),
    ("background", "&"),
    ("subshell close", ")"),
    ("redirect out", ">f"),
    ("redirect out with path", ">/tmp/x"),
    ("redirect append", ">>log"),
    ("redirect in", "<f"),
]


@pytest.mark.parametrize("label,suffix", TERMINATORS)
def test_root_stays_critical_through_every_operator(label, suffix):
    assert assess_command_risk(f"rm -rf /{suffix}") == "critical"


@pytest.mark.parametrize("label,suffix", TERMINATORS)
def test_critical_dir_stays_critical_through_every_operator(label, suffix):
    assert assess_command_risk(f"rm -rf /etc{suffix}") == "critical"


@pytest.mark.parametrize(
    "directory",
    ["home", "usr", "boot", "root", "sys", "proc", "lib", "bin", "sbin", "opt"],
)
def test_all_critical_dirs_covered(directory):
    assert assess_command_risk(f"rm -rf /{directory};") == "critical"
    assert assess_command_risk(f"rm -rf /{directory}|cat") == "critical"


class TestFlagOrderAndWrappers:
    def test_reversed_and_split_flags(self):
        assert assess_command_risk("rm -fr /;") == "critical"
        assert assess_command_risk("rm -r -f /;") == "critical"
        assert assess_command_risk("rm -f -r /etc;") == "critical"

    def test_sudo_and_chained_position(self):
        assert assess_command_risk("sudo rm -rf /;") == "critical"
        assert assess_command_risk("echo ok && rm -rf /boot;") == "critical"
        assert assess_command_risk("cd /tmp; rm -rf /usr|cat") == "critical"

    def test_subshell_close(self):
        assert assess_command_risk("(rm -rf /)") == "critical"


class TestNoNewFalsePositives:
    def test_does_not_promote_a_non_critical_path(self):
        assert assess_command_risk("rm -rf /tmp/build;") == "high"
        assert assess_command_risk("rm -rf ./node_modules && npm i") == "high"
        assert assess_command_risk("rm -rf build|tee log") == "high"

    def test_longer_path_starting_with_a_critical_dir_name(self):
        # /etcetera is not /etc — the terminator must still be required.
        assert assess_command_risk("rm -rf /etcetera;") == "high"
        assert assess_command_risk("rm -rf /libraries;") == "high"
        assert assess_command_risk("rm -rf /opts;") == "high"

    def test_non_rm_commands_are_untouched(self):
        assert assess_command_risk("ls /;") == "low"
        assert assess_command_risk("cat /etc/hostname;") == "low"
        assert assess_command_risk("git status && ls /") == "low"

    def test_quoted_mention_is_still_data(self):
        assert assess_command_risk('git commit -m "never rm -rf /; really"') == "low"
        assert assess_command_risk('echo "rm -rf /;" > notes.txt') == "low"

    def test_bare_forms_still_critical(self):
        assert assess_command_risk("rm -rf /") == "critical"
        assert assess_command_risk("rm -rf / ") == "critical"
        assert assess_command_risk("rm -rf /etc") == "critical"


class TestDefaultDenyListInheritsTheFix:
    """CRITICAL_PATTERNS is DEFAULT_BLOCKED_PATTERNS byte for byte, so a
    terminator gap was a hard-block gap AND a default-deny gap."""

    def test_deny_list_identical_to_critical_set(self):
        assert DEFAULT_BLOCKED_PATTERNS == list(CRITICAL_PATTERNS)

    def test_deny_list_matches_the_operator_suffixed_form(self):
        assert any(re.search(p, "rm -rf /;", re.IGNORECASE) for p in DEFAULT_BLOCKED_PATTERNS)
