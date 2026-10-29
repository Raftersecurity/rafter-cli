"""Process substitution and trap are code-bearing positions (rf-zvll A1/A2).

DELIBERATELY INDEPENDENT OF #249. Nothing here touches `<<<` or relies on the
here-string work, so if that change is reworked this file rebases onto main
untouched and keeps asserting what it asserts.

Both were found by the rf-zvll generated corpus with a real-shell oracle, not by
inspection, and they are DIFFERENT KINDS of gap:

  A1 PARSING.  `<(cmd)` was never formed as a construct. The tokenizer emitted
     op `<`, which is in REDIRECT_OPS, so `(cmd` became a redirect TARGET and was
     left untouched -- while the remaining words were redacted as the host's data
     operands. Two independent wrong decisions conspiring: `ack <(rm -rf /)`
     sanitized to `ack <(rm    `, harmless head preserved, dangerous tail deleted.
     Fixing either half alone leaves the bypass.

  A2 TABLE.    `trap 'cmd' EXIT` is an ordinary quoted operand, redacted as prose
     exactly as `echo "..."` correctly is, because trap was not code-carrying.

The distinction matters beyond these two: a fix that only added trap to the exec
table would have looked complete and missed process substitution entirely.
"""
from __future__ import annotations

import pytest

from rafter_cli.core.risk_rules import assess_command_risk, sanitize_command_for_matching


class TestProcessSubstitutionIsCode:
    @pytest.mark.parametrize("cmd", [
        "ack <(rm -rf /)",
        "ack >(rm -rf /)",
        "grep -q x <(rm -rf /)",
        "diff <(cat a) <(rm -rf /)",
        "tee >(rm -rf /)",
    ])
    def test_payload_inside_process_substitution_is_classified(self, cmd):
        assert assess_command_risk(cmd) == "critical", sanitize_command_for_matching(cmd)

    @pytest.mark.parametrize("cmd", ["diff <(ls) <(ls -a)", "cat <(echo hi)", "tee >(wc -l)"])
    def test_benign_process_substitution_is_not_over_blocked(self, cmd):
        # The fix must not make every `<(...)` dangerous; without this the rows
        # above would pass with a blanket rule that is unusable in practice.
        assert assess_command_risk(cmd) == "low", sanitize_command_for_matching(cmd)

    def test_a_plain_redirect_is_untouched(self):
        # `<` without `(` must keep behaving as a redirect: the operand is a
        # PATH, not code, and reading a file is not executing it.
        assert assess_command_risk("cat < /tmp/some-file") == "low"

    def test_both_halves_of_the_bug_are_fixed(self):
        # The head survived as a redirect target while the tail was redacted as
        # a text-exec operand. Assert the WHOLE payload reaches the matcher, or
        # a future change could fix one half and look done.
        assert "rm -rf /" in sanitize_command_for_matching("ack <(rm -rf /)")


class TestTrapIsCodeCarrying:
    @pytest.mark.parametrize("cmd", [
        "trap 'rm -rf /' EXIT; true",
        "trap 'rm -rf /' INT TERM",
        'trap "rm -rf /" EXIT',
    ])
    def test_trap_payload_is_classified(self, cmd):
        assert assess_command_risk(cmd) == "critical", sanitize_command_for_matching(cmd)

    def test_benign_trap_is_not_over_blocked(self):
        assert assess_command_risk("trap 'echo done' EXIT") == "low"

    def test_trap_reset_is_not_a_command(self):
        assert assess_command_risk("trap - EXIT") == "low"

    def test_CONTROL_echo_operand_is_still_prose(self):
        # The load-bearing control: making trap code-carrying must NOT make every
        # quoted operand code. `echo` prints, and there is a long-standing test
        # elsewhere asserting exactly that -- this keeps the two honest together.
        assert assess_command_risk('echo "rm -rf /"') == "low"
