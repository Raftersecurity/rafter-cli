"""A shell fed its program from a channel requires approval (rf-zvll B2).

Independent of the here-string and process-substitution work: nothing here
relies on `<<<` parsing or `<(...)`, so this file rebases onto main alone.

THE RULE IS POSTURE, NOT ANALYSIS. `cat f | sh`, `base64 -d | sh` and
`bash < f` all EXECUTE their payload -- the sandboxed oracle watched them do it
-- and the classifier cannot read any of them. No better parsing recovers the
payload, so the only sound answer is to require approval.

THE EXCLUSION IS FREQUENCY, NOT RISK, and that is stated rather than dressed up:
`bash deploy.sh` is equally unreadable and stays silent because it is the
overwhelmingly common legitimate form. Measured over 13,613 intercepted
commands, the stream forms are 0.022% of traffic in 2 of 665 repos, while
`curl|wget` into a shell -- already gated -- is 100 events. One machine; the
limit and what would overturn it are on rf-zvll.
"""
from __future__ import annotations

import pytest

from rafter_cli.core.risk_rules import assess_command_risk


class TestShellFedFromAChannel:
    @pytest.mark.parametrize("cmd", [
        "cat payload.txt | sh",
        "cat payload.txt | bash",
        "echo cm0K | base64 -d | bash",
        "echo 726d | xxd -r -p | sh",
        "bash < payload.txt",
        "sh < /tmp/script",
        "cat f | sudo bash",
        "cat f | env FOO=1 bash",
        "tac f | zsh",
    ])
    def test_requires_approval(self, cmd):
        assert assess_command_risk(cmd) == "high", cmd


class TestWhatMustStaySilent:
    @pytest.mark.parametrize("cmd", [
        "bash deploy.sh",          # a path ARGUMENT -- the deliberate exclusion
        "sh -c 'echo hi'",         # program is inline and readable
        "echo hi | grep x",        # not a shell on the receiving end
        "cat a.txt | wc -l",
        "git push",
        "python3 script.py",
    ])
    def test_not_elevated(self, cmd):
        assert assess_command_risk(cmd) == "low", cmd


class TestCriticalIsNotSoftened:
    @pytest.mark.parametrize("cmd", ["echo 'rm -rf /' | sh", "echo 'rm -rf /' | bash"])
    def test_readable_dangerous_payload_keeps_its_hard_block(self, cmd):
        # B2 is checked AFTER the critical patterns precisely so a payload we CAN
        # read and that matches stays a hard block rather than being softened to
        # an approval prompt. Without this ordering B2 would be a downgrade.
        assert assess_command_risk(cmd) == "critical", cmd

    def test_a_bare_critical_command_is_unaffected(self):
        assert assess_command_risk("rm -rf /") == "critical"
