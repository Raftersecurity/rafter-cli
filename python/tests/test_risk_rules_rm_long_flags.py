"""Regression tests for the `rm` long-flag evasion (sable-urvj).

The risk rules spell rm's flags the short way (`-rf`, `-r -f`, `-fr`). GNU rm
accepts long spellings meaning exactly the same thing, and those evaded every
rule: `rm --recursive --force /` assessed LOW and was silently allowed.

The inversion is what makes this severe: modern coreutils REFUSES `rm -rf /`
unless `--no-preserve-root` is also given, so the only interactive form that
actually wipes root was precisely the form the hard-block missed.

Mirrors node/tests/risk-rules-rm-long-flags.test.ts.
"""
from rafter_cli.core.risk_rules import assess_command_risk, normalize_rm_flags


class TestLongFormFlagsReachTheHardBlock:
    def test_blocks_fully_long_form_rm_on_root(self):
        assert assess_command_risk("rm --recursive --force /") == "critical"

    def test_blocks_long_form_flags_in_either_order(self):
        assert assess_command_risk("rm --force --recursive /home") == "critical"
        assert assess_command_risk("rm --recursive --force /etc") == "critical"

    def test_blocks_mixed_short_and_long_spellings(self):
        assert assess_command_risk("rm -r --force /etc") == "critical"
        assert assess_command_risk("rm --recursive -f /usr") == "critical"

    def test_blocks_long_flags_in_flag_equals_value_form(self):
        # GNU rm's long options take no argument, so this is in truth an error;
        # reading it as recursive is the conservative direction for a blocker.
        assert assess_command_risk("rm --recursive=yes -f /") == "critical"
        assert assess_command_risk("rm --recursive=yes --force=yes /boot") == "critical"

    def test_blocks_the_form_that_actually_wipes_root(self):
        # `rm -rf /` alone is refused by coreutils; this is the one that isn't.
        assert assess_command_risk("rm --recursive --force --no-preserve-root /") == "critical"
        assert assess_command_risk("rm -rf --no-preserve-root /") == "critical"

    def test_blocks_long_form_rm_behind_sudo_and_through_chains(self):
        assert assess_command_risk("sudo rm --recursive --force /usr") == "critical"
        assert assess_command_risk("echo ok && rm --recursive --force /boot") == "critical"
        assert assess_command_risk("cd /tmp; rm --force --recursive /lib") == "critical"

    def test_long_form_rm_on_a_non_critical_path_is_high(self):
        assert assess_command_risk("rm --recursive --force /tmp/build") == "high"
        assert assess_command_risk("rm --recursive --force ./node_modules") == "high"


class TestNoNewFalsePositives:
    def test_leaves_rm_without_recursive_or_force_alone(self):
        assert assess_command_risk("rm -i -v notes.txt") == "low"
        assert assess_command_risk("rm notes.txt") == "low"
        assert assess_command_risk("rm --interactive notes.txt") == "low"

    def test_does_not_treat_an_operand_after_dashdash_as_a_flag(self):
        assert assess_command_risk("rm -- --weird-file") == "low"

    def test_flag_run_does_not_swallow_a_chained_command(self):
        # A naive `.*` rule spans chain operators; the run must stop at them.
        assert assess_command_risk("rm -r dir && cp -r a b") == "high"
        assert assess_command_risk("rm -i f; ls -la") == "low"

    def test_force_flag_mention_inside_prose_is_still_data(self):
        assert assess_command_risk('git commit -m "never rm --recursive --force /"') == "low"
        assert assess_command_risk('echo "rm --recursive --force /" > notes.txt') == "low"

    def test_does_not_rewrite_commands_that_merely_contain_the_letters_rm(self):
        assert assess_command_risk("npm run format") == "low"
        assert assess_command_risk("chmod --recursive 755 dir") == "medium"


class TestNormalizeRmFlags:
    def test_collapses_a_flag_run_to_a_canonical_short_cluster(self):
        assert normalize_rm_flags("rm --recursive --force /") == "rm -rf /"
        assert normalize_rm_flags("rm -r --force --no-preserve-root /") == "rm -rf /"
        assert normalize_rm_flags("rm --recursive /tmp") == "rm -r /tmp"

    def test_returns_the_input_untouched_when_nothing_to_canonicalize(self):
        assert normalize_rm_flags("rm -i -v notes.txt") == "rm -i -v notes.txt"
        assert normalize_rm_flags("ls -la") == "ls -la"

    def test_normalizes_every_rm_in_a_chain(self):
        assert normalize_rm_flags("rm --recursive a && rm --force b") == "rm -r a && rm -f b"
