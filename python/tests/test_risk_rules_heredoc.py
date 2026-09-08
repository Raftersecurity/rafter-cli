"""sable-5ogx / issue #230 — heredoc bodies were scanned as executable commands.

``cat > README.md <<'EOF' … EOF`` WRITES its body to a file. It does not run it.
With no heredoc handling in the tokenizer the body arrived at the matcher as
bare words, so a documentation line quoting a dangerous command scored
identically to running it: ``rm -rf /`` inside prose classified CRITICAL, the
tier no policy, mode or deny-list can override. An external reporter hit this
writing documentation about Rafter itself.

This is also the half that has to land WITH rf-6pqx: that fix splits statements
on newlines, which promotes every heredoc body line to its own statement and
makes this strictly worse. Heredoc consumption therefore lives in the tokenizer,
ahead of any statement split.

The other direction is pinned just as hard: a heredoc a shell actually consumes
is still code, and still hard-blocks.

Mirrors node/tests/risk-rules-heredoc.test.ts.
"""
from __future__ import annotations

from rafter_cli.core.risk_rules import (
    assess_command_risk,
    sanitize_command_for_matching,
)


class TestHeredocBodiesAreData:
    def test_documentation_that_quotes_a_dangerous_command_is_not_blocked(self):
        # The reporter's case, verbatim in shape.
        cmd = "cat > README.md <<'EOF'\nNever run rm -rf / on prod.\nEOF"
        assert assess_command_risk(cmd) == "low"

    def test_unquoted_delimiter_behaves_like_a_quoted_one(self):
        # <<'EOF' and <<EOF differ in expansion, not in where the body ends.
        assert assess_command_risk("cat > a.md <<EOF\nrm -rf /\nEOF") == "low"
        assert assess_command_risk("cat > a.md <<'EOF'\nrm -rf /\nEOF") == "low"
        assert assess_command_risk('cat > a.md <<"EOF"\nrm -rf /\nEOF') == "low"

    def test_dash_form_strips_leading_tabs_from_the_terminator(self):
        assert assess_command_risk("cat > a.md <<-EOF\n\trm -rf /\n\tEOF") == "low"

    def test_delimiter_need_not_be_eof(self):
        assert assess_command_risk("tee notes.md <<'DOC'\nrm -rf /\nDOC") == "low"

    def test_several_heredocs_on_one_line_queue_in_order(self):
        assert assess_command_risk("cat <<A <<B\nrm -rf /\nA\nrm -rf /\nB") == "low"

    def test_unterminated_heredoc_is_data_to_end_of_input(self):
        # Fail-safe direction: the alternative is scanning documentation as
        # commands, which is the bug this exists to fix.
        assert assess_command_risk("cat > a.md <<'EOF'\nrm -rf /") == "low"

    def test_a_real_command_after_the_terminator_still_classifies(self):
        # The body ends at the delimiter. Everything past it is live again — a
        # heredoc must not become a way to hide the next statement.
        cmd = "cat > a.md <<'EOF'\nsome docs\nEOF\nrm -rf /"
        assert assess_command_risk(cmd) == "critical"

    def test_the_body_is_redacted_not_the_command_around_it(self):
        out = sanitize_command_for_matching("cat > a.md <<'EOF'\nrm -rf /\nEOF")
        assert "cat" in out
        assert "rm -rf /" not in out


class TestHeredocBodiesAShellConsumes:
    def test_heredoc_fed_straight_to_a_shell_hard_blocks(self):
        assert assess_command_risk("bash <<EOF\nrm -rf /\nEOF") == "critical"
        assert assess_command_risk("sh <<'EOF'\nrm -rf /\nEOF") == "critical"

    def test_heredoc_fed_to_an_eval_style_exec_hard_blocks(self):
        assert assess_command_risk("ssh host <<EOF\nrm -rf /\nEOF") == "critical"

    def test_heredoc_piped_into_a_shell_hard_blocks(self):
        # The body is data to `cat`, but `cat`'s output is the script. Splitting
        # on the pipe puts the body and the shell in different segments, so the
        # segment has to be asked what the NEXT one does with its output.
        assert assess_command_risk("cat <<EOF | bash\nrm -rf /\nEOF") == "critical"
        assert (
            assess_command_risk("cat <<EOF | sudo bash\nrm -rf /\nEOF") == "critical"
        )

    def test_heredoc_captured_into_a_c_script_hard_blocks(self):
        cmd = 'bash -c "$(cat <<EOF\nrm -rf /\nEOF\n)"'
        assert assess_command_risk(cmd) == "critical"


class TestScriptArgumentIsCodeHoweverSpelled:
    """sable-c6an — found while building the above, pre-existing on main.

    Fixed here because it is the same bug in a different spelling: the sanitizer
    looked at one form of a thing that has several equivalent forms.
    ``bash -c "$(…)"`` put the payload in the piece's ``substs``, leaving
    ``text`` empty — so the script argument sanitized to nothing and the hard
    block, the property documented as impossible to opt out of, was two tokens
    away.
    """

    def test_a_command_substitution_used_as_the_script_hard_blocks(self):
        assert assess_command_risk('bash -c "$(echo rm -rf /)"') == "critical"
        assert assess_command_risk('sh -c "`echo rm -rf /`"') == "critical"

    def test_a_quoted_operand_whose_output_becomes_the_script_hard_blocks(self):
        assert assess_command_risk("bash -c \"$(printf %s 'rm -rf /')\"") == "critical"

    def test_text_piped_into_a_shell_hard_blocks(self):
        # `echo` operands are data when the output is printed, and the script
        # when the output is executed. Same rule, asked of the pipeline.
        assert assess_command_risk('echo "rm -rf /" | bash') == "critical"

    def test_an_ordinary_text_command_is_left_alone(self):
        # The narrowing above must not spill onto output nobody executes.
        assert assess_command_risk('echo "never run rm -rf / on prod"') == "low"
        assert assess_command_risk('grep -r "rm -rf /" /var/log') == "low"
        assert assess_command_risk("echo hello | grep h") == "low"
        assert assess_command_risk('git commit -m "do not run rm -rf / here"') == "low"

    def test_a_script_that_merely_prints_is_still_printing(self):
        # The distinction the whole rule turns on: `bash -c "echo 'rm -rf /'"`
        # runs echo, and echo prints. Only its OUTPUT being executed makes the
        # operand code.
        assert assess_command_risk("bash -c \"echo 'rm -rf /'\"") == "low"


class TestHereStringIsNotAHeredoc:
    def test_triple_lt_does_not_swallow_the_rest_of_the_input(self):
        # `<<<` shares a prefix with `<<`. Read as a heredoc introducer it would
        # take `"hello"` for a delimiter, find no terminator line, and redact
        # everything to end of input — over-blocking's mirror image, silently
        # hiding whatever came next.
        #
        # The NEWLINE is what makes this test able to fail: heredoc bodies are
        # only consumed at one, so a single-line `cat <<< "hello" ; rm -rf /`
        # passes even with `<<<` mis-read, and asserts nothing.
        cmd = 'cat <<< "hello" > a.txt\nrm -rf /'
        assert "rm -rf /" in sanitize_command_for_matching(cmd)
        assert assess_command_risk(cmd) == "critical"
