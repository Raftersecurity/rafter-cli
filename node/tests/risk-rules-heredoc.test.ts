import { describe, it, expect } from "vitest";
import {
  assessCommandRisk,
  sanitizeCommandForMatching,
} from "../src/core/risk-rules.js";

/**
 * sable-5ogx / issue #230 — heredoc bodies were scanned as executable commands.
 *
 * `cat > README.md <<'EOF' … EOF` WRITES its body to a file. It does not run
 * it. With no heredoc handling in the tokenizer the body arrived at the matcher
 * as bare words, so a documentation line quoting a dangerous command scored
 * identically to running it: `rm -rf /` inside prose classified CRITICAL, the
 * tier no policy, mode or deny-list can override. An external reporter hit this
 * writing documentation about Rafter itself.
 *
 * This is also the half that has to land WITH rf-6pqx: that fix splits
 * statements on newlines, which promotes every heredoc body line to its own
 * statement and makes this strictly worse. Heredoc consumption therefore lives
 * in the tokenizer, ahead of any statement split.
 *
 * The other direction is pinned just as hard: a heredoc a shell actually
 * consumes is still code, and still hard-blocks.
 */

describe("heredoc bodies are data (sable-5ogx, issue #230)", () => {
  it("does not block writing documentation that quotes a dangerous command", () => {
    // The reporter's case, verbatim in shape.
    const cmd = "cat > README.md <<'EOF'\nNever run rm -rf / on prod.\nEOF";
    expect(assessCommandRisk(cmd)).toBe("low");
  });

  it("treats an unquoted delimiter the same as a quoted one", () => {
    // <<'EOF' and <<EOF differ in expansion, not in where the body ends.
    expect(assessCommandRisk("cat > a.md <<EOF\nrm -rf /\nEOF")).toBe("low");
    expect(assessCommandRisk("cat > a.md <<'EOF'\nrm -rf /\nEOF")).toBe("low");
    expect(assessCommandRisk('cat > a.md <<"EOF"\nrm -rf /\nEOF')).toBe("low");
  });

  it("honors <<- , which strips leading tabs from the terminator", () => {
    expect(assessCommandRisk("cat > a.md <<-EOF\n\trm -rf /\n\tEOF")).toBe("low");
  });

  it("handles a delimiter that is not EOF", () => {
    expect(assessCommandRisk("tee notes.md <<'DOC'\nrm -rf /\nDOC")).toBe("low");
  });

  it("queues several heredocs on one line, in order", () => {
    expect(assessCommandRisk("cat <<A <<B\nrm -rf /\nA\nrm -rf /\nB")).toBe("low");
  });

  it("treats an unterminated heredoc as data to end of input", () => {
    // Fail-safe direction: the alternative is scanning documentation as
    // commands, which is the bug this exists to fix.
    expect(assessCommandRisk("cat > a.md <<'EOF'\nrm -rf /")).toBe("low");
  });

  it("still classifies a real command AFTER the terminator", () => {
    // The body ends at the delimiter. Everything past it is live again — a
    // heredoc must not become a way to hide the next statement.
    expect(
      assessCommandRisk("cat > a.md <<'EOF'\nsome docs\nEOF\nrm -rf /")
    ).toBe("critical");
  });

  it("redacts the body rather than deleting the command around it", () => {
    const out = sanitizeCommandForMatching(
      "cat > a.md <<'EOF'\nrm -rf /\nEOF"
    );
    expect(out).toContain("cat");
    expect(out).not.toContain("rm -rf /");
  });
});

describe("heredoc bodies a shell consumes are still code", () => {
  it("hard-blocks a heredoc fed straight to a shell", () => {
    expect(assessCommandRisk("bash <<EOF\nrm -rf /\nEOF")).toBe("critical");
    expect(assessCommandRisk("sh <<'EOF'\nrm -rf /\nEOF")).toBe("critical");
  });

  it("hard-blocks a heredoc fed to an eval-style exec", () => {
    expect(assessCommandRisk("ssh host <<EOF\nrm -rf /\nEOF")).toBe("critical");
  });

  it("hard-blocks a heredoc piped into a shell", () => {
    // The body is data to `cat`, but `cat`'s output is the script. Splitting on
    // the pipe puts the body and the shell in different segments, so the
    // segment has to be asked what the NEXT one does with its output.
    expect(assessCommandRisk("cat <<EOF | bash\nrm -rf /\nEOF")).toBe("critical");
    expect(assessCommandRisk("cat <<EOF | sudo bash\nrm -rf /\nEOF")).toBe(
      "critical"
    );
  });

  it("hard-blocks a heredoc captured into a -c script", () => {
    expect(
      assessCommandRisk('bash -c "$(cat <<EOF\nrm -rf /\nEOF\n)"')
    ).toBe("critical");
  });
});

/**
 * sable-c6an — found while building the above, pre-existing on main, fixed here
 * because it is the same bug in a different spelling: the sanitizer looked at
 * one form of a thing that has several equivalent forms.
 *
 * `bash -c "$(…)"` put the payload in the piece's `substs`, leaving `text`
 * empty — so the script argument sanitized to nothing and the hard block, the
 * property documented as impossible to opt out of, was two tokens away.
 */
describe("a script argument is code however it is spelled (sable-c6an)", () => {
  it("hard-blocks a command substitution used as the script", () => {
    expect(assessCommandRisk('bash -c "$(echo rm -rf /)"')).toBe("critical");
    expect(assessCommandRisk("sh -c \"`echo rm -rf /`\"")).toBe("critical");
  });

  it("hard-blocks a quoted operand whose output becomes the script", () => {
    expect(assessCommandRisk("bash -c \"$(printf %s 'rm -rf /')\"")).toBe(
      "critical"
    );
  });

  it("hard-blocks text piped into a shell", () => {
    // `echo` operands are data when the output is printed, and the script when
    // the output is executed. Same rule, asked of the pipeline.
    expect(assessCommandRisk('echo "rm -rf /" | bash')).toBe("critical");
  });

  it("leaves an ordinary text command alone", () => {
    // The narrowing above must not spill onto output nobody executes.
    expect(assessCommandRisk('echo "never run rm -rf / on prod"')).toBe("low");
    expect(assessCommandRisk('grep -r "rm -rf /" /var/log')).toBe("low");
    expect(assessCommandRisk("echo hello | grep h")).toBe("low");
    expect(
      assessCommandRisk("git commit -m \"don't run rm -rf / here\"")
    ).toBe("low");
  });

  it("leaves a script that merely prints alone", () => {
    // The distinction the whole rule turns on: `bash -c "echo 'rm -rf /'"` runs
    // echo, and echo prints. Only its OUTPUT being executed makes the operand
    // code. An existing test asserted this before the change and was right.
    expect(assessCommandRisk("bash -c \"echo 'rm -rf /'\"")).toBe("low");
  });
});

describe("a here-string is not a heredoc", () => {
  it("does not swallow the rest of the input after <<<", () => {
    // `<<<` shares a prefix with `<<`. Read as a heredoc introducer it would
    // take `"hello"` for a delimiter, find no terminator line, and redact
    // everything to end of input — over-blocking's mirror image, silently
    // hiding whatever came next.
    //
    // The NEWLINE is what makes this test able to fail: heredoc bodies are only
    // consumed at one, so a single-line `cat <<< "hello" ; rm -rf /` passes
    // even with `<<<` mis-read, and asserts nothing.
    const cmd = 'cat <<< "hello" > a.txt\nrm -rf /';
    expect(sanitizeCommandForMatching(cmd)).toContain("rm -rf /");
    expect(assessCommandRisk(cmd)).toBe("critical");
  });
});
