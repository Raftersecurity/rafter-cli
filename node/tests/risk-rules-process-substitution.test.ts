/**
 * Process substitution and trap are code-bearing positions (rf-zvll A1/A2).
 *
 * DELIBERATELY INDEPENDENT OF #249 — nothing here touches `<<<` or relies on the
 * here-string work, so if that change is reworked this file rebases onto main
 * untouched. Verified by cherry-picking A1+A2 onto main alone: all rows pass
 * while `bash <<< "…"` is still `high`, i.e. #249 genuinely absent.
 *
 * Both found by the rf-zvll generated corpus with a real-shell oracle, and they
 * are DIFFERENT KINDS of gap:
 *   A1 PARSING — `<(cmd)` was never formed. The tokenizer emitted op `<`, which
 *      is in REDIRECT_OPS, so `(cmd` became a redirect TARGET and survived while
 *      the rest was redacted as the host's data operands. Two wrong decisions
 *      conspiring; fixing either alone leaves the bypass.
 *   A2 TABLE — `trap 'cmd' EXIT` is an ordinary quoted operand, redacted as
 *      prose exactly as `echo "…"` correctly is.
 */
import { describe, it, expect } from "vitest";
import { assessCommandRisk, sanitizeCommandForMatching } from "../src/core/risk-rules.js";

describe("process substitution content is code (rf-zvll A1)", () => {
  for (const cmd of [
    "ack <(rm -rf /)",
    "ack >(rm -rf /)",
    "grep -q x <(rm -rf /)",
    "diff <(cat a) <(rm -rf /)",
    "tee >(rm -rf /)",
  ]) {
    it(`classifies the payload inside: ${cmd}`, () => {
      expect(assessCommandRisk(cmd), sanitizeCommandForMatching(cmd)).toBe("critical");
    });
  }

  for (const cmd of ["diff <(ls) <(ls -a)", "cat <(echo hi)", "tee >(wc -l)"]) {
    it(`does not over-block benign use: ${cmd}`, () => {
      // Without these the rows above would pass with a blanket rule that is
      // unusable in practice.
      expect(assessCommandRisk(cmd), sanitizeCommandForMatching(cmd)).toBe("low");
    });
  }

  it("leaves a plain redirect alone — reading a file is not executing it", () => {
    expect(assessCommandRisk("cat < /tmp/some-file")).toBe("low");
  });

  it("fixes BOTH halves — the whole payload reaches the matcher", () => {
    // The head survived as a redirect target while the tail was redacted as a
    // text-exec operand. Assert the whole string, or a future change could fix
    // one half and look done.
    expect(sanitizeCommandForMatching("ack <(rm -rf /)")).toContain("rm -rf /");
  });
});

describe("trap registers a command, so its operand is code (rf-zvll A2)", () => {
  for (const cmd of ["trap 'rm -rf /' EXIT; true", "trap 'rm -rf /' INT TERM", 'trap "rm -rf /" EXIT']) {
    it(`classifies: ${cmd}`, () => {
      expect(assessCommandRisk(cmd), sanitizeCommandForMatching(cmd)).toBe("critical");
    });
  }

  it("does not over-block a benign trap", () => {
    expect(assessCommandRisk("trap 'echo done' EXIT")).toBe("low");
  });

  it("a trap reset is not a command", () => {
    expect(assessCommandRisk("trap - EXIT")).toBe("low");
  });

  it("CONTROL — an echo operand is STILL prose", () => {
    // Load-bearing: making trap code-carrying must not make every quoted
    // operand code. echo prints.
    expect(assessCommandRisk('echo "rm -rf /"')).toBe("low");
  });
});
