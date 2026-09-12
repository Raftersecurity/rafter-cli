import { describe, it, expect } from "vitest";
import {
  assessCommandRisk,
  sanitizeCommandForMatching,
} from "../src/core/risk-rules.js";

/**
 * sable-lbyp (from rf-ss67) — the hook sees through rafter's own binary.
 *
 * `rafter agent exec <operand>` RUNS its operand. Before this the sanitizer
 * treated rafter as an unrecognised evaluator, so a quoted multi-word operand
 * was prose and `rafter agent exec --force "rm -rf /tmp/x"` classified `low`
 * while exec ran a HIGH-tier command. The level assertions live in the shared
 * battery (rf-6pqx-newline-heredoc-battery.json, "lbyp:" rows) so both
 * runtimes prove them; this file pins the SHAPE of the sanitized text and the
 * one exemption.
 */
describe("rafter agent exec operand is a command (sable-lbyp)", () => {
  it("inlines the quoted operand so the patterns can see it", () => {
    const s = sanitizeCommandForMatching('rafter agent exec --force "rm -rf /tmp/x"');
    expect(s).toContain("rm -rf /tmp/x");
    expect(assessCommandRisk('rafter agent exec --force "rm -rf /tmp/x"')).toBe("high");
  });

  it("resolves the binary by basename, package runner and wrapper", () => {
    for (const cmd of [
      '/usr/local/bin/rafter agent exec "chmod 777 /etc/passwd"',
      'npx @rafter-security/cli agent exec "chmod 777 /etc/passwd"',
      'bunx rafter agent exec "chmod 777 /etc/passwd"',
      'sudo -E rafter agent exec "chmod 777 /etc/passwd"',
      'env RAFTER_X=1 rafter-cli agent exec "chmod 777 /etc/passwd"',
    ]) {
      expect(sanitizeCommandForMatching(cmd), cmd).toContain("chmod 777 /etc/passwd");
      expect(assessCommandRisk(cmd), cmd).toBe("high");
    }
  });

  it("--dry-run runs nothing, so its operand stays data", () => {
    const cmd = 'rafter agent exec --dry-run "rm -rf /"';
    expect(sanitizeCommandForMatching(cmd)).not.toContain("rm -rf /");
    expect(assessCommandRisk(cmd)).toBe("low");
  });

  it("a quoted --dry-run is not the flag", () => {
    // Quoting the flag would make exec treat it as the command; the hook must
    // not honour it as the exemption.
    expect(assessCommandRisk('rafter agent exec "--dry-run" "rm -rf /"')).toBe("critical");
  });

  it("only agent exec is code-carrying; other rafter operands stay prose", () => {
    expect(assessCommandRisk('rafter secrets "my project/src"')).toBe("low");
    expect(assessCommandRisk('rafter agent config get "agent risk level"')).toBe("low");
    expect(assessCommandRisk("echo 'rafter agent exec \"rm -rf /\"'")).toBe("low");
  });

  it("a pty wrapper around rafter agent exec is HIGH on its own", () => {
    for (const cmd of [
      'script -q -c "rafter agent exec \'echo hi\'" /dev/null',
      'unbuffer rafter agent exec "echo hi"',
      "expect -c 'spawn rafter agent exec \"echo hi\"; send \"yes\\r\"'",
      "python3 -c \"import pty; pty.spawn(['rafter','agent','exec','echo hi'])\"",
    ]) {
      expect(assessCommandRisk(cmd), cmd).toBe("high");
    }
    // The wrapper alone, without rafter, is not the signal.
    expect(assessCommandRisk('script -q -c "ls -la" /dev/null')).toBe("low");
  });

  it("unbuffer is a tail wrapper: the command after it resolves as the exec", () => {
    // Without the wrapper entry, `unbuffer` would be the exec and the operand
    // prose, so this would only reach HIGH through the pty pattern. The
    // operand must still be seen, so a critical one is CRITICAL.
    const cmd = 'unbuffer rafter agent exec "rm -rf /"';
    expect(sanitizeCommandForMatching(cmd)).toContain("rm -rf /");
    expect(assessCommandRisk(cmd)).toBe("critical");
  });
});
