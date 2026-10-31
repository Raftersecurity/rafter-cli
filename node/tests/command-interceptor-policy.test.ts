/**
 * Exhaustive tests for CommandInterceptor policy modes and override behavior.
 *
 * Covers: deny-list / approve-dangerous / allow-all modes, custom blocked/approval
 * patterns, pattern priority (blocked wins over approval), policy override of
 * defaults, and edge cases (empty patterns, invalid regex, no policy).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { CommandInterceptor } from "../src/core/command-interceptor.js";

// ---------------------------------------------------------------------------
// Helpers: stub loadWithPolicy to inject arbitrary policy configs
// ---------------------------------------------------------------------------

function stubPolicy(interceptor: CommandInterceptor, policy: {
  mode?: string;
  blockedPatterns?: string[];
  requireApproval?: string[];
} | null) {
  const cfg: any = {
    agent: policy ? { commandPolicy: {
      mode: policy.mode ?? "approve-dangerous",
      blockedPatterns: policy.blockedPatterns ?? [],
      requireApproval: policy.requireApproval ?? [],
    }} : undefined,
  };
  vi.spyOn((interceptor as any).config, "loadWithPolicy").mockReturnValue(cfg);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("CommandInterceptor — Policy modes", () => {
  let interceptor: CommandInterceptor;

  beforeEach(() => {
    interceptor = new CommandInterceptor();
  });

  // ── No policy (agent.commandPolicy undefined) ───────────────────────

  describe("No policy configured", () => {
    it("should hard-block critical destructive commands even with no policy", () => {
      stubPolicy(interceptor, null);
      const result = interceptor.evaluate("rm -rf /");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(false);
      expect(result.riskLevel).toBe("critical");
      expect(result.matchedPattern).toBeDefined();
    });

    it("should require approval for high-risk commands even with no policy", () => {
      stubPolicy(interceptor, null);
      const result = interceptor.evaluate("rm -rf node_modules");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
      expect(result.riskLevel).toBe("high");
    });

    it("should return low risk for safe command", () => {
      stubPolicy(interceptor, null);
      const result = interceptor.evaluate("echo hello");
      expect(result.allowed).toBe(true);
      expect(result.riskLevel).toBe("low");
    });
  });

  // ── deny-list mode ──────────────────────────────────────────────────

  describe("deny-list mode", () => {
    it("should block commands matching blockedPatterns", () => {
      stubPolicy(interceptor, {
        mode: "deny-list",
        blockedPatterns: ["dangerous-cmd"],
        requireApproval: [],
      });
      const result = interceptor.evaluate("dangerous-cmd --now");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(false);
      // A deny-list hit denies, but it does not *rewrite* the risk: this command
      // is assessed low, and saying "critical" would misreport it to the user.
      expect(result.riskLevel).toBe("low");
      expect(result.matchedPattern).toBe("dangerous-cmd");
    });

    it("should require approval for commands matching requireApproval", () => {
      stubPolicy(interceptor, {
        mode: "deny-list",
        blockedPatterns: [],
        requireApproval: ["risky-op"],
      });
      const result = interceptor.evaluate("risky-op --flag");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
      expect(result.matchedPattern).toBe("risky-op");
    });

    it("should allow commands not in any list, even if high risk", () => {
      stubPolicy(interceptor, {
        mode: "deny-list",
        blockedPatterns: [],
        requireApproval: [],
      });
      // rm -rf is high risk by assessment, but deny-list only blocks listed patterns
      const result = interceptor.evaluate("rm -rf /tmp/stuff");
      expect(result.allowed).toBe(true);
      expect(result.requiresApproval).toBe(false);
      expect(result.riskLevel).toBe("high");
    });

    it("should allow safe commands", () => {
      stubPolicy(interceptor, {
        mode: "deny-list",
        blockedPatterns: ["bad"],
        requireApproval: ["scary"],
      });
      const result = interceptor.evaluate("ls -la");
      expect(result.allowed).toBe(true);
      expect(result.riskLevel).toBe("low");
    });
  });

  // ── approve-dangerous mode ──────────────────────────────────────────

  describe("approve-dangerous mode", () => {
    it("should require approval for high-risk commands even without explicit patterns", () => {
      stubPolicy(interceptor, {
        mode: "approve-dangerous",
        blockedPatterns: [],
        requireApproval: [],
      });
      const result = interceptor.evaluate("rm -rf /tmp/stuff");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
      expect(result.riskLevel).toBe("high");
      expect(result.reason).toContain("High risk");
    });

    it("should hard-block critical-risk commands (never merely require approval)", () => {
      stubPolicy(interceptor, {
        mode: "approve-dangerous",
        blockedPatterns: [],
        requireApproval: [],
      });
      const result = interceptor.evaluate("mkfs.ext4 /dev/sda1");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(false);
      expect(result.riskLevel).toBe("critical");
    });

    it("should allow medium-risk commands without approval", () => {
      stubPolicy(interceptor, {
        mode: "approve-dangerous",
        blockedPatterns: [],
        requireApproval: [],
      });
      const result = interceptor.evaluate("sudo apt update");
      expect(result.allowed).toBe(true);
      expect(result.requiresApproval).toBe(false);
      expect(result.riskLevel).toBe("medium");
    });

    it("should allow low-risk commands (empty pattern lists block nothing)", () => {
      stubPolicy(interceptor, {
        mode: "approve-dangerous",
        blockedPatterns: [],
        requireApproval: [],
      });
      for (const cmd of ["git status", "echo hello"]) {
        const result = interceptor.evaluate(cmd);
        expect(result.allowed, cmd).toBe(true);
        expect(result.riskLevel, cmd).toBe("low");
      }
    });

    it("blockedPatterns still wins over risk-based approval", () => {
      stubPolicy(interceptor, {
        mode: "approve-dangerous",
        blockedPatterns: ["rm -rf"],
        requireApproval: [],
      });
      const result = interceptor.evaluate("rm -rf /tmp");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(false); // blocked, not just approval
      expect(result.riskLevel).toBe("high");       // assessed risk, not coerced to critical
    });

    it("requireApproval patterns checked before risk-based assessment", () => {
      stubPolicy(interceptor, {
        mode: "approve-dangerous",
        blockedPatterns: [],
        requireApproval: ["npm test"],
      });
      // npm test is low risk, but matches approval pattern
      const result = interceptor.evaluate("npm test --coverage");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
      expect(result.matchedPattern).toBe("npm test");
    });
  });

  // ── allow-all mode ──────────────────────────────────────────────────

  describe("allow-all mode", () => {
    it("should still hard-block critical destructive commands (allow-all cannot opt out)", () => {
      stubPolicy(interceptor, {
        mode: "allow-all",
        blockedPatterns: [],
        requireApproval: [],
      });
      const result = interceptor.evaluate("rm -rf /");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(false);
      expect(result.riskLevel).toBe("critical");
    });

    it("should still report correct risk level", () => {
      stubPolicy(interceptor, {
        mode: "allow-all",
        blockedPatterns: [],
        requireApproval: [],
      });
      const result = interceptor.evaluate("git push --force origin main");
      expect(result.allowed).toBe(true);
      expect(result.riskLevel).toBe("high");
    });

    it("blockedPatterns still deny even in allow-all mode", () => {
      stubPolicy(interceptor, {
        mode: "allow-all",
        blockedPatterns: ["forbidden"],
        requireApproval: [],
      });
      const result = interceptor.evaluate("forbidden action");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(false);
      expect(result.riskLevel).toBe("low"); // denied by policy, but not a critical command
    });

    it("requireApproval patterns still require approval in allow-all mode", () => {
      stubPolicy(interceptor, {
        mode: "allow-all",
        blockedPatterns: [],
        requireApproval: ["deploy"],
      });
      const result = interceptor.evaluate("deploy to production");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });
  });

  // ── Pattern priority: blocked > approval ────────────────────────────

  describe("Pattern priority", () => {
    it("blocked pattern wins when command matches both blocked and approval", () => {
      stubPolicy(interceptor, {
        mode: "approve-dangerous",
        blockedPatterns: ["nuke"],
        requireApproval: ["nuke"],
      });
      const result = interceptor.evaluate("nuke everything");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(false); // blocked, not approval
      expect(result.reason).toContain("blocked pattern");
    });
  });

  // ── Custom patterns (regex) ─────────────────────────────────────────

  describe("Custom regex patterns", () => {
    it("should support regex in blockedPatterns", () => {
      stubPolicy(interceptor, {
        mode: "deny-list",
        blockedPatterns: ["drop\\s+table"],
        requireApproval: [],
      });
      const result = interceptor.evaluate("mysql -e 'DROP TABLE users'");
      expect(result.allowed).toBe(false);
      expect(result.matchedPattern).toBe("drop\\s+table");
    });

    it("should support regex in requireApproval", () => {
      stubPolicy(interceptor, {
        mode: "deny-list",
        blockedPatterns: [],
        requireApproval: ["\\bsudo\\b.*\\binstall\\b"],
      });
      const result = interceptor.evaluate("sudo apt install vim");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });

    it("should fall back to substring match for invalid regex", () => {
      const badRegex = "[invalid-regex";  // unclosed bracket
      stubPolicy(interceptor, {
        mode: "deny-list",
        blockedPatterns: [badRegex],
        requireApproval: [],
      });
      // Falls back to substring check
      const result = interceptor.evaluate("test [invalid-regex here");
      expect(result.allowed).toBe(false);
    });

    it("invalid regex should not match when substring absent", () => {
      const badRegex = "[invalid-regex";
      stubPolicy(interceptor, {
        mode: "deny-list",
        blockedPatterns: [badRegex],
        requireApproval: [],
      });
      const result = interceptor.evaluate("some other command");
      expect(result.allowed).toBe(true);
    });

    it("pattern matching is case-insensitive", () => {
      stubPolicy(interceptor, {
        mode: "deny-list",
        blockedPatterns: ["delete"],
        requireApproval: [],
      });
      const result = interceptor.evaluate("DELETE FROM users");
      expect(result.allowed).toBe(false);
    });
  });

  // ── Empty patterns ──────────────────────────────────────────────────

  describe("Empty patterns", () => {
    it("empty requireApproval with approve-dangerous still uses risk assessment", () => {
      stubPolicy(interceptor, {
        mode: "approve-dangerous",
        blockedPatterns: [],
        requireApproval: [],
      });
      const result = interceptor.evaluate("git push --force origin main");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
      expect(result.riskLevel).toBe("high");
    });
  });

  // ── Policy override replaces defaults ───────────────────────────────

  describe("Policy overrides defaults", () => {
    it("built-in critical hard-block applies even when custom blockedPatterns omit it", () => {
      // Custom blocked patterns replace the policy defaults, but the built-in
      // critical-destructive hard-block is unconditional and still applies —
      // "rm -rf /" can never be allowed through, whatever the policy says.
      stubPolicy(interceptor, {
        mode: "deny-list",
        blockedPatterns: ["only-this-is-blocked"],
        requireApproval: [],
      });

      const result = interceptor.evaluate("rm -rf /");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(false);
      expect(result.riskLevel).toBe("critical");
    });

    it("custom requireApproval replaces default approval patterns", () => {
      stubPolicy(interceptor, {
        mode: "deny-list",
        blockedPatterns: [],
        requireApproval: ["only-this-needs-approval"],
      });

      // "rm -rf" would normally need approval, but custom replaces defaults
      const result = interceptor.evaluate("rm -rf /tmp");
      expect(result.allowed).toBe(true); // not in custom requireApproval
    });
  });
});

// ---------------------------------------------------------------------------
// Risk tier wiring (evaluate reports assessCommandRisk)
// ---------------------------------------------------------------------------

describe("CommandInterceptor — risk tier wiring", () => {
  let interceptor: CommandInterceptor;

  beforeEach(() => {
    interceptor = new CommandInterceptor();
    // No policy → evaluate just returns risk level, always allowed
    stubPolicy(interceptor, null);
  });

  // The full tier tables live in risk-rules-comprehensive.test.ts, at the
  // assessCommandRisk level. evaluate() reports that same assessment, so one
  // row per tier here is enough to pin the wiring.
  const smoke: Array<[string, string]> = [
    ["rm -rf /", "critical"],
    ["rm -rf node_modules", "high"],
    ["sudo apt update", "medium"],
    ["echo hello", "low"],
  ];

  for (const [cmd, tier] of smoke) {
    it(`evaluate() reports "${cmd}" as ${tier}`, () => {
      expect(interceptor.evaluate(cmd).riskLevel).toBe(tier);
    });
  }

  // ── False positive regression tests ─────────────────────────────────

  describe("False positive regressions", () => {
    it("git stash should not trigger curl|sh pattern", () => {
      const result = interceptor.evaluate("git stash");
      expect(result.riskLevel).toBe("low");
    });

    it("echo with rm -rf quoted should be low risk (safe prefix)", () => {
      const result = interceptor.evaluate('echo "rm -rf /"');
      expect(result.riskLevel).toBe("low");
    });

    it("grep for dangerous pattern should be low risk (safe prefix)", () => {
      const result = interceptor.evaluate("grep 'sudo rm' /var/log/auth.log");
      expect(result.riskLevel).toBe("low");
    });
  });
});
