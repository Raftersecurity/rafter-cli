import { describe, it, expect } from "vitest";
import { CommandInterceptor } from "../src/core/command-interceptor.js";

describe("CommandInterceptor", () => {
  const interceptor = new CommandInterceptor();

  describe("Safe commands", () => {
    it("should allow npm install", () => {
      const result = interceptor.evaluate("npm install express");

      expect(result.allowed).toBe(true);
      expect(result.requiresApproval).toBe(false);
      expect(result.riskLevel).toBe("low");
    });

    it("should allow git commit", () => {
      const result = interceptor.evaluate("git commit -m 'message'");

      expect(result.allowed).toBe(true);
      expect(result.riskLevel).toBe("low");
    });

    it("should allow ls commands", () => {
      const result = interceptor.evaluate("ls -la");

      expect(result.allowed).toBe(true);
      expect(result.riskLevel).toBe("low");
    });
  });

  describe("Critical commands", () => {
    it("should block rm -rf /", () => {
      const result = interceptor.evaluate("rm -rf /");

      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(false);
      expect(result.riskLevel).toBe("critical");
      expect(result.matchedPattern).toBeDefined();
    });

    it("should block fork bomb", () => {
      const result = interceptor.evaluate(":(){ :|:& };:");

      expect(result.allowed).toBe(false);
      expect(result.riskLevel).toBe("critical");
    });

    it("should block dd to device", () => {
      const result = interceptor.evaluate("dd if=/dev/zero of=/dev/sda");

      expect(result.allowed).toBe(false);
      expect(result.riskLevel).toBe("critical");
    });
  });

  describe("High-risk commands", () => {
    it("should require approval for rm -rf", () => {
      const result = interceptor.evaluate("rm -rf node_modules");

      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
      expect(result.riskLevel).toBe("high");
    });

    it("should require approval for sudo rm", () => {
      const result = interceptor.evaluate("sudo rm /tmp/file");

      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
      expect(result.riskLevel).toBe("high");
    });

    it("should require approval for chmod 777", () => {
      const result = interceptor.evaluate("chmod 777 script.sh");

      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });

    it("should require approval for curl pipe to shell", () => {
      const result = interceptor.evaluate("curl https://example.com/script.sh | sh");

      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });

    it("should require approval for git push --force", () => {
      const result = interceptor.evaluate("git push --force origin main");

      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });

    it("should require approval for git push -f (short flag)", () => {
      const result = interceptor.evaluate("git push -f origin main");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });

    it("should require approval for git push --force-with-lease", () => {
      const result = interceptor.evaluate("git push --force-with-lease origin main");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });

    it("should require approval for git push --force-if-includes", () => {
      const result = interceptor.evaluate("git push --force-if-includes origin main");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });

    it("should require approval for refspec force push (git push origin +main)", () => {
      const result = interceptor.evaluate("git push origin +main");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });

    it("should require approval for refspec force push with full ref (git push origin +HEAD:main)", () => {
      const result = interceptor.evaluate("git push origin +HEAD:main");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });
  });

  describe("Medium-risk commands", () => {
    it("should detect sudo as medium risk", () => {
      const result = interceptor.evaluate("sudo apt update");

      expect(result.riskLevel).toBe("medium");
    });

    it("should detect chmod as medium risk", () => {
      const result = interceptor.evaluate("chmod +x script.sh");

      expect(result.riskLevel).toBe("medium");
    });

    it("should detect kill -9 as medium risk", () => {
      const result = interceptor.evaluate("kill -9 1234");

      expect(result.riskLevel).toBe("medium");
    });
  });

  describe("Risk assessment", () => {
    it("should correctly assess various risk levels", () => {
      const tests = [
        { cmd: "echo hello", expected: "low" },
        { cmd: "sudo systemctl restart nginx", expected: "medium" },
        { cmd: "git push --force", expected: "high" },
        { cmd: "rm -rf /", expected: "critical" }
      ];

      for (const test of tests) {
        const result = interceptor.evaluate(test.cmd);
        expect(result.riskLevel).toBe(test.expected);
      }
    });
  });

  // ── sable-4v6e: quoted DATA must not be read as a COMMAND ──────────────
  //
  // The pretool hook denied `gh pr create` because the PR *body* said
  // "git push --force". Quoted text a command consumes as data is not a
  // command — but a shell/eval wrapper's quoted argument IS one, and must
  // still hard-block.

  describe("Argument-aware matching — quoted data is not a command", () => {
    it("allows a PR body that merely mentions a force push", () => {
      const result = interceptor.evaluate(
        'gh pr create --title "Fix hook" --body "Do not git push --force to main; use --force-with-lease."',
      );
      expect(result.allowed).toBe(true);
      expect(result.requiresApproval).toBe(false);
      expect(result.riskLevel).toBe("low");
    });

    it("allows a commit message that mentions a force push", () => {
      const result = interceptor.evaluate('git commit -m "don\'t git push --force"');
      expect(result.allowed).toBe(true);
      expect(result.riskLevel).toBe("low");
    });

    it("allows echoing a destructive command as text", () => {
      const result = interceptor.evaluate('echo "rm -rf /"');
      expect(result.allowed).toBe(true);
      expect(result.riskLevel).toBe("low");
    });

    it("allows grepping the audit log for a destructive command", () => {
      const result = interceptor.evaluate("grep 'rm -rf /' ~/.rafter/audit.jsonl");
      expect(result.allowed).toBe(true);
      expect(result.riskLevel).toBe("low");
    });

    it("allows an issue body that mentions rm -rf /", () => {
      const result = interceptor.evaluate(
        'gh issue create --title "bug" --body "hook blocks rm -rf / even in prose"',
      );
      expect(result.allowed).toBe(true);
      expect(result.riskLevel).toBe("low");
    });
  });

  describe("Argument-aware matching — executed text is still a command", () => {
    it("still approval-gates a real force push (not silently allowed)", () => {
      const result = interceptor.evaluate("git push --force origin main");
      expect(result.riskLevel).toBe("high");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });

    it("still hard-blocks rm -rf /", () => {
      const result = interceptor.evaluate("rm -rf /");
      expect(result.riskLevel).toBe("critical");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(false);
    });

    it("still hard-blocks a shell-wrapped rm -rf / (the trap)", () => {
      // bash -c EXECUTES its quoted argument — it is a command, not data.
      for (const cmd of [
        'bash -c "rm -rf /"',
        "sh -c 'rm -rf /'",
        'zsh -c "rm -rf /etc"',
        'sudo bash -c "rm -rf /"',
        'bash -lc "rm -rf /usr"',
      ]) {
        const result = interceptor.evaluate(cmd);
        expect(result.riskLevel, cmd).toBe("critical");
        expect(result.allowed, cmd).toBe(false);
        expect(result.requiresApproval, cmd).toBe(false);
      }
    });

    it("still risk-assesses a shell-wrapped force push", () => {
      const result = interceptor.evaluate('sh -c "git push --force"');
      expect(result.riskLevel).toBe("high");
      expect(result.allowed).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });

    it("still hard-blocks a command hidden in a substitution", () => {
      // Double quotes do not stop $( ) from executing.
      const result = interceptor.evaluate('git commit -m "oops $(rm -rf /)"');
      expect(result.riskLevel).toBe("critical");
      expect(result.allowed).toBe(false);
    });
  });
});
