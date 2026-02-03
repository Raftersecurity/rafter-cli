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
});
