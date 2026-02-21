import { describe, it, expect, vi, beforeEach } from "vitest";
import { RegexScanner } from "../src/scanners/regex-scanner.js";
import { AuditLogger } from "../src/core/audit-logger.js";

// We test the core logic extracted from posttool.ts
// by reproducing the evaluateToolResponse function inline.

interface PostToolInput {
  tool_name: string;
  tool_input: Record<string, any>;
  tool_response?: {
    output?: string;
    content?: string;
    error?: string;
  };
}

interface PostToolOutput {
  action: "continue" | "modify";
  tool_response?: Record<string, any>;
}

function evaluateToolResponse(payload: PostToolInput): PostToolOutput {
  const { tool_response } = payload;

  if (!tool_response) {
    return { action: "continue" };
  }

  const scanner = new RegexScanner();
  let modified = false;
  const redacted: Record<string, any> = { ...tool_response };

  if (typeof tool_response.output === "string" && tool_response.output) {
    if (scanner.hasSecrets(tool_response.output)) {
      redacted.output = scanner.redact(tool_response.output);
      modified = true;
    }
  }

  if (typeof tool_response.content === "string" && tool_response.content) {
    if (scanner.hasSecrets(tool_response.content)) {
      redacted.content = scanner.redact(tool_response.content);
      modified = true;
    }
  }

  if (modified) {
    return { action: "modify", tool_response: redacted };
  }

  return { action: "continue" };
}

describe("PostTool Hook", () => {
  beforeEach(() => {
    vi.spyOn(AuditLogger.prototype, "log").mockImplementation(() => {});
  });

  describe("clean output", () => {
    it("passes through with continue when no tool_response", () => {
      const result = evaluateToolResponse({
        tool_name: "Bash",
        tool_input: { command: "ls" },
      });
      expect(result.action).toBe("continue");
    });

    it("passes through when output has no secrets", () => {
      const result = evaluateToolResponse({
        tool_name: "Bash",
        tool_input: { command: "ls" },
        tool_response: { output: "file1.txt\nfile2.txt\n", error: "" },
      });
      expect(result.action).toBe("continue");
    });

    it("passes through when tool_response is empty object", () => {
      const result = evaluateToolResponse({
        tool_name: "Bash",
        tool_input: { command: "echo hi" },
        tool_response: {},
      });
      expect(result.action).toBe("continue");
    });
  });

  describe("secret detection in output", () => {
    it("redacts AWS key in output and returns modify", () => {
      const result = evaluateToolResponse({
        tool_name: "Bash",
        tool_input: { command: "cat .env" },
        tool_response: {
          output: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nsome other stuff",
          error: "",
        },
      });
      expect(result.action).toBe("modify");
      expect(result.tool_response).toBeDefined();
      expect(result.tool_response!.output).not.toContain("AKIAIOSFODNN7EXAMPLE");
      // Original secret should be masked
      expect(result.tool_response!.output).toContain("****");
    });

    it("does not alter clean lines when redacting", () => {
      const result = evaluateToolResponse({
        tool_name: "Bash",
        tool_input: { command: "cat .env" },
        tool_response: {
          output: "DB_HOST=localhost\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
          error: "",
        },
      });
      expect(result.action).toBe("modify");
      expect(result.tool_response!.output).toContain("DB_HOST=localhost");
      expect(result.tool_response!.output).not.toContain("AKIAIOSFODNN7EXAMPLE");
    });
  });

  describe("secret detection in content field", () => {
    it("redacts secret in content field", () => {
      const result = evaluateToolResponse({
        tool_name: "Read",
        tool_input: { file_path: "config.json" },
        tool_response: {
          content: '{"api_key": "AKIAIOSFODNN7EXAMPLE"}',
        },
      });
      expect(result.action).toBe("modify");
      expect(result.tool_response!.content).not.toContain("AKIAIOSFODNN7EXAMPLE");
    });
  });

  describe("error field passthrough", () => {
    it("preserves error field unchanged when redacting output", () => {
      const result = evaluateToolResponse({
        tool_name: "Bash",
        tool_input: { command: "cat .env" },
        tool_response: {
          output: "AKIAIOSFODNN7EXAMPLE1B",
          error: "some error message",
        },
      });
      expect(result.action).toBe("modify");
      expect(result.tool_response!.error).toBe("some error message");
    });
  });
});
