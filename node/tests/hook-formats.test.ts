import { describe, it, expect, vi, beforeEach } from "vitest";
import { AuditLogger } from "../src/core/audit-logger.js";
import { RegexScanner } from "../src/scanners/regex-scanner.js";

// ── Types mirroring hook interfaces ──────────────────────────────────────

type HookFormat = "claude" | "cursor" | "gemini" | "windsurf";

interface HookInput {
  session_id?: string;
  tool_name: string;
  tool_input: Record<string, any>;
}

interface HookDecision {
  decision: "allow" | "deny";
  reason?: string;
}

interface PostToolInput {
  session_id?: string;
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

// ── Reproduced normalizeInput from pretool.ts ────────────────────────────

function normalizeInput(raw: Record<string, any>, format: HookFormat): HookInput {
  if (format === "cursor") {
    const command = raw.command || "";
    const eventName = raw.hook_event_name || "";
    const toolName = eventName === "beforeShellExecution" ? "Bash"
      : eventName === "beforeReadFile" ? "Read"
      : eventName === "afterFileEdit" ? "Write"
      : raw.tool_name || "unknown";
    return {
      session_id: raw.conversation_id,
      tool_name: toolName,
      tool_input: eventName === "beforeShellExecution" ? { command } : (raw.tool_input || {}),
    };
  }

  if (format === "windsurf") {
    const toolInfo = raw.tool_info || {};
    const actionName = raw.agent_action_name || "";
    const toolName = actionName.includes("run_command") ? "Bash"
      : actionName.includes("write_code") ? "Write"
      : actionName.includes("read_code") ? "Read"
      : actionName.includes("mcp_tool_use") ? (toolInfo.mcp_tool_name || "unknown")
      : "unknown";
    return {
      session_id: raw.trajectory_id,
      tool_name: toolName,
      tool_input: toolName === "Bash" ? { command: toolInfo.command_line || "" } : toolInfo,
    };
  }

  // Claude, Codex, Continue, Gemini
  return {
    session_id: raw.session_id,
    tool_name: raw.tool_name || "",
    tool_input: raw.tool_input || {},
  };
}

// ── Reproduced writeDecision from pretool.ts ─────────────────────────────

function writeDecision(
  decision: HookDecision,
  format: HookFormat,
  stdoutWrite: (s: string) => void,
  stderrWrite: (s: string) => void,
  exitFn: (code: number) => void,
): void {
  const isDeny = decision.decision === "deny";
  const reason = decision.reason ?? "";

  switch (format) {
    case "cursor": {
      const output: Record<string, any> = {
        permission: isDeny ? "deny" : "allow",
      };
      if (isDeny && reason) {
        output.agentMessage = reason;
        output.userMessage = reason;
      }
      stdoutWrite(JSON.stringify(output) + "\n");
      break;
    }

    case "gemini": {
      if (isDeny) {
        stdoutWrite(JSON.stringify({ decision: "deny", reason }) + "\n");
      } else {
        stdoutWrite("{}\n");
      }
      break;
    }

    case "windsurf": {
      if (isDeny) {
        stderrWrite(reason + "\n");
        exitFn(2);
      }
      break;
    }

    default: {
      const output = {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: isDeny ? "deny" : "allow",
          permissionDecisionReason: reason,
        },
      };
      stdoutWrite(JSON.stringify(output) + "\n");
      break;
    }
  }
}

// ── Reproduced normalizePostInput from posttool.ts ───────────────────────

function normalizePostInput(raw: Record<string, any>, format: HookFormat): PostToolInput {
  if (format === "windsurf") {
    const toolInfo = raw.tool_info || {};
    return {
      session_id: raw.trajectory_id,
      tool_name: raw.agent_action_name?.includes("run_command") ? "Bash" : (toolInfo.mcp_tool_name || "unknown"),
      tool_input: {},
      tool_response: {
        output: toolInfo.stdout || toolInfo.output || "",
        error: toolInfo.stderr || "",
      },
    };
  }

  if (format === "cursor") {
    return {
      session_id: raw.conversation_id,
      tool_name: raw.hook_event_name === "afterShellExecution" ? "Bash" : (raw.tool_name || "unknown"),
      tool_input: raw.tool_input || {},
      tool_response: {
        output: raw.output || raw.tool_response?.output || "",
        content: raw.content || raw.tool_response?.content || "",
        error: raw.error || raw.tool_response?.error || "",
      },
    };
  }

  // Claude, Codex, Continue, Gemini
  return {
    session_id: raw.session_id,
    tool_name: raw.tool_name || "",
    tool_input: raw.tool_input || {},
    tool_response: raw.tool_response,
  };
}

// ── Reproduced writeOutput from posttool.ts ──────────────────────────────

function writeOutput(
  output: PostToolOutput,
  format: HookFormat,
  stdoutWrite: (s: string) => void,
  stderrWrite: (s: string) => void,
): void {
  const isModify = output.action === "modify" && output.tool_response;

  switch (format) {
    case "cursor": {
      if (isModify) {
        stdoutWrite(JSON.stringify({
          agentMessage: "Rafter redacted secrets from tool output",
        }) + "\n");
      }
      break;
    }

    case "gemini": {
      if (isModify) {
        stdoutWrite(JSON.stringify({
          systemMessage: "Rafter redacted secrets from tool output",
        }) + "\n");
      } else {
        stdoutWrite("{}\n");
      }
      break;
    }

    case "windsurf": {
      if (isModify) {
        stderrWrite("Rafter: secrets redacted from tool output\n");
      }
      break;
    }

    default: {
      const hookOutput: Record<string, any> = {
        hookSpecificOutput: {
          hookEventName: "PostToolUse",
        },
      };
      if (isModify) {
        hookOutput.hookSpecificOutput.modifiedToolResult = output.tool_response;
      }
      stdoutWrite(JSON.stringify(hookOutput) + "\n");
      break;
    }
  }
}

// ── Tests ────────────────────────────────────────────────────────────────

describe("Multi-Platform Hook Format Support", () => {
  beforeEach(() => {
    vi.spyOn(AuditLogger.prototype, "log").mockImplementation(() => {});
  });

  // ═══════════════════════════════════════════════════════════════════════
  // 1. normalizeInput() — pretool input normalization
  // ═══════════════════════════════════════════════════════════════════════

  describe("normalizeInput()", () => {
    describe("Cursor format", () => {
      it("maps beforeShellExecution to Bash with command", () => {
        const result = normalizeInput(
          { hook_event_name: "beforeShellExecution", command: "ls -la", conversation_id: "c-123" },
          "cursor",
        );
        expect(result).toEqual({
          session_id: "c-123",
          tool_name: "Bash",
          tool_input: { command: "ls -la" },
        });
      });

      it("maps beforeReadFile to Read", () => {
        const result = normalizeInput(
          { hook_event_name: "beforeReadFile", conversation_id: "c-456" },
          "cursor",
        );
        expect(result.tool_name).toBe("Read");
      });

      it("maps afterFileEdit to Write", () => {
        const result = normalizeInput(
          { hook_event_name: "afterFileEdit", conversation_id: "c-789" },
          "cursor",
        );
        expect(result.tool_name).toBe("Write");
      });

      it("falls back to tool_name for unknown events", () => {
        const result = normalizeInput(
          { hook_event_name: "someOtherEvent", tool_name: "CustomTool" },
          "cursor",
        );
        expect(result.tool_name).toBe("CustomTool");
      });

      it("uses 'unknown' when no tool_name or recognized event", () => {
        const result = normalizeInput(
          { hook_event_name: "unknownEvent" },
          "cursor",
        );
        expect(result.tool_name).toBe("unknown");
      });

      it("passes tool_input for non-shell events", () => {
        const result = normalizeInput(
          { hook_event_name: "beforeReadFile", tool_input: { file_path: "/etc/passwd" } },
          "cursor",
        );
        expect(result.tool_input).toEqual({ file_path: "/etc/passwd" });
      });
    });

    describe("Windsurf format", () => {
      it("maps pre_run_command to Bash with command_line", () => {
        const result = normalizeInput(
          {
            agent_action_name: "pre_run_command",
            tool_info: { command_line: "ls -la", cwd: "/home/user" },
            trajectory_id: "w-100",
          },
          "windsurf",
        );
        expect(result).toEqual({
          session_id: "w-100",
          tool_name: "Bash",
          tool_input: { command: "ls -la" },
        });
      });

      it("maps pre_write_code to Write", () => {
        const result = normalizeInput(
          {
            agent_action_name: "pre_write_code",
            tool_info: { file_path: "app.ts", content: "code" },
          },
          "windsurf",
        );
        expect(result.tool_name).toBe("Write");
        expect(result.tool_input).toEqual({ file_path: "app.ts", content: "code" });
      });

      it("maps pre_read_code to Read", () => {
        const result = normalizeInput(
          { agent_action_name: "pre_read_code", tool_info: { file_path: "main.ts" } },
          "windsurf",
        );
        expect(result.tool_name).toBe("Read");
      });

      it("maps pre_mcp_tool_use to the MCP tool name", () => {
        const result = normalizeInput(
          {
            agent_action_name: "pre_mcp_tool_use",
            tool_info: { mcp_tool_name: "scan_secrets", args: {} },
          },
          "windsurf",
        );
        expect(result.tool_name).toBe("scan_secrets");
      });

      it("uses 'unknown' for unrecognized action names", () => {
        const result = normalizeInput(
          { agent_action_name: "pre_something_else", tool_info: {} },
          "windsurf",
        );
        expect(result.tool_name).toBe("unknown");
      });

      it("handles missing tool_info gracefully", () => {
        const result = normalizeInput(
          { agent_action_name: "pre_run_command" },
          "windsurf",
        );
        expect(result.tool_name).toBe("Bash");
        expect(result.tool_input).toEqual({ command: "" });
      });
    });

    describe("Claude/Gemini passthrough format", () => {
      it("passes through Claude-format payload unchanged", () => {
        const raw = {
          session_id: "sess-abc",
          tool_name: "Bash",
          tool_input: { command: "ls" },
        };
        const result = normalizeInput(raw, "claude");
        expect(result).toEqual({
          session_id: "sess-abc",
          tool_name: "Bash",
          tool_input: { command: "ls" },
        });
      });

      it("passes through Gemini-format payload unchanged", () => {
        const raw = {
          session_id: "gem-1",
          tool_name: "Read",
          tool_input: { file_path: "/etc/hosts" },
        };
        const result = normalizeInput(raw, "gemini");
        expect(result).toEqual({
          session_id: "gem-1",
          tool_name: "Read",
          tool_input: { file_path: "/etc/hosts" },
        });
      });

      it("defaults tool_name to empty string when missing", () => {
        const result = normalizeInput({ session_id: "x" }, "claude");
        expect(result.tool_name).toBe("");
      });

      it("defaults tool_input to empty object when missing", () => {
        const result = normalizeInput({ tool_name: "Bash" }, "claude");
        expect(result.tool_input).toEqual({});
      });
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // 2. writeDecision() — pretool output formatting
  // ═══════════════════════════════════════════════════════════════════════

  describe("writeDecision()", () => {
    let stdoutBuf: string;
    let stderrBuf: string;
    let exitCode: number | null;
    let stdoutWrite: (s: string) => void;
    let stderrWrite: (s: string) => void;
    let exitFn: (code: number) => void;

    beforeEach(() => {
      stdoutBuf = "";
      stderrBuf = "";
      exitCode = null;
      stdoutWrite = (s: string) => { stdoutBuf += s; };
      stderrWrite = (s: string) => { stderrBuf += s; };
      exitFn = (code: number) => { exitCode = code; };
    });

    describe("Claude format (default)", () => {
      it("outputs hookSpecificOutput envelope with allow", () => {
        writeDecision({ decision: "allow" }, "claude", stdoutWrite, stderrWrite, exitFn);
        const parsed = JSON.parse(stdoutBuf.trim());
        expect(parsed.hookSpecificOutput).toBeDefined();
        expect(parsed.hookSpecificOutput.hookEventName).toBe("PreToolUse");
        expect(parsed.hookSpecificOutput.permissionDecision).toBe("allow");
        expect(parsed.hookSpecificOutput.permissionDecisionReason).toBe("");
      });

      it("outputs hookSpecificOutput envelope with deny and reason", () => {
        writeDecision(
          { decision: "deny", reason: "blocked: rm -rf" },
          "claude", stdoutWrite, stderrWrite, exitFn,
        );
        const parsed = JSON.parse(stdoutBuf.trim());
        expect(parsed.hookSpecificOutput.permissionDecision).toBe("deny");
        expect(parsed.hookSpecificOutput.permissionDecisionReason).toBe("blocked: rm -rf");
      });
    });

    describe("Cursor format", () => {
      it("outputs { permission: 'allow' } for allow decisions", () => {
        writeDecision({ decision: "allow" }, "cursor", stdoutWrite, stderrWrite, exitFn);
        const parsed = JSON.parse(stdoutBuf.trim());
        expect(parsed).toEqual({ permission: "allow" });
      });

      it("outputs deny with agentMessage and userMessage", () => {
        writeDecision(
          { decision: "deny", reason: "dangerous command" },
          "cursor", stdoutWrite, stderrWrite, exitFn,
        );
        const parsed = JSON.parse(stdoutBuf.trim());
        expect(parsed.permission).toBe("deny");
        expect(parsed.agentMessage).toBe("dangerous command");
        expect(parsed.userMessage).toBe("dangerous command");
      });

      it("omits agentMessage/userMessage when deny has no reason", () => {
        writeDecision(
          { decision: "deny" },
          "cursor", stdoutWrite, stderrWrite, exitFn,
        );
        const parsed = JSON.parse(stdoutBuf.trim());
        expect(parsed.permission).toBe("deny");
        expect(parsed.agentMessage).toBeUndefined();
        expect(parsed.userMessage).toBeUndefined();
      });
    });

    describe("Gemini format", () => {
      it("outputs empty object for allow", () => {
        writeDecision({ decision: "allow" }, "gemini", stdoutWrite, stderrWrite, exitFn);
        expect(stdoutBuf.trim()).toBe("{}");
      });

      it("outputs { decision: 'deny', reason } for deny", () => {
        writeDecision(
          { decision: "deny", reason: "secret found" },
          "gemini", stdoutWrite, stderrWrite, exitFn,
        );
        const parsed = JSON.parse(stdoutBuf.trim());
        expect(parsed).toEqual({ decision: "deny", reason: "secret found" });
      });
    });

    describe("Windsurf format", () => {
      it("produces no stdout output for allow (just exits 0)", () => {
        writeDecision({ decision: "allow" }, "windsurf", stdoutWrite, stderrWrite, exitFn);
        expect(stdoutBuf).toBe("");
        expect(stderrBuf).toBe("");
        expect(exitCode).toBeNull();
      });

      it("writes reason to stderr and exits with code 2 on deny", () => {
        writeDecision(
          { decision: "deny", reason: "blocked: rm -rf /" },
          "windsurf", stdoutWrite, stderrWrite, exitFn,
        );
        expect(stdoutBuf).toBe("");
        expect(stderrBuf).toBe("blocked: rm -rf /\n");
        expect(exitCode).toBe(2);
      });
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // 3. normalizePostInput() — posttool input normalization
  // ═══════════════════════════════════════════════════════════════════════

  describe("normalizePostInput()", () => {
    describe("Windsurf format", () => {
      it("maps post_run_command with stdout/stderr", () => {
        const result = normalizePostInput(
          {
            agent_action_name: "post_run_command",
            tool_info: { stdout: "hello world", stderr: "" },
            trajectory_id: "w-200",
          },
          "windsurf",
        );
        expect(result).toEqual({
          session_id: "w-200",
          tool_name: "Bash",
          tool_input: {},
          tool_response: {
            output: "hello world",
            error: "",
          },
        });
      });

      it("falls back to output field when stdout missing", () => {
        const result = normalizePostInput(
          {
            agent_action_name: "post_something",
            tool_info: { output: "data", mcp_tool_name: "scan_secrets" },
          },
          "windsurf",
        );
        expect(result.tool_name).toBe("scan_secrets");
        expect(result.tool_response?.output).toBe("data");
      });

      it("handles missing tool_info gracefully", () => {
        const result = normalizePostInput(
          { agent_action_name: "post_run_command" },
          "windsurf",
        );
        expect(result.tool_name).toBe("Bash");
        expect(result.tool_response).toEqual({ output: "", error: "" });
      });
    });

    describe("Cursor format", () => {
      it("maps afterShellExecution to Bash with output", () => {
        const result = normalizePostInput(
          {
            hook_event_name: "afterShellExecution",
            output: "file1.txt\nfile2.txt",
            conversation_id: "c-300",
          },
          "cursor",
        );
        expect(result).toEqual({
          session_id: "c-300",
          tool_name: "Bash",
          tool_input: {},
          tool_response: {
            output: "file1.txt\nfile2.txt",
            content: "",
            error: "",
          },
        });
      });

      it("falls back to tool_response fields", () => {
        const result = normalizePostInput(
          {
            hook_event_name: "afterReadFile",
            tool_name: "Read",
            tool_response: { output: "file content", content: "raw", error: "warn" },
          },
          "cursor",
        );
        expect(result.tool_name).toBe("Read");
        expect(result.tool_response?.output).toBe("file content");
        expect(result.tool_response?.content).toBe("raw");
        expect(result.tool_response?.error).toBe("warn");
      });

      it("uses top-level fields over tool_response fields", () => {
        const result = normalizePostInput(
          {
            hook_event_name: "afterShellExecution",
            output: "top-level",
            tool_response: { output: "nested" },
          },
          "cursor",
        );
        // Top-level "output" takes priority due to || short-circuit
        expect(result.tool_response?.output).toBe("top-level");
      });
    });

    describe("Claude/Gemini passthrough", () => {
      it("passes through Claude payload unchanged", () => {
        const raw = {
          session_id: "sess-post",
          tool_name: "Bash",
          tool_input: { command: "echo hi" },
          tool_response: { output: "hi\n" },
        };
        const result = normalizePostInput(raw, "claude");
        expect(result).toEqual(raw);
      });

      it("passes through Gemini payload unchanged", () => {
        const raw = {
          session_id: "gem-post",
          tool_name: "Read",
          tool_input: { file_path: "test.txt" },
          tool_response: { content: "hello" },
        };
        const result = normalizePostInput(raw, "gemini");
        expect(result).toEqual(raw);
      });

      it("preserves undefined tool_response", () => {
        const result = normalizePostInput(
          { tool_name: "Bash", tool_input: {} },
          "claude",
        );
        expect(result.tool_response).toBeUndefined();
      });
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // 4. writeOutput() — posttool output formatting
  // ═══════════════════════════════════════════════════════════════════════

  describe("writeOutput()", () => {
    let stdoutBuf: string;
    let stderrBuf: string;
    let stdoutWrite: (s: string) => void;
    let stderrWrite: (s: string) => void;

    beforeEach(() => {
      stdoutBuf = "";
      stderrBuf = "";
      stdoutWrite = (s: string) => { stdoutBuf += s; };
      stderrWrite = (s: string) => { stderrBuf += s; };
    });

    describe("Claude format (default)", () => {
      it("outputs hookSpecificOutput without modifiedToolResult on continue", () => {
        writeOutput({ action: "continue" }, "claude", stdoutWrite, stderrWrite);
        const parsed = JSON.parse(stdoutBuf.trim());
        expect(parsed.hookSpecificOutput).toBeDefined();
        expect(parsed.hookSpecificOutput.hookEventName).toBe("PostToolUse");
        expect(parsed.hookSpecificOutput.modifiedToolResult).toBeUndefined();
      });

      it("outputs hookSpecificOutput with modifiedToolResult on modify", () => {
        const redacted = { output: "AWS_ACCESS_KEY_ID=****" };
        writeOutput(
          { action: "modify", tool_response: redacted },
          "claude", stdoutWrite, stderrWrite,
        );
        const parsed = JSON.parse(stdoutBuf.trim());
        expect(parsed.hookSpecificOutput.hookEventName).toBe("PostToolUse");
        expect(parsed.hookSpecificOutput.modifiedToolResult).toEqual(redacted);
      });
    });

    describe("Cursor format", () => {
      it("produces no output on continue", () => {
        writeOutput({ action: "continue" }, "cursor", stdoutWrite, stderrWrite);
        expect(stdoutBuf).toBe("");
        expect(stderrBuf).toBe("");
      });

      it("outputs agentMessage on modify", () => {
        writeOutput(
          { action: "modify", tool_response: { output: "redacted" } },
          "cursor", stdoutWrite, stderrWrite,
        );
        const parsed = JSON.parse(stdoutBuf.trim());
        expect(parsed).toEqual({
          agentMessage: "Rafter redacted secrets from tool output",
        });
      });
    });

    describe("Gemini format", () => {
      it("outputs empty object on continue", () => {
        writeOutput({ action: "continue" }, "gemini", stdoutWrite, stderrWrite);
        expect(stdoutBuf.trim()).toBe("{}");
      });

      it("outputs systemMessage on modify", () => {
        writeOutput(
          { action: "modify", tool_response: { output: "redacted" } },
          "gemini", stdoutWrite, stderrWrite,
        );
        const parsed = JSON.parse(stdoutBuf.trim());
        expect(parsed).toEqual({
          systemMessage: "Rafter redacted secrets from tool output",
        });
      });
    });

    describe("Windsurf format", () => {
      it("produces no output on continue", () => {
        writeOutput({ action: "continue" }, "windsurf", stdoutWrite, stderrWrite);
        expect(stdoutBuf).toBe("");
        expect(stderrBuf).toBe("");
      });

      it("writes notification to stderr on modify", () => {
        writeOutput(
          { action: "modify", tool_response: { output: "redacted" } },
          "windsurf", stdoutWrite, stderrWrite,
        );
        expect(stdoutBuf).toBe("");
        expect(stderrBuf).toBe("Rafter: secrets redacted from tool output\n");
      });
    });

    describe("edge cases", () => {
      it("treats modify without tool_response as continue for Cursor", () => {
        writeOutput({ action: "modify" }, "cursor", stdoutWrite, stderrWrite);
        expect(stdoutBuf).toBe("");
      });

      it("treats modify without tool_response as continue for Windsurf", () => {
        writeOutput({ action: "modify" }, "windsurf", stdoutWrite, stderrWrite);
        expect(stderrBuf).toBe("");
      });

      it("treats modify without tool_response as no modifiedToolResult for Claude", () => {
        writeOutput({ action: "modify" }, "claude", stdoutWrite, stderrWrite);
        const parsed = JSON.parse(stdoutBuf.trim());
        expect(parsed.hookSpecificOutput.modifiedToolResult).toBeUndefined();
      });
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // 5. Cross-format consistency checks
  // ═══════════════════════════════════════════════════════════════════════

  describe("cross-format consistency", () => {
    it("all formats normalize the same Bash command to the same HookInput shape", () => {
      const claudeResult = normalizeInput(
        { tool_name: "Bash", tool_input: { command: "rm -rf /" } },
        "claude",
      );
      const cursorResult = normalizeInput(
        { hook_event_name: "beforeShellExecution", command: "rm -rf /" },
        "cursor",
      );
      const windsurfResult = normalizeInput(
        { agent_action_name: "pre_run_command", tool_info: { command_line: "rm -rf /" } },
        "windsurf",
      );
      const geminiResult = normalizeInput(
        { tool_name: "Bash", tool_input: { command: "rm -rf /" } },
        "gemini",
      );

      // All should normalize to the same tool_name and command
      expect(claudeResult.tool_name).toBe("Bash");
      expect(cursorResult.tool_name).toBe("Bash");
      expect(windsurfResult.tool_name).toBe("Bash");
      expect(geminiResult.tool_name).toBe("Bash");

      expect(claudeResult.tool_input.command).toBe("rm -rf /");
      expect(cursorResult.tool_input.command).toBe("rm -rf /");
      expect(windsurfResult.tool_input.command).toBe("rm -rf /");
      expect(geminiResult.tool_input.command).toBe("rm -rf /");
    });

    it("all formats produce valid JSON output for pretool allow", () => {
      const formats: HookFormat[] = ["claude", "cursor", "gemini", "windsurf"];
      for (const format of formats) {
        let stdout = "";
        let stderr = "";
        writeDecision(
          { decision: "allow" },
          format,
          (s) => { stdout += s; },
          (s) => { stderr += s; },
          () => {},
        );
        // Windsurf allow produces no output; others produce valid JSON
        if (format === "windsurf") {
          expect(stdout).toBe("");
        } else {
          expect(() => JSON.parse(stdout.trim())).not.toThrow();
        }
      }
    });

    it("all formats produce valid JSON output for posttool continue", () => {
      const formats: HookFormat[] = ["claude", "cursor", "gemini", "windsurf"];
      for (const format of formats) {
        let stdout = "";
        writeOutput(
          { action: "continue" },
          format,
          (s) => { stdout += s; },
          () => {},
        );
        // Cursor and Windsurf continue produce no output; others produce valid JSON
        if (format === "cursor" || format === "windsurf") {
          expect(stdout).toBe("");
        } else {
          expect(() => JSON.parse(stdout.trim())).not.toThrow();
        }
      }
    });
  });
});
