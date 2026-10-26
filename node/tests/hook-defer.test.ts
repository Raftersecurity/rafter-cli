import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

// The PreToolUse hook may only ever deny. When rafter has no objection it must
// defer to the platform's own permission flow, never approve: in Claude Code
// (and Codex) a PreToolUse "allow" skips the permission prompt, so an approving
// hook would make an agent more permissive than it is without rafter.
// Runs the real built CLI, as the agent platform would.

const CLI_ENTRY = path.join(path.resolve(__dirname, ".."), "dist", "index.js");

type Format = "claude" | "cursor" | "gemini" | "windsurf";

// One benign shell command, one benign file write and one blocked command,
// in each platform's own stdin shape.
const PAYLOADS: Record<Format, { bash: object; write: object; blocked: object }> = {
  claude: {
    bash: { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls -la" } },
    write: { hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: "notes.txt", content: "hello" } },
    blocked: { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "rm -rf /" } },
  },
  cursor: {
    bash: { hook_event_name: "beforeShellExecution", command: "ls -la", cwd: "." },
    write: { hook_event_name: "preToolUse", tool_name: "Write", tool_input: { file_path: "notes.txt", content: "hello" } },
    blocked: { hook_event_name: "beforeShellExecution", command: "rm -rf /", cwd: "." },
  },
  gemini: {
    bash: { hook_event_name: "BeforeTool", tool_name: "Bash", tool_input: { command: "ls -la" } },
    write: { hook_event_name: "BeforeTool", tool_name: "Write", tool_input: { file_path: "notes.txt", content: "hello" } },
    blocked: { hook_event_name: "BeforeTool", tool_name: "Bash", tool_input: { command: "rm -rf /" } },
  },
  windsurf: {
    bash: { agent_action_name: "pre_run_command", tool_info: { command_line: "ls -la", cwd: "." } },
    write: { agent_action_name: "pre_write_code", tool_info: { file_path: "notes.txt", content: "hello" } },
    blocked: { agent_action_name: "pre_run_command", tool_info: { command_line: "rm -rf /", cwd: "." } },
  },
};

let home: string;

function runHook(format: Format, payload: object) {
  const r = spawnSync("node", [CLI_ENTRY, "hook", "pretool", "--format", format], {
    cwd: home,
    input: JSON.stringify(payload),
    encoding: "utf-8",
    timeout: 30_000,
    // Isolate HOME so a developer's ~/.rafter config cannot change the result.
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: path.join(home, ".config") },
  });
  return { status: r.status, stdout: r.stdout.trim(), stderr: r.stderr };
}

beforeAll(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-defer-"));
});
afterAll(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe("hook pretool defers when it has no objection", () => {
  for (const kind of ["bash", "write"] as const) {
    it(`claude: a benign ${kind} gets no permission decision`, () => {
      const r = runHook("claude", PAYLOADS.claude[kind]);
      expect(r.status).toBe(0);
      expect(JSON.parse(r.stdout)).toEqual({});
    });

    it(`gemini: a benign ${kind} gets no decision`, () => {
      const r = runHook("gemini", PAYLOADS.gemini[kind]);
      expect(r.status).toBe(0);
      expect(JSON.parse(r.stdout)).toEqual({});
    });

    it(`windsurf: a benign ${kind} exits 0 with no output`, () => {
      const r = runHook("windsurf", PAYLOADS.windsurf[kind]);
      expect(r.status).toBe(0);
      expect(r.stdout).toBe("");
    });

    // Cursor has no neutral answer: its permission hooks block on an empty or
    // schema-invalid response, so "allow" is the only way to let a call proceed.
    it(`cursor: a benign ${kind} still returns the required permission field`, () => {
      const r = runHook("cursor", PAYLOADS.cursor[kind]);
      expect(r.status).toBe(0);
      expect(JSON.parse(r.stdout)).toEqual({ permission: "allow" });
    });
  }
});

describe("hook pretool still denies a blocked command", () => {
  it("claude", () => {
    const out = JSON.parse(runHook("claude", PAYLOADS.claude.blocked).stdout).hookSpecificOutput;
    expect(out.permissionDecision).toBe("deny");
    expect(out.permissionDecisionReason).toContain("Rafter blocked");
  });
  it("cursor", () => {
    expect(JSON.parse(runHook("cursor", PAYLOADS.cursor.blocked).stdout).permission).toBe("deny");
  });
  it("gemini", () => {
    expect(JSON.parse(runHook("gemini", PAYLOADS.gemini.blocked).stdout).decision).toBe("deny");
  });
  it("windsurf", () => {
    const r = runHook("windsurf", PAYLOADS.windsurf.blocked);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("Rafter blocked");
  });
});
