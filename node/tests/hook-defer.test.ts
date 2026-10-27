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

// Each platform names its shell and file-write tools differently. The same
// policy must apply whatever the tool is called: a blocked command (or a write
// carrying a secret) through the platform's own tool name is denied, and a
// benign one gets the usual no-objection answer.
const FAKE_KEY = "AKIA" + "IOSFODNN7" + "ABCDEFG";
const NATIVE_TOOLS: { name: string; format: Format; payload: (bad: boolean) => object }[] = [
  { name: "gemini run_shell_command", format: "gemini",
    payload: (bad) => ({ tool_name: "run_shell_command", tool_input: { command: bad ? "rm -rf /" : "ls -la" } }) },
  { name: "gemini write_file", format: "gemini",
    payload: (bad) => ({ tool_name: "write_file", tool_input: { file_path: "a.ts", content: bad ? FAKE_KEY : "hello" } }) },
  { name: "gemini replace", format: "gemini",
    payload: (bad) => ({ tool_name: "replace", tool_input: { file_path: "a.ts", old_string: "x", new_string: bad ? FAKE_KEY : "hello" } }) },
  { name: "cursor Shell", format: "cursor",
    payload: (bad) => ({ hook_event_name: "preToolUse", tool_name: "Shell", tool_input: { command: bad ? "rm -rf /" : "ls -la" } }) },
  { name: "codex apply_patch", format: "claude",
    payload: (bad) => ({ tool_name: "apply_patch", tool_input: { command: `*** Begin Patch\n*** Add File: a.ts\n+${bad ? FAKE_KEY : "hello"}\n*** End Patch` } }) },
  // Continue's Write names its path "filepath"; the rafter-config guard must still see it.
  { name: "continue Write", format: "claude",
    payload: (bad) => ({ tool_name: "Write", tool_input: { filepath: bad ? path.join(home, ".rafter", "config.json") : "a.ts", content: "{}" } }) },
  { name: "continue MultiEdit", format: "claude",
    payload: (bad) => ({ tool_name: "MultiEdit", tool_input: { file_path: "a.ts", edits: [{ old_string: "x", new_string: bad ? FAKE_KEY : "hello" }] } }) },
  { name: "windsurf pre_write_code edits", format: "windsurf",
    payload: (bad) => ({ agent_action_name: "pre_write_code", tool_info: { file_path: "a.ts", edits: [{ old_string: "x", new_string: bad ? FAKE_KEY : "hello" }] } }) },
];

function isDeny(format: Format, r: ReturnType<typeof runHook>): boolean {
  if (format === "windsurf") return r.status === 2;
  const out = JSON.parse(r.stdout);
  if (format === "cursor") return out.permission === "deny";
  if (format === "gemini") return out.decision === "deny";
  return out.hookSpecificOutput?.permissionDecision === "deny";
}

describe("hook pretool evaluates each platform's own tool names", () => {
  for (const t of NATIVE_TOOLS) {
    it(`${t.name}: denied when bad, no objection when benign`, () => {
      expect(isDeny(t.format, runHook(t.format, t.payload(true)))).toBe(true);
      const ok = runHook(t.format, t.payload(false));
      expect(ok.status).toBe(0);
      expect(isDeny(t.format, ok)).toBe(false);
    });
  }
});
