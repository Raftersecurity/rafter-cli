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
  // apply_patch names its files only in its headers; the rafter-config guard
  // must see each one: Add (~), Update + Move to (absolute), Delete (relative).
  { name: "codex apply_patch Add File", format: "claude",
    payload: (bad) => ({ tool_name: "apply_patch", tool_input: { command: `*** Begin Patch\n*** Add File: ${bad ? "~/.rafter/config.json" : "a.json"}\n+{}\n*** End Patch` } }) },
  { name: "codex apply_patch Move to", format: "claude",
    payload: (bad) => ({ tool_name: "apply_patch", tool_input: { command: `*** Begin Patch\n*** Update File: a.json\n*** Move to: ${bad ? path.join(home, ".rafter", "config.json") : "b.json"}\n@@\n-x\n+{}\n*** End Patch` } }) },
  { name: "codex apply_patch Delete File", format: "claude",
    payload: (bad) => ({ tool_name: "apply_patch", tool_input: { command: `*** Begin Patch\n*** Delete File: ${bad ? ".rafter/config.json" : "a.json"}\n*** End Patch` } }) },
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

describe("apply_patch to rafter's config gets the Write guard's reason", () => {
  it("claude", () => {
    const r = runHook("claude", { tool_name: "apply_patch", tool_input: { command: "*** Begin Patch\n*** Update File: ~/.rafter/config.json\n@@\n-x\n+{}\n*** End Patch" } });
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecisionReason).toContain("write to rafter's own configuration");
  });
});

describe("a symlink into the rafter dir does not get around the Write guard (sable-rxqr)", () => {
  it("denies a Write through a link to ~/.rafter", () => {
    fs.mkdirSync(path.join(home, ".rafter"), { recursive: true });
    const link = path.join(home, "innocent");
    fs.symlinkSync(path.join(home, ".rafter"), link);
    try {
      const r = runHook("claude", { tool_name: "Write", tool_input: { file_path: path.join(link, "config.json"), content: "{}" } });
      expect(isDeny("claude", r)).toBe(true);
    } finally {
      fs.unlinkSync(link);
    }
  });
});

// The platform only calls the hook for tools its matcher names, so each
// installer's matcher must name the write tools the hook evaluates.
describe("installers register the hook for every evaluated write tool", () => {
  function install(args: string[], file: string) {
    const h = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-install-"));
    try {
      const r = spawnSync("node", [CLI_ENTRY, "agent", ...args], {
        cwd: h, encoding: "utf-8", timeout: 60_000,
        env: { ...process.env, HOME: h, XDG_CONFIG_HOME: path.join(h, ".config") },
      });
      expect(r.status, r.stderr).toBe(0);
      return JSON.parse(fs.readFileSync(path.join(h, file), "utf-8")).hooks;
    } finally {
      fs.rmSync(h, { recursive: true, force: true });
    }
  }
  it("claude code: init --with-claude-code matches MultiEdit", () => {
    const hooks = install(["init", "--with-claude-code"], ".claude/settings.json");
    expect(hooks.PreToolUse.map((e: any) => e.matcher)).toEqual(["Bash", "Write|Edit|MultiEdit"]);
  });
  it("gemini: the BeforeTool matcher names only Gemini's real tools", () => {
    const hooks = install(["enable", "gemini.hooks", "--force"], ".gemini/settings.json");
    expect(hooks.BeforeTool.map((e: any) => e.matcher)).toEqual(["run_shell_command|write_file|replace"]);
  });
});
