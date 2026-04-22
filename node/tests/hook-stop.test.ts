import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { STOP_DIRECTIVE, transcriptTouchedRafter } from "../src/commands/hook/stop.js";

const CLI = path.resolve(__dirname, "..", "src", "index.ts");

function runStop(input: Record<string, any>): string {
  return execFileSync("npx", ["tsx", CLI, "hook", "stop"], {
    input: JSON.stringify(input),
    encoding: "utf-8",
    stdio: ["pipe", "pipe", "pipe"],
  });
}

describe("rafter hook stop", () => {
  it("blocks completion with STOP_DIRECTIVE when no rafter engagement in transcript", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "stop-"));
    const transcript = path.join(dir, "t.jsonl");
    writeFileSync(transcript, "", "utf-8");
    try {
      const out = runStop({ transcript_path: transcript, stop_hook_active: false });
      const parsed = JSON.parse(out);
      expect(parsed.decision).toBe("block");
      expect(parsed.reason).toBe(STOP_DIRECTIVE);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("allows completion when transcript shows `rafter scan local`", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "stop-"));
    const transcript = path.join(dir, "t.jsonl");
    writeFileSync(transcript, JSON.stringify({
      message: { content: [{ type: "tool_use", name: "Bash", input: { command: "rafter scan local ." } }] },
    }) + "\n", "utf-8");
    try {
      const out = runStop({ transcript_path: transcript, stop_hook_active: false });
      expect(JSON.parse(out)).toEqual({});
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("allows completion when transcript shows a rafter-* Skill invocation", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "stop-"));
    const transcript = path.join(dir, "t.jsonl");
    writeFileSync(transcript, JSON.stringify({
      message: { content: [{ type: "tool_use", name: "Skill", input: { skill: "rafter-secure-design" } }] },
    }) + "\n", "utf-8");
    try {
      const out = runStop({ transcript_path: transcript, stop_hook_active: false });
      expect(JSON.parse(out)).toEqual({});
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("always allows when stop_hook_active=true (prevents infinite loops)", () => {
    const out = runStop({ transcript_path: "/dev/null", stop_hook_active: true });
    expect(JSON.parse(out)).toEqual({});
  });

  it("fails open if transcript_path is missing — would rather never trap the agent", () => {
    const out = runStop({ stop_hook_active: false });
    // No transcript → block (since we can't verify engagement). That's the intended
    // first-stop behavior; verify we produced a well-formed block response.
    const parsed = JSON.parse(out);
    expect(parsed.decision).toBe("block");
  });

  it("transcriptTouchedRafter returns false for missing files (fail-open on IO error)", () => {
    expect(transcriptTouchedRafter("/no/such/path.jsonl")).toBe(false);
  });

  it("detects rafter engagement inside a subagent transcript (Claude Code delegation)", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "stop-"));
    const transcript = path.join(dir, "main.jsonl");
    writeFileSync(transcript, "", "utf-8");
    // Subagent path: <dir>/main/subagents/*.jsonl
    const subDir = path.join(dir, "main", "subagents");
    mkdirSync(subDir, { recursive: true });
    writeFileSync(path.join(subDir, "sub.jsonl"), JSON.stringify({
      message: { content: [{ type: "tool_use", name: "Skill", input: { skill: "rafter-secure-design" } }] },
    }) + "\n", "utf-8");
    try {
      const out = runStop({ transcript_path: transcript, stop_hook_active: false });
      expect(JSON.parse(out)).toEqual({});
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("STOP_DIRECTIVE stays lean — under 70 words", () => {
    const words = STOP_DIRECTIVE.split(/\s+/).filter(Boolean).length;
    expect(words).toBeLessThan(70);
  });
});
