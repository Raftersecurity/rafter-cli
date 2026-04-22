import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { SESSION_START_DIRECTIVE } from "../src/commands/hook/session-start.js";

// Runs the compiled CLI via tsx so we exercise the real commander wiring.
const CLI = path.resolve(__dirname, "..", "src", "index.ts");

function runSessionStart(): { stdout: string; stderr: string } {
  const stdout = execFileSync("npx", ["tsx", CLI, "hook", "session-start"], {
    input: JSON.stringify({ hook_event_name: "SessionStart", source: "startup" }),
    encoding: "utf-8",
    stdio: ["pipe", "pipe", "pipe"],
  });
  return { stdout, stderr: "" };
}

describe("rafter hook session-start", () => {
  it("emits hookSpecificOutput with SessionStart event + directive", () => {
    const { stdout } = runSessionStart();
    const parsed = JSON.parse(stdout);
    expect(parsed).toHaveProperty("hookSpecificOutput");
    expect(parsed.hookSpecificOutput.hookEventName).toBe("SessionStart");
    expect(parsed.hookSpecificOutput.additionalContext).toBe(SESSION_START_DIRECTIVE);
  });

  it("directive stays lean — under 80 words — to keep per-session token cost low", () => {
    const wordCount = SESSION_START_DIRECTIVE.split(/\s+/).filter(Boolean).length;
    expect(wordCount).toBeLessThan(80);
  });

  it("directive mentions the two organic uptake levers: `rafter scan local` and rafter-secure-design", () => {
    expect(SESSION_START_DIRECTIVE).toContain("rafter scan local");
    expect(SESSION_START_DIRECTIVE).toContain("rafter-secure-design");
  });
});
