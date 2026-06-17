import { describe, it, expect } from "vitest";
import { spawn } from "child_process";
import path from "path";

// Regression: `rafter hook pretool/posttool` must not hang when stdin is held
// open with no EOF (e.g. a harness that wires up a pipe but never writes/closes
// it). The read is bounded by a timeout, but the bound only protects OUTPUT
// latency — the process itself must also EXIT. A piped stdin left in flowing
// mode keeps the Node event loop alive forever, so the hook hung indefinitely
// AFTER emitting its decision. The fix pauses stdin on the timeout path.
//
// We pin the bound low via RAFTER_HOOK_STDIN_TIMEOUT_MS so the test is fast.

const CLI_ENTRY = path.join(path.resolve(__dirname, ".."), "dist", "index.js");
const BOUND_MS = 300;

/**
 * Spawn the real hook subcommand, hold stdin open (never write, never end),
 * and resolve with how it terminated.
 */
function runWithOpenStdin(
  sub: "pretool" | "posttool",
): Promise<{ code: number | null; stdout: string; timedOut: boolean }> {
  return new Promise((resolve) => {
    const child = spawn("node", [CLI_ENTRY, "hook", sub, "--format", "claude"], {
      stdio: ["pipe", "pipe", "ignore"],
      env: { ...process.env, RAFTER_HOOK_STDIN_TIMEOUT_MS: String(BOUND_MS) },
    });

    let stdout = "";
    child.stdout.setEncoding("utf-8");
    child.stdout.on("data", (c) => { stdout += c; });

    // Hard backstop: if the process is still alive well past its own bound,
    // it hung — record that and kill it so the test fails loudly (not by
    // timing out the whole suite).
    const backstop = setTimeout(() => {
      child.kill("SIGKILL");
      resolve({ code: null, stdout, timedOut: true });
    }, BOUND_MS + 4000);

    child.on("exit", (code) => {
      clearTimeout(backstop);
      resolve({ code, stdout, timedOut: false });
    });

    // Intentionally never call child.stdin.end() — stdin stays open with no EOF.
  });
}

describe("hook stdin read is bounded — process exits even when stdin never closes", () => {
  it("pretool: exits (fail-open allow) instead of hanging", async () => {
    const r = await runWithOpenStdin("pretool");
    expect(r.timedOut).toBe(false);
    expect(r.code).toBe(0);
    const out = JSON.parse(r.stdout || "{}");
    expect(out.hookSpecificOutput?.permissionDecision).toBe("allow");
  });

  it("posttool: exits instead of hanging", async () => {
    const r = await runWithOpenStdin("posttool");
    expect(r.timedOut).toBe(false);
    expect(r.code).toBe(0);
    const out = JSON.parse(r.stdout || "{}");
    expect(out.hookSpecificOutput?.hookEventName).toBe("PostToolUse");
  });
});
