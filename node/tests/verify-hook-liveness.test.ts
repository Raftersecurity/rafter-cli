import { describe, it, expect } from "vitest";
import { runConfiguredHook } from "../src/commands/agent/verify.js";

/**
 * rf-fuwy: `agent verify` must EXECUTE the configured PreToolUse hook, not just
 * read that it is configured. These are the positive and negative controls for
 * that executor — a check nobody has tried to break has not been tested.
 *
 * `runConfiguredHook` runs the command string through `sh -c` (exactly how Claude
 * Code invokes a shell-form hook) with a synthetic payload and reports the
 * permissionDecision it emitted.
 */
// These tests spawn real subprocesses, which is inherently environment-sensitive
// under process pressure (the very condition the product-level retry addresses).
// A per-test retry keeps a transient spawn hiccup from flaking the gate's own
// tests red — it does not mask a real failure, which reproduces on every attempt.
describe("runConfiguredHook (rf-fuwy liveness executor)", { retry: 3 }, () => {
  // The decision is what carries the meaning — assert that, not the exact exit
  // code. `runConfiguredHook` retries a transient spawn failure, so a working
  // hook returns its decision reliably; asserting `status === 0` is fragile under
  // CI process pressure (spawnSync can return a null status on a resource hiccup).

  it("reads a deny decision from a working hook", () => {
    // A stand-in hook that emits the exact envelope a real deny produces.
    const cmd = `printf '%s' '{"hookSpecificOutput":{"permissionDecision":"deny"}}'`;
    const r = runConfiguredHook(cmd, "rm -rf / --no-preserve-root");
    expect(r.decision).toBe("deny");
    expect(r.error).toBeUndefined();
  });

  it("reads an allow decision from a permissive hook", () => {
    const cmd = `printf '%s' '{"hookSpecificOutput":{"permissionDecision":"allow"}}'`;
    const r = runConfiguredHook(cmd, "echo hello");
    expect(r.decision).toBe("allow");
  });

  it("surfaces an inert gate: a command that does not resolve yields no decision and no success", () => {
    // This is the npx-install failure mode: the configured command is not on
    // PATH, so it exits 127 — which Claude Code treats as a silent allow, and
    // which verify must therefore report as a hard failure. What matters is that
    // it produced NO decision and did NOT exit 0 (127 through the shell, or a
    // spawn error).
    const cmd = "rafter-does-not-exist-9c1f hook pretool";
    const r = runConfiguredHook(cmd, "rm -rf / --no-preserve-root");
    expect(r.decision).toBeNull();
    expect(r.status).not.toBe(0);
  });

  it("reports no decision when the hook emits non-JSON", () => {
    const cmd = `printf '%s' 'not json at all'`;
    const r = runConfiguredHook(cmd, "echo hi");
    expect(r.decision).toBeNull();
  });
});
