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
describe("runConfiguredHook (rf-fuwy liveness executor)", () => {
  it("reads a deny decision from a working hook", () => {
    // A stand-in hook that emits the exact envelope a real deny produces.
    const cmd = `printf '%s' '{"hookSpecificOutput":{"permissionDecision":"deny"}}'`;
    const r = runConfiguredHook(cmd, "rm -rf / --no-preserve-root");
    expect(r.status).toBe(0);
    expect(r.decision).toBe("deny");
    expect(r.error).toBeUndefined();
  });

  it("reads an allow decision from a permissive hook", () => {
    const cmd = `printf '%s' '{"hookSpecificOutput":{"permissionDecision":"allow"}}'`;
    const r = runConfiguredHook(cmd, "echo hello");
    expect(r.status).toBe(0);
    expect(r.decision).toBe("allow");
  });

  it("surfaces an inert gate: a command that does not resolve exits 127 with no decision", () => {
    // This is the npx-install failure mode: the configured command is not on
    // PATH, so it exits 127 — which Claude Code treats as a silent allow, and
    // which verify must therefore report as a hard failure.
    const cmd = "rafter-does-not-exist-9c1f hook pretool";
    const r = runConfiguredHook(cmd, "rm -rf / --no-preserve-root");
    expect(r.status).toBe(127);
    expect(r.decision).toBeNull();
  });

  it("reports no decision when the hook emits non-JSON", () => {
    const cmd = `printf '%s' 'not json at all'`;
    const r = runConfiguredHook(cmd, "echo hi");
    expect(r.decision).toBeNull();
  });
});
