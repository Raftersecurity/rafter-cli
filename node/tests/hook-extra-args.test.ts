import { describe, it, expect } from "vitest";
import { spawnSync } from "child_process";
import path from "path";

// Regression: the host harness may append extra flags/args to the hook command.
// Claude Code appends `--hook-json <data>`; hook input comes from stdin, so the
// CLI must tolerate (discard) the extra flag instead of erroring (#180).

const CLI_ENTRY = path.join(path.resolve(__dirname, ".."), "dist", "index.js");
const PRETOOL_IN = JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" } });
const POSTTOOL_IN = JSON.stringify({ tool_name: "Bash", tool_response: { output: "ok" } });

function runHook(args: string): { code: number; out: any } {
  const r = spawnSync(`node ${CLI_ENTRY} ${args}`, {
    input: args.includes("posttool") ? POSTTOOL_IN : PRETOOL_IN,
    encoding: "utf-8",
    shell: true,
    timeout: 30_000,
  });
  return { code: r.status ?? -1, out: JSON.parse(r.stdout || "{}") };
}

describe("hook commands tolerate harness-appended flags (#180)", () => {
  it("pretool accepts --hook-json and still returns a decision", () => {
    const { code, out } = runHook("hook pretool --hook-json '{}'");
    expect(code).toBe(0);
    expect(out.hookSpecificOutput?.permissionDecision).toBe("allow");
  });

  it("posttool accepts --hook-json", () => {
    const { code, out } = runHook("hook posttool --hook-json '{\"x\":1}'");
    expect(code).toBe(0);
    expect(out.hookSpecificOutput?.hookEventName).toBe("PostToolUse");
  });

  it("a real option (--format) is still honored, not swallowed", () => {
    // gemini "allow" emits an empty object, distinct from the claude shape.
    const r = spawnSync(`node ${CLI_ENTRY} hook pretool --format gemini --hook-json '{}'`, {
      input: PRETOOL_IN, encoding: "utf-8", shell: true, timeout: 30_000,
    });
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toBe("{}");
  });

  it("still works with no extra flag (unchanged behavior)", () => {
    const { code, out } = runHook("hook pretool");
    expect(code).toBe(0);
    expect(out.hookSpecificOutput?.permissionDecision).toBe("allow");
  });
});
