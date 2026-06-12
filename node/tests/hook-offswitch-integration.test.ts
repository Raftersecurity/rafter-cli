import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

// End-to-end coverage of the config-driven hook off-switch through the REAL
// built CLI (`rafter hook pretool`). The security-critical assertion is that a
// project-local `.rafter.yml` can NOT disable the hook (secure-design D1).

const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_ENTRY = path.join(PROJECT_ROOT, "dist", "index.js");

const SECRET_WRITE = JSON.stringify({
  tool_name: "Write",
  tool_input: { content: "aws_key = AKIAIOSFODNN7EXAMPLE" },
});

function runHook(cwd: string, env: Record<string, string> = {}): { decision: string } {
  const r = spawnSync(`node ${CLI_ENTRY} hook pretool`, {
    cwd,
    input: SECRET_WRITE,
    encoding: "utf-8",
    shell: true,
    timeout: 30_000,
    // Isolate HOME so the developer's real ~/.rafter/config.json can't change the result.
    env: { ...process.env, HOME: cwd, XDG_CONFIG_HOME: path.join(cwd, ".config"), ...env },
  });
  const out = JSON.parse(r.stdout || "{}");
  return { decision: out.hookSpecificOutput?.permissionDecision ?? "unknown" };
}

describe("hook off-switch — end to end via the real CLI", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-offswitch-"));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("default: a staged secret is DENIED", () => {
    expect(runHook(dir).decision).toBe("deny");
  });

  it("RAFTER_DISABLE_HOOKS=1: ALLOWED", () => {
    expect(runHook(dir, { RAFTER_DISABLE_HOOKS: "1" }).decision).toBe("allow");
  });

  it("RAFTER_DISABLE_SECRET_SCAN=1: ALLOWED (secret scan off)", () => {
    expect(runHook(dir, { RAFTER_DISABLE_SECRET_SCAN: "1" }).decision).toBe("allow");
  });

  // ── The security property ────────────────────────────────────────────────
  it("SECURITY: a project-local .rafter.yml CANNOT disable the hook", () => {
    // A hostile repo ships every plausible disable shape in project-local config.
    fs.writeFileSync(
      path.join(dir, ".rafter.yml"),
      "hooks:\n  enabled: false\n  secretScan: false\n  commandPolicy: false\n",
    );
    // Also the backend flat-file location, which is likewise repo-local.
    fs.mkdirSync(path.join(dir, ".rafter"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".rafter", "config.yml"), "hooks:\n  enabled: false\n");

    // Still denied — the project-local file is never a trusted disable source.
    expect(runHook(dir).decision).toBe("deny");
  });

  it("SECURITY: global config (trusted) CAN disable — ALLOWED", () => {
    // The user-owned ~/.rafter/config.json (HOME is isolated to `dir`) is trusted.
    fs.mkdirSync(path.join(dir, ".rafter"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, ".rafter", "config.json"),
      JSON.stringify({ version: "1", agent: { hooks: { enabled: false } } }),
    );
    expect(runHook(dir).decision).toBe("allow");
  });
});
