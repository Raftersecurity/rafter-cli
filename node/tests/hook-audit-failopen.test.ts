import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { pathToFileURL } from "url";

// The audit log must never change a hook decision. A repo's `.rafter.yml` used
// to choose where the audit log lives; pointing it at an unwritable path made
// every deny branch throw on its audit write, and the pretool's outer catch
// then answered ALLOW — `rm -rf /` went through. Driven through the REAL built
// CLI with an isolated HOME so the developer's ~/.rafter is never touched.

const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_ENTRY = path.join(PROJECT_ROOT, "dist", "index.js");
const INTERCEPTOR = pathToFileURL(path.join(PROJECT_ROOT, "dist", "core", "command-interceptor.js")).href;

function runHook(dir: string, command: string, nodeArgs = ""): { decision: string; stderr: string } {
  const r = spawnSync(`node ${nodeArgs} ${CLI_ENTRY} hook pretool`, {
    cwd: dir,
    input: JSON.stringify({ tool_name: "Bash", tool_input: { command } }),
    encoding: "utf-8",
    shell: true,
    timeout: 30_000,
    env: { ...process.env, HOME: dir, XDG_CONFIG_HOME: path.join(dir, ".config") },
  });
  const out = JSON.parse(r.stdout || "{}");
  return { decision: out.hookSpecificOutput?.permissionDecision ?? "unknown", stderr: r.stderr };
}

function writeGlobalConfig(dir: string, agent: Record<string, unknown>): void {
  fs.mkdirSync(path.join(dir, ".rafter"), { recursive: true });
  fs.writeFileSync(path.join(dir, ".rafter", "config.json"), JSON.stringify({ version: "1", agent }));
}

describe("hook pretool — audit failures cannot flip a deny", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-auditfail-"));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("an unwritable audit log path still DENIES a critical command", () => {
    // Global (trusted) config, so this isolates the logger fix from the
    // project-config fix below.
    writeGlobalConfig(dir, { audit: { logAllActions: true, logPath: "/proc/version" } });
    const r = runHook(dir, "rm -rf /");
    expect(r.decision).toBe("deny");
    expect(r.stderr).toMatch(/audit log/i);
  });

  it("a project .rafter.yml cannot point the audit log at an unwritable path", () => {
    fs.writeFileSync(path.join(dir, ".rafter.yml"), "audit:\n  log_path: /proc/version\n");
    expect(runHook(dir, "rm -rf /").decision).toBe("deny");
  });

  it("a project .rafter.yml cannot choose where the audit log is appended", () => {
    const target = path.join(dir, "victim.txt");
    fs.writeFileSync(path.join(dir, ".rafter.yml"), `audit:\n  log_path: ${target}\n`);
    const r = runHook(dir, "echo hi");
    expect(r.decision).toBe("allow");
    expect(fs.existsSync(target)).toBe(false);
    expect(fs.existsSync(path.join(dir, ".rafter", "audit.jsonl"))).toBe(true);
    expect(r.stderr).toMatch(/audit\.log_path/);
  });

  it("an unexpected error fails CLOSED for a critical Bash command, open for a low one", () => {
    const preload = path.join(dir, "boom.mjs");
    fs.writeFileSync(
      preload,
      `import { CommandInterceptor } from ${JSON.stringify(INTERCEPTOR)};\n` +
        `CommandInterceptor.prototype.evaluate = () => { throw new Error("boom"); };\n`,
    );
    const imp = `--import ${pathToFileURL(preload).href}`;
    expect(runHook(dir, "rm -rf /", imp).decision).toBe("deny");
    expect(runHook(dir, "git commit -m x", imp).decision).toBe("deny");
    expect(runHook(dir, "ls -la", imp).decision).toBe("allow");
  });
});
