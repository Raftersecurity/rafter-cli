import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";
import { spawnSync } from "child_process";
import { fileURLToPath } from "url";
import { randomBytes } from "crypto";

/**
 * Tests for `rafter agent uninstall` — the bulk revert of `rafter agent init`.
 * Each test gets a fake HOME so we can inspect the on-disk side effects
 * without clobbering the developer's real configs.
 */

vi.setConfig({ testTimeout: 30_000 });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_ENTRY = path.join(PROJECT_ROOT, "dist", "index.js");

function makeHome(): string {
  const dir = path.join(os.tmpdir(), `rafter-uninstall-${Date.now()}-${randomBytes(4).toString("hex")}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function runCli(args: string, home: string): { stdout: string; stderr: string; code: number } {
  const r = spawnSync(`node ${CLI_ENTRY} ${args}`, {
    cwd: home,
    encoding: "utf-8",
    timeout: 15_000,
    shell: true,
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: path.join(home, ".config") },
    stdio: ["pipe", "pipe", "pipe"],
  });
  return { stdout: r.stdout || "", stderr: r.stderr || "", code: r.status ?? 1 };
}

function snapshotTree(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (dir: string) => {
    if (!fs.existsSync(dir)) return;
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(full);
      else if (ent.isFile()) {
        out[path.relative(root, full)] = fs.readFileSync(full, "utf-8");
      }
    }
  };
  walk(root);
  return out;
}

describe("rafter agent uninstall", () => {
  let home: string;

  beforeEach(() => {
    home = makeHome();
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("info-exits with no changes when nothing is installed", () => {
    const r = runCli("agent uninstall --yes", home);
    expect(r.code).toBe(0);
    expect(r.stdout + r.stderr).toMatch(/Nothing to uninstall/i);
  });

  it("--dry-run writes nothing", () => {
    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    runCli("agent enable cursor.mcp", home);
    const before = snapshotTree(home);

    const r = runCli("agent uninstall --dry-run --yes", home);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/DRY RUN/);
    expect(r.stdout).toMatch(/cursor\.mcp/);

    const after = snapshotTree(home);
    expect(after).toEqual(before);
  });

  it("--yes skips confirmation and reverses installed components", () => {
    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    runCli("agent enable cursor.mcp", home);
    runCli("agent enable claude-code.mcp", home);
    runCli("agent enable claude-code.instructions", home);

    expect(fs.existsSync(path.join(home, ".cursor", "mcp.json"))).toBe(true);

    const r = runCli("agent uninstall --yes", home);
    expect(r.code).toBe(0);

    // cursor.mcp uninstall removes the rafter entry but leaves the file (other entries may exist).
    const cursorCfg = JSON.parse(fs.readFileSync(path.join(home, ".cursor", "mcp.json"), "utf-8"));
    expect(cursorCfg.mcpServers?.rafter).toBeUndefined();

    // claude-code.mcp creates <cwd>/.mcp.json — when rafter is the only entry, uninstall removes the file.
    expect(fs.existsSync(path.join(home, ".mcp.json"))).toBe(false);

    // Instruction marker block is gone.
    const claudeMd = path.join(home, ".claude", "CLAUDE.md");
    if (fs.existsSync(claudeMd)) {
      expect(fs.readFileSync(claudeMd, "utf-8")).not.toMatch(/rafter:start/);
    }
  });

  it("preserves pre-existing non-rafter hook entries", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    const settingsPath = path.join(home, ".claude", "settings.json");
    // User's pre-existing hook from some other tool.
    fs.writeFileSync(
      settingsPath,
      JSON.stringify(
        {
          hooks: {
            PreToolUse: [
              { matcher: "Bash", hooks: [{ type: "command", command: "some-other-tool guard" }] },
            ],
          },
        },
        null,
        2,
      ),
    );

    runCli("agent enable claude-code.hooks", home);
    let s = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    const preCmds = (s.hooks.PreToolUse as any[]).flatMap((e) => e.hooks.map((h: any) => h.command));
    expect(preCmds).toContain("some-other-tool guard");
    expect(preCmds).toContain("rafter hook pretool");

    const r = runCli("agent uninstall --yes", home);
    expect(r.code).toBe(0);

    s = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    const after = (s.hooks?.PreToolUse ?? []).flatMap((e: any) => e.hooks.map((h: any) => h.command));
    expect(after).toContain("some-other-tool guard");
    expect(after).not.toContain("rafter hook pretool");
  });

  it("round-trip: install → uninstall returns the filesystem to its prior shape", () => {
    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    // Capture filesystem state BEFORE any rafter writes.
    const before = snapshotTree(home);

    runCli("agent enable cursor.mcp", home);
    runCli("agent enable claude-code.instructions", home);
    runCli("agent enable claude-code.mcp", home);

    const r = runCli("agent uninstall --yes", home);
    expect(r.code).toBe(0);

    // Everything rafter wrote should be gone. ~/.rafter/config.json IS allowed
    // to exist (it records component state) — we filter it out before comparing.
    const after = snapshotTree(home);
    for (const key of Object.keys(after)) {
      if (key.startsWith(".rafter/")) delete after[key];
    }
    expect(after).toEqual(before);
  });

  it("without --purge preserves ~/.rafter/audit.jsonl and ~/.rafter/config.json", () => {
    const rafterDir = path.join(home, ".rafter");
    fs.mkdirSync(rafterDir, { recursive: true });
    fs.writeFileSync(path.join(rafterDir, "audit.jsonl"), '{"event":"test"}\n');
    fs.writeFileSync(path.join(rafterDir, "config.json"), '{"keep":true}');

    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    runCli("agent enable cursor.mcp", home);

    const r = runCli("agent uninstall --yes", home);
    expect(r.code).toBe(0);

    expect(fs.existsSync(path.join(rafterDir, "audit.jsonl"))).toBe(true);
    expect(fs.readFileSync(path.join(rafterDir, "audit.jsonl"), "utf-8")).toContain("test");
    expect(fs.existsSync(path.join(rafterDir, "config.json"))).toBe(true);
  });

  it("--purge removes ~/.rafter including audit log", () => {
    const rafterDir = path.join(home, ".rafter");
    fs.mkdirSync(path.join(rafterDir, "bin"), { recursive: true });
    fs.writeFileSync(path.join(rafterDir, "audit.jsonl"), '{"event":"test"}\n');
    fs.writeFileSync(path.join(rafterDir, "config.json"), '{"keep":true}');
    fs.writeFileSync(path.join(rafterDir, "bin", "betterleaks"), "fake binary");

    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    runCli("agent enable cursor.mcp", home);

    const r = runCli("agent uninstall --purge --yes", home);
    expect(r.code).toBe(0);

    expect(fs.existsSync(path.join(rafterDir, "audit.jsonl"))).toBe(false);
    expect(fs.existsSync(path.join(rafterDir, "bin"))).toBe(false);
  });

  it("is idempotent — second run is a no-op", () => {
    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    runCli("agent enable cursor.mcp", home);
    runCli("agent uninstall --yes", home);

    const before = snapshotTree(home);
    const r = runCli("agent uninstall --yes", home);
    expect(r.code).toBe(0);
    expect(r.stdout + r.stderr).toMatch(/Nothing to uninstall/i);
    const after = snapshotTree(home);
    expect(after).toEqual(before);
  });
});
