import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";
import { spawnSync } from "child_process";
import { fileURLToPath } from "url";
import { randomBytes } from "crypto";

/**
 * Tests for `rafter skill list / install / uninstall`. Each test uses a fake
 * HOME so on-disk side effects are observable and isolated from the dev env.
 */

vi.setConfig({ testTimeout: 30_000 });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_ENTRY = path.join(PROJECT_ROOT, "dist", "index.js");

function makeHome(): string {
  const dir = path.join(os.tmpdir(), `rafter-skill-${Date.now()}-${randomBytes(4).toString("hex")}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function run(args: string, home: string): { stdout: string; stderr: string; code: number } {
  const r = spawnSync(`node ${CLI_ENTRY} ${args}`, {
    cwd: PROJECT_ROOT,
    encoding: "utf-8",
    timeout: 15_000,
    shell: true,
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: path.join(home, ".config") },
    stdio: ["pipe", "pipe", "pipe"],
  });
  return { stdout: r.stdout || "", stderr: r.stderr || "", code: r.status ?? 1 };
}

describe("rafter skill list", () => {
  let home: string;
  beforeEach(() => { home = makeHome(); });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  it("--json lists bundled skills and empty installations when nothing exists", () => {
    const r = run("skill list --json", home);
    expect(r.code).toBe(0);
    const payload = JSON.parse(r.stdout);
    const names = payload.skills.map((s: any) => s.name);
    expect(names).toEqual(
      expect.arrayContaining([
        "rafter",
        "rafter-agent-security",
        "rafter-secure-design",
        "rafter-code-review",
      ]),
    );
    // With a pristine fake HOME, nothing is installed.
    for (const row of payload.installations) {
      expect(row.installed).toBe(false);
    }
  });

  it("--installed filters to only installed (skill, platform) pairs", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    run("skill install rafter-secure-design --platform claude-code", home);
    const r = run("skill list --json --installed", home);
    expect(r.code).toBe(0);
    const payload = JSON.parse(r.stdout);
    expect(payload.installations.length).toBeGreaterThan(0);
    expect(payload.installations.every((row: any) => row.installed)).toBe(true);
    expect(payload.installations[0].name).toBe("rafter-secure-design");
    expect(payload.installations[0].platform).toBe("claude-code");
  });

  it("rejects unknown --platform", () => {
    const r = run("skill list --platform bogus", home);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/Unknown platform/);
  });
});

describe("rafter skill install / uninstall", () => {
  let home: string;
  beforeEach(() => { home = makeHome(); });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  it("install → uninstall → reinstall round-trip for claude-code", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    const skillPath = path.join(home, ".claude", "skills", "rafter-secure-design", "SKILL.md");

    const first = run("skill install rafter-secure-design --platform claude-code", home);
    expect(first.code).toBe(0);
    expect(fs.existsSync(skillPath)).toBe(true);
    expect(fs.readFileSync(skillPath, "utf-8")).toContain("rafter-secure-design");

    const un = run("skill uninstall rafter-secure-design --platform claude-code", home);
    expect(un.code).toBe(0);
    expect(fs.existsSync(skillPath)).toBe(false);

    const second = run("skill install rafter-secure-design --platform claude-code", home);
    expect(second.code).toBe(0);
    expect(fs.existsSync(skillPath)).toBe(true);
  });

  it("install is idempotent: second call overwrites without duplicating", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    const skillPath = path.join(home, ".claude", "skills", "rafter", "SKILL.md");
    run("skill install rafter --platform claude-code", home);
    const first = fs.readFileSync(skillPath, "utf-8");
    run("skill install rafter --platform claude-code", home);
    const second = fs.readFileSync(skillPath, "utf-8");
    expect(second).toBe(first);
  });

  it("install with no --platform installs to every detected platform", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    const r = run("skill install rafter-code-review", home);
    expect(r.code).toBe(0);
    expect(fs.existsSync(path.join(home, ".claude", "skills", "rafter-code-review", "SKILL.md"))).toBe(true);
    expect(fs.existsSync(path.join(home, ".cursor", "rules", "rafter-code-review.mdc"))).toBe(true);
    // Openclaw and codex are not detected, so no files there:
    expect(fs.existsSync(path.join(home, ".openclaw", "skills", "rafter-code-review.md"))).toBe(false);
  });

  it("install exits 2 when no platform detected and --force absent", () => {
    const r = run("skill install rafter-secure-design", home);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/No supported platform detected/);
  });

  it("install --force installs to all known platforms when none detected", () => {
    const r = run("skill install rafter --force", home);
    expect(r.code).toBe(0);
    expect(fs.existsSync(path.join(home, ".claude", "skills", "rafter", "SKILL.md"))).toBe(true);
    expect(fs.existsSync(path.join(home, ".cursor", "rules", "rafter.mdc"))).toBe(true);
    expect(fs.existsSync(path.join(home, ".openclaw", "skills", "rafter.md"))).toBe(true);
  });

  it("install --to <dir> writes to a base directory (<dir>/<name>/SKILL.md)", () => {
    const dest = path.join(home, "custom-skills");
    const r = run(`skill install rafter --to ${dest}`, home);
    expect(r.code).toBe(0);
    expect(fs.existsSync(path.join(dest, "rafter", "SKILL.md"))).toBe(true);
  });

  it("install --to <file.md> writes to the exact path given", () => {
    const dest = path.join(home, "custom", "my-skill.md");
    const r = run(`skill install rafter --to ${dest}`, home);
    expect(r.code).toBe(0);
    expect(fs.existsSync(dest)).toBe(true);
    expect(fs.readFileSync(dest, "utf-8")).toContain("name: rafter");
  });

  it("openclaw uses flat-file naming (~/.openclaw/skills/<name>.md)", () => {
    fs.mkdirSync(path.join(home, ".openclaw"), { recursive: true });
    const r = run("skill install rafter-agent-security --platform openclaw", home);
    expect(r.code).toBe(0);
    const expected = path.join(home, ".openclaw", "skills", "rafter-agent-security.md");
    expect(fs.existsSync(expected)).toBe(true);
  });

  it("cursor uses .mdc extension in ~/.cursor/rules/", () => {
    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    const r = run("skill install rafter --platform cursor", home);
    expect(r.code).toBe(0);
    const expected = path.join(home, ".cursor", "rules", "rafter.mdc");
    expect(fs.existsSync(expected)).toBe(true);
  });

  it("unknown skill exits 1 and reports available names", () => {
    const r = run("skill install bogus-skill", home);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/Unknown skill: bogus-skill/);
    expect(r.stderr).toMatch(/rafter-secure-design|rafter-code-review/);
  });

  it("unknown platform in --platform exits 1", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    const r = run("skill install rafter --platform whatever", home);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/Unknown platform/);
  });

  it("uninstall with no --platform removes from every platform where installed", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    run("skill install rafter", home);
    expect(fs.existsSync(path.join(home, ".claude", "skills", "rafter", "SKILL.md"))).toBe(true);
    expect(fs.existsSync(path.join(home, ".cursor", "rules", "rafter.mdc"))).toBe(true);
    const r = run("skill uninstall rafter", home);
    expect(r.code).toBe(0);
    expect(fs.existsSync(path.join(home, ".claude", "skills", "rafter", "SKILL.md"))).toBe(false);
    expect(fs.existsSync(path.join(home, ".cursor", "rules", "rafter.mdc"))).toBe(false);
  });

  it("uninstall reports no-op when skill isn't installed anywhere", () => {
    const r = run("skill uninstall rafter", home);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/not installed on any known platform/);
  });

  it("records skillInstallations state in ~/.rafter/config.json", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    run("skill install rafter-secure-design --platform claude-code", home);
    const cfgPath = path.join(home, ".rafter", "config.json");
    const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
    expect(cfg.skillInstallations?.["claude-code"]?.["rafter-secure-design"]?.enabled).toBe(true);
    expect(cfg.skillInstallations?.["claude-code"]?.["rafter-secure-design"]?.version).toBe("0.1.0");

    run("skill uninstall rafter-secure-design --platform claude-code", home);
    const cfg2 = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
    expect(cfg2.skillInstallations?.["claude-code"]?.["rafter-secure-design"]?.enabled).toBe(false);
  });
});
