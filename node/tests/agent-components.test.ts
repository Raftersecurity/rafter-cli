import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";
import { spawnSync } from "child_process";
import { fileURLToPath } from "url";
import { randomBytes } from "crypto";

/**
 * Tests for `rafter agent list` / `enable` / `disable` — the granular component-control
 * commands. Each test gets a fake HOME so we can inspect the on-disk side effects
 * (and so we don't clobber the developer's real configs).
 */

vi.setConfig({ testTimeout: 30_000 });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_ENTRY = path.join(PROJECT_ROOT, "dist", "index.js");

function makeHome(): string {
  const dir = path.join(os.tmpdir(), `rafter-comp-${Date.now()}-${randomBytes(4).toString("hex")}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function runCli(args: string, home: string): { stdout: string; stderr: string; code: number } {
  // cwd=home so project-scope components (e.g. claude-code.mcp writes to
  // <cwd>/.mcp.json) are isolated inside the fake HOME.
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

describe("rafter agent list", () => {
  let home: string;

  beforeEach(() => {
    home = makeHome();
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("emits JSON with expected component shape", () => {
    const r = runCli("agent list --json", home);
    expect(r.code).toBe(0);
    const payload = JSON.parse(r.stdout);
    expect(Array.isArray(payload.components)).toBe(true);
    const byId = new Map(payload.components.map((c: any) => [c.id, c]));

    for (const id of [
      "claude-code.hooks",
      "claude-code.instructions",
      "claude-code.skills",
      "claude-code.mcp",
      "cursor.hooks",
      "cursor.mcp",
      "gemini.hooks",
      "gemini.mcp",
      "windsurf.hooks",
      "windsurf.mcp",
      "continue.hooks",
      "continue.mcp",
      "aider.mcp",
      "codex.hooks",
      "codex.skills",
      "openclaw.skills",
    ]) {
      const c = byId.get(id) as any;
      expect(c, `missing ${id}`).toBeDefined();
      expect(c.state).toMatch(/^(installed|not-installed|not-detected)$/);
      expect(["hooks", "mcp", "instructions", "skills"]).toContain(c.kind);
      expect(typeof c.path).toBe("string");
      expect(typeof c.detected).toBe("boolean");
      expect(typeof c.installed).toBe("boolean");
    }
  });

  it("reports state=not-detected for platforms whose dir is absent", () => {
    // Fake HOME has no platform dirs, so everything should be not-detected
    // except aider which uses HOME as its detect dir.
    const r = runCli("agent list --json", home);
    const payload = JSON.parse(r.stdout);
    const byId = new Map(payload.components.map((c: any) => [c.id, c]));
    expect((byId.get("cursor.mcp") as any).state).toBe("not-detected");
    expect((byId.get("gemini.mcp") as any).state).toBe("not-detected");
    // aider's "platform detected" is HOME which always exists
    expect((byId.get("aider.mcp") as any).detected).toBe(true);
  });

  it("--installed filters to only installed rows", () => {
    // Enable one component first, then verify --installed returns just that row
    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    runCli("agent enable cursor.mcp", home);
    const r = runCli("agent list --json --installed", home);
    const payload = JSON.parse(r.stdout);
    const ids = payload.components.map((c: any) => c.id);
    expect(ids).toContain("cursor.mcp");
    expect(payload.components.every((c: any) => c.installed)).toBe(true);
  });
});

describe("rafter agent enable / disable", () => {
  let home: string;

  beforeEach(() => {
    home = makeHome();
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("exits 1 and lists known IDs when given an unknown component", () => {
    const r = runCli("agent enable bogus.whatever", home);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/Unknown component: bogus.whatever/);
    expect(r.stderr).toMatch(/claude-code\.mcp|cursor\.mcp/);
  });

  it("exits 2 when platform is undetected and --force is not passed", () => {
    // No ~/.cursor dir → cursor.mcp is not detected
    const r = runCli("agent enable cursor.mcp", home);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/platform not detected/);
  });

  it("--force installs even when platform is undetected", () => {
    const r = runCli("agent enable cursor.mcp --force", home);
    expect(r.code).toBe(0);
    const mcp = JSON.parse(fs.readFileSync(path.join(home, ".cursor", "mcp.json"), "utf-8"));
    expect(mcp.mcpServers?.rafter).toMatchObject({ command: "rafter" });
  });

  it("cursor.mcp round-trips (install → disable leaves the file but removes entry)", () => {
    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    fs.writeFileSync(
      path.join(home, ".cursor", "mcp.json"),
      JSON.stringify({ mcpServers: { keep: { command: "keep" } } }, null, 2),
    );

    const enable = runCli("agent enable cursor.mcp", home);
    expect(enable.code).toBe(0);
    let cfg = JSON.parse(fs.readFileSync(path.join(home, ".cursor", "mcp.json"), "utf-8"));
    expect(cfg.mcpServers.rafter).toBeDefined();
    expect(cfg.mcpServers.keep).toBeDefined();

    const disable = runCli("agent disable cursor.mcp", home);
    expect(disable.code).toBe(0);
    cfg = JSON.parse(fs.readFileSync(path.join(home, ".cursor", "mcp.json"), "utf-8"));
    expect(cfg.mcpServers.rafter).toBeUndefined();
    // non-rafter entry preserved
    expect(cfg.mcpServers.keep).toBeDefined();
  });

  it("claude-code.mcp round-trips (install → disable leaves unrelated entries intact)", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    const mcpPath = path.join(home, ".mcp.json");
    fs.writeFileSync(
      mcpPath,
      JSON.stringify({ mcpServers: { keep: { command: "keep" } } }, null, 2),
    );

    const enable = runCli("agent enable claude-code.mcp", home);
    expect(enable.code).toBe(0);
    let cfg = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
    expect(cfg.mcpServers.rafter).toBeDefined();
    expect(cfg.mcpServers.keep).toBeDefined();

    const disable = runCli("agent disable claude-code.mcp", home);
    expect(disable.code).toBe(0);
    cfg = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
    expect(cfg.mcpServers.rafter).toBeUndefined();
    expect(cfg.mcpServers.keep).toBeDefined();
  });

  it("claude-code.mcp disable deletes the file when it becomes empty", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    const mcpPath = path.join(home, ".mcp.json");

    const enable = runCli("agent enable claude-code.mcp", home);
    expect(enable.code).toBe(0);
    expect(fs.existsSync(mcpPath)).toBe(true);

    const disable = runCli("agent disable claude-code.mcp", home);
    expect(disable.code).toBe(0);
    expect(fs.existsSync(mcpPath)).toBe(false);
  });

  it("claude-code.hooks install preserves non-rafter hook entries and is idempotent", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    const settingsPath = path.join(home, ".claude", "settings.json");
    fs.writeFileSync(
      settingsPath,
      JSON.stringify(
        {
          hooks: {
            PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "other hook" }] }],
          },
        },
        null,
        2,
      ),
    );

    runCli("agent enable claude-code.hooks", home);
    runCli("agent enable claude-code.hooks", home); // idempotent
    const s = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    const preCommands = (s.hooks.PreToolUse as any[]).flatMap((e) => e.hooks.map((h: any) => h.command));
    expect(preCommands).toContain("other hook");
    const rafterPreCount = preCommands.filter((c) => c === "rafter hook pretool").length;
    // Installer adds 2 PreToolUse entries (Bash + Write|Edit). Idempotent install
    // should still produce exactly 2, not 4.
    expect(rafterPreCount).toBe(2);
  });

  it("aider.mcp appends only once; disable strips the block", () => {
    const conf = path.join(home, ".aider.conf.yml");
    fs.writeFileSync(conf, "# pre-existing line\nmodel: gpt-5\n");

    runCli("agent enable aider.mcp", home);
    runCli("agent enable aider.mcp", home); // idempotent
    const after = fs.readFileSync(conf, "utf-8");
    const occurrences = (after.match(/rafter mcp serve/g) || []).length;
    expect(occurrences).toBe(1);
    expect(after).toContain("model: gpt-5");

    runCli("agent disable aider.mcp", home);
    const cleaned = fs.readFileSync(conf, "utf-8");
    expect(cleaned).not.toContain("rafter mcp serve");
    expect(cleaned).toContain("model: gpt-5");
  });

  it("records enabled=true/false in ~/.rafter/config.json for each toggle", () => {
    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    runCli("agent enable cursor.mcp", home);

    const cfgPath = path.join(home, ".rafter", "config.json");
    expect(fs.existsSync(cfgPath)).toBe(true);
    let cfg = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
    expect(cfg.agent?.components?.["cursor.mcp"]?.enabled).toBe(true);

    runCli("agent disable cursor.mcp", home);
    cfg = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
    expect(cfg.agent?.components?.["cursor.mcp"]?.enabled).toBe(false);
  });

  it("accepts 'claude.hooks' as an alias for 'claude-code.hooks'", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    const r = runCli("agent enable claude.hooks", home);
    expect(r.code).toBe(0);
    const settings = JSON.parse(fs.readFileSync(path.join(home, ".claude", "settings.json"), "utf-8"));
    expect(settings.hooks?.PreToolUse?.length).toBeGreaterThan(0);
  });

  it("claude-code.skills installs SKILL.md plus sibling docs/ folder, removes both on disable", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    const enable = runCli("agent enable claude-code.skills", home);
    expect(enable.code).toBe(0);

    // Each skill that has a docs/ folder in source must mirror it on install,
    // because SKILL.md tells the agent to read sibling docs/<x>.md by relative
    // path. Without this, those references resolve to nothing.
    const skillsDir = path.join(home, ".claude", "skills");
    for (const name of [
      "rafter",
      "rafter-secure-design",
      "rafter-code-review",
      "rafter-skill-review",
    ]) {
      const skillDir = path.join(skillsDir, name);
      expect(fs.existsSync(path.join(skillDir, "SKILL.md")), `missing SKILL.md for ${name}`).toBe(true);
      const docsDir = path.join(skillDir, "docs");
      expect(fs.existsSync(docsDir), `missing docs/ for ${name}`).toBe(true);
      expect(fs.readdirSync(docsDir).length, `empty docs/ for ${name}`).toBeGreaterThan(0);
    }

    // SKILL.md sub-doc references must resolve on disk
    const rafterSkill = fs.readFileSync(path.join(skillsDir, "rafter", "SKILL.md"), "utf-8");
    const refs = [...rafterSkill.matchAll(/`docs\/([\w-]+\.md)`/g)].map((m) => m[1]);
    expect(refs.length, "expected SKILL.md to reference docs/").toBeGreaterThan(0);
    for (const ref of refs) {
      expect(
        fs.existsSync(path.join(skillsDir, "rafter", "docs", ref)),
        `SKILL.md references docs/${ref} but it was not installed`,
      ).toBe(true);
    }

    const disable = runCli("agent disable claude-code.skills", home);
    expect(disable.code).toBe(0);
    for (const name of ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"]) {
      const skillDir = path.join(skillsDir, name);
      expect(fs.existsSync(path.join(skillDir, "SKILL.md")), `${name}/SKILL.md not removed`).toBe(false);
      expect(fs.existsSync(path.join(skillDir, "docs")), `${name}/docs not removed`).toBe(false);
    }
  });

  it("claude-code.instructions strip leaves surrounding content intact", () => {
    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
    const filePath = path.join(home, ".claude", "CLAUDE.md");
    fs.writeFileSync(filePath, "# My notes\nkeep this\n");

    runCli("agent enable claude-code.instructions", home);
    const after = fs.readFileSync(filePath, "utf-8");
    expect(after).toContain("# My notes");
    expect(after).toContain("rafter:start");

    runCli("agent disable claude-code.instructions", home);
    const cleaned = fs.readFileSync(filePath, "utf-8");
    expect(cleaned).toContain("# My notes");
    expect(cleaned).toContain("keep this");
    expect(cleaned).not.toContain("rafter:start");
  });
});
