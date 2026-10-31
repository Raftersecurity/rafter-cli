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
      "windsurf.rules",
      "windsurf.mcp",
      "continue.rules",
      "continue.mcp",
      "aider.read",
      "hermes.mcp",
      "opencode.mcp",
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
    expect((byId.get("aider.read") as any).detected).toBe(true);
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

  it("aider.read writes RAFTER.md + read: entry, idempotent, strips legacy mcp line", () => {
    const conf = path.join(home, ".aider.conf.yml");
    // Pre-existing config including the legacy silent-no-op MCP line that
    // earlier rafter versions wrote (rf-du2o migration path).
    fs.writeFileSync(
      conf,
      "model: gpt-5\n\n# Rafter security MCP server\nmcp-server-command: rafter mcp serve\n",
    );

    runCli("agent enable aider.read", home);
    runCli("agent enable aider.read", home); // idempotent

    const after = fs.readFileSync(conf, "utf-8");
    expect(after).not.toContain("rafter mcp serve");
    expect(after).toContain("model: gpt-5");
    // RAFTER.md should appear in read: exactly once.
    const occurrences = (after.match(/RAFTER\.md/g) || []).length;
    expect(occurrences).toBe(1);
    // RAFTER.md was written at cwd (test runs with cwd=home).
    expect(fs.existsSync(path.join(home, "RAFTER.md"))).toBe(true);

    runCli("agent disable aider.read", home);
    const cleaned = fs.readFileSync(conf, "utf-8");
    expect(cleaned).not.toContain("RAFTER.md");
    expect(cleaned).toContain("model: gpt-5");
    expect(fs.existsSync(path.join(home, "RAFTER.md"))).toBe(false);
  });

  it("aider.read disable preserves user content outside the managed block", () => {
    const rafterMd = path.join(home, "RAFTER.md");
    // Enable writes a fresh RAFTER.md (the managed block) + the read: entry.
    runCli("agent enable aider.read", home);
    const managed = fs.readFileSync(rafterMd, "utf-8");
    expect(managed).toContain("<!-- rafter:start -->");

    // User wraps their own notes around the managed block.
    fs.writeFileSync(
      rafterMd,
      `# My project notes\nKeep this line.\n\n${managed}\n## My own section\nDo not delete me.\n`,
      "utf-8",
    );

    runCli("agent disable aider.read", home);

    // The file survives, the block is gone, and both user sections remain.
    expect(fs.existsSync(rafterMd)).toBe(true);
    const after = fs.readFileSync(rafterMd, "utf-8");
    expect(after).toContain("Keep this line.");
    expect(after).toContain("Do not delete me.");
    expect(after).not.toContain("<!-- rafter:start -->");
    expect(after).not.toContain("<!-- rafter:end -->");
    expect(after).not.toContain("Security: Rafter");
    // The read: entry is still removed from the aider config.
    expect(fs.readFileSync(path.join(home, ".aider.conf.yml"), "utf-8")).not.toContain("RAFTER.md");
  });

  it("aider.read disable removes the Aider note too: init/enable then disable leaves no orphan", () => {
    // Fails if disable strips only the main block (RAFTER.md would survive
    // holding a note about "the skill names above"), or if enable and init
    // write different RAFTER.md content.
    const rafterMd = path.join(home, "RAFTER.md");
    fs.writeFileSync(path.join(home, ".aider.conf.yml"), "model: gpt-5\n");

    runCli("agent init --with-aider", home);
    const fromInit = fs.readFileSync(rafterMd, "utf-8");
    expect(fromInit).toContain("<!-- rafter:aider-note:start -->");
    runCli("agent disable aider.read", home);
    expect(fs.existsSync(rafterMd)).toBe(false);

    runCli("agent enable aider.read", home);
    expect(fs.readFileSync(rafterMd, "utf-8")).toBe(fromInit);
    fs.writeFileSync(rafterMd, `# My notes\nKeep this line.\n\n${fromInit}`, "utf-8");
    runCli("agent disable aider.read", home);
    const after = fs.readFileSync(rafterMd, "utf-8");
    expect(after).toContain("Keep this line.");
    expect(after).not.toContain("rafter:aider-note");
    expect(after).not.toContain("skill names above");
  });

  it("openclaw.skills installs where OpenClaw reads skills, and verify sees it", () => {
    fs.mkdirSync(path.join(home, ".openclaw"), { recursive: true });
    const skill = path.join(home, ".openclaw", "workspace", "skills", "rafter-security", "SKILL.md");
    expect(runCli("agent enable openclaw.skills", home).code).toBe(0);
    expect(fs.readFileSync(skill, "utf-8")).toMatch(/^name: rafter-security$/m);
    expect(fs.existsSync(path.join(home, ".openclaw", "skills", "rafter-security.md"))).toBe(false);
    expect(runCli("agent verify", home).stdout).toMatch(/OpenClaw.*skill installed/);
    expect(runCli("agent disable openclaw.skills", home).code).toBe(0);
    expect(fs.existsSync(skill)).toBe(false);
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
