import { describe, it, expect, beforeEach, afterEach, beforeAll, vi } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";
import { execSync, spawnSync } from "child_process";
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

beforeAll(() => {
  try {
    execSync("pnpm run build", { cwd: PROJECT_ROOT, stdio: "ignore", timeout: 30000 });
  } catch {
    /* dist may already exist */
  }
}, 60000);

function makeHome(): string {
  const dir = path.join(os.tmpdir(), `rafter-comp-${Date.now()}-${randomBytes(4).toString("hex")}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function runCli(args: string, home: string): { stdout: string; stderr: string; code: number } {
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
