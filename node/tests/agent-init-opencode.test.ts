/**
 * Tests for the OpenCode platform integration (sable-l8e5).
 *
 * Runs the built CLI as a subprocess against a tempdir HOME so the test
 * exercises the real --with-opencode code path (option parsing →
 * detection → installer → JSON write), not just the installer in
 * isolation. Mirrors the pattern used by agent-init-hermes.test.ts.
 *
 * OpenCode's schema differs from Cursor/Windsurf: the block is `mcp`
 * (not `mcpServers`), each local server carries type: "local", and the
 * command + args are a single `command` array. Verified against
 * https://opencode.ai/docs/mcp-servers/.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { execSync, spawnSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { randomBytes } from "crypto";

const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_DIST = path.join(PROJECT_ROOT, "dist", "index.js");

beforeAll(() => {
  if (!fs.existsSync(CLI_DIST)) {
    execSync("pnpm run build", { cwd: PROJECT_ROOT, stdio: "inherit" });
  }
});

function createTempHome(): string {
  const dir = path.join(
    os.tmpdir(),
    `rafter-opencode-test-${Date.now()}-${randomBytes(4).toString("hex")}`,
  );
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function runCli(args: string[], homeDir: string): { stdout: string; stderr: string; exitCode: number } {
  const r = spawnSync(process.execPath, [CLI_DIST, ...args], {
    cwd: PROJECT_ROOT,
    encoding: "utf-8",
    timeout: 60_000,
    env: {
      ...process.env,
      HOME: homeDir,
      XDG_CONFIG_HOME: path.join(homeDir, ".config"),
      CI: "1",
    },
  });
  return {
    stdout: r.stdout || "",
    stderr: r.stderr || "",
    exitCode: r.status ?? 1,
  };
}

function openCodeConfigPath(home: string): string {
  return path.join(home, ".config", "opencode", "opencode.json");
}

function readOpenCodeConfig(home: string): Record<string, any> {
  const raw = fs.readFileSync(openCodeConfigPath(home), "utf-8");
  return JSON.parse(raw) as Record<string, any>;
}

describe("agent init --with-opencode", () => {
  let home: string;

  beforeEach(() => {
    home = createTempHome();
    fs.mkdirSync(path.join(home, ".config", "opencode"), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("creates opencode.json from scratch with mcp.rafter populated", () => {
    const r = runCli(["agent", "init", "--with-opencode"], home);
    expect(r.exitCode).toBe(0);
    const cfg = readOpenCodeConfig(home);
    expect(cfg.mcp?.rafter?.type).toBe("local");
    expect(cfg.mcp?.rafter?.command).toEqual(["rafter", "mcp", "serve"]);
    expect(cfg.mcp?.rafter?.enabled).toBe(true);
    expect(cfg.$schema).toBe("https://opencode.ai/config.json");
  });

  it("preserves existing mcp entries and other top-level keys", () => {
    fs.writeFileSync(
      openCodeConfigPath(home),
      JSON.stringify({
        $schema: "https://opencode.ai/config.json",
        mcp: { other: { type: "local", command: ["other", "go"], enabled: true } },
        theme: "system",
      }, null, 2),
      "utf-8",
    );

    const r = runCli(["agent", "init", "--with-opencode"], home);
    expect(r.exitCode).toBe(0);

    const cfg = readOpenCodeConfig(home);
    expect(cfg.mcp.other.command).toEqual(["other", "go"]);
    expect(cfg.mcp.rafter).toBeDefined();
    expect(cfg.theme).toBe("system");
  });

  it("is idempotent on a second run", () => {
    runCli(["agent", "init", "--with-opencode"], home);
    const first = fs.readFileSync(openCodeConfigPath(home), "utf-8");
    runCli(["agent", "init", "--with-opencode"], home);
    const second = fs.readFileSync(openCodeConfigPath(home), "utf-8");
    expect(second).toBe(first);
  });

  it("recovers from an unreadable / malformed JSON config", () => {
    fs.writeFileSync(
      openCodeConfigPath(home),
      "{ this is not valid json",
      "utf-8",
    );

    const r = runCli(["agent", "init", "--with-opencode"], home);
    expect(r.exitCode).toBe(0);
    const cfg = readOpenCodeConfig(home);
    expect(cfg.mcp?.rafter?.type).toBe("local");
    expect(cfg.mcp?.rafter?.command).toEqual(["rafter", "mcp", "serve"]);
  });

  it("coerces an array-shaped mcp block (wrong shape) into an object", () => {
    fs.writeFileSync(
      openCodeConfigPath(home),
      JSON.stringify({ mcp: ["junk"] }, null, 2),
      "utf-8",
    );

    const r = runCli(["agent", "init", "--with-opencode"], home);
    expect(r.exitCode).toBe(0);
    const cfg = readOpenCodeConfig(home);
    expect(typeof cfg.mcp).toBe("object");
    expect(Array.isArray(cfg.mcp)).toBe(false);
    expect(cfg.mcp.rafter?.type).toBe("local");
  });

  it("recovers from a valid-but-non-object top-level config (array)", () => {
    // Valid JSON, but the top level is an array — must be replaced with a
    // fresh object, not silently mangled by property assignment (rafter review).
    fs.writeFileSync(
      openCodeConfigPath(home),
      JSON.stringify([1, 2, 3], null, 2),
      "utf-8",
    );

    const r = runCli(["agent", "init", "--with-opencode"], home);
    expect(r.exitCode).toBe(0);
    const cfg = readOpenCodeConfig(home);
    expect(Array.isArray(cfg)).toBe(false);
    expect(cfg.mcp?.rafter?.type).toBe("local");
    expect(cfg.$schema).toBe("https://opencode.ai/config.json");
  });

  it("recovers from a valid-but-non-object top-level config (string)", () => {
    fs.writeFileSync(openCodeConfigPath(home), JSON.stringify("hello"), "utf-8");

    const r = runCli(["agent", "init", "--with-opencode"], home);
    expect(r.exitCode).toBe(0);
    const cfg = readOpenCodeConfig(home);
    expect(cfg.mcp?.rafter?.command).toEqual(["rafter", "mcp", "serve"]);
  });

  it("warns when --with-opencode is requested but ~/.config/opencode does not exist", () => {
    // Tear down the dir we created in beforeEach
    fs.rmSync(path.join(home, ".config", "opencode"), { recursive: true, force: true });

    const r = runCli(["agent", "init", "--with-opencode"], home);
    expect(r.exitCode).toBe(0); // not detected ≠ failure
    expect(r.stdout + r.stderr).toMatch(/OpenCode requested but not detected/);
    expect(fs.existsSync(openCodeConfigPath(home))).toBe(false);
  });

  it("lists OpenCode in the dry-run plan when detected", () => {
    const r = runCli(["agent", "init", "--with-opencode", "--dry-run"], home);
    expect(r.exitCode).toBe(0);
    expect(r.stdout + r.stderr).toMatch(/OpenCode \(--with-opencode\):/);
    expect(r.stdout + r.stderr).toMatch(/opencode\/opencode\.json/);
    // No actual file written under --dry-run.
    expect(fs.existsSync(openCodeConfigPath(home))).toBe(false);
  });
});

describe("OpenCode detection in verify / status / list", () => {
  let home: string;

  beforeEach(() => {
    home = createTempHome();
    fs.mkdirSync(path.join(home, ".config", "opencode"), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("agent status reports OpenCode installed after init", () => {
    runCli(["agent", "init", "--with-opencode"], home);
    const r = runCli(["agent", "status"], home);
    expect(r.stdout + r.stderr).toMatch(/OpenCode:\s+MCP installed/);
  });

  it("agent status reports detected-but-missing when dir exists without rafter", () => {
    const r = runCli(["agent", "status"], home);
    expect(r.stdout + r.stderr).toMatch(/OpenCode:\s+detected but MCP missing/);
  });

  it("agent status --json includes opencode in agents_detected", () => {
    const r = runCli(["agent", "status", "--json"], home);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.agents_detected).toContain("opencode");
  });

  it("agent verify --json marks OpenCode pass after init", () => {
    runCli(["agent", "init", "--with-opencode"], home);
    const r = runCli(["agent", "verify", "--json"], home);
    const parsed = JSON.parse(r.stdout);
    const opencode = parsed.checks.find((c: any) => c.name === "OpenCode");
    expect(opencode).toBeDefined();
    expect(opencode.status).toBe("pass");
  });

  it("agent verify --json warns (not fails) when OpenCode config lacks rafter", () => {
    fs.writeFileSync(
      openCodeConfigPath(home),
      JSON.stringify({ mcp: { other: { type: "local", command: ["other"] } } }, null, 2),
      "utf-8",
    );
    const r = runCli(["agent", "verify", "--json"], home);
    const parsed = JSON.parse(r.stdout);
    const opencode = parsed.checks.find((c: any) => c.name === "OpenCode");
    expect(opencode.status).toBe("warn");
  });

  it("agent list includes the opencode.mcp component", () => {
    const r = runCli(["agent", "list", "--json"], home);
    const parsed = JSON.parse(r.stdout);
    const ids = parsed.components.map((c: any) => c.id);
    expect(ids).toContain("opencode.mcp");
  });

  it("opencode.mcp reports installed=true in list after init", () => {
    runCli(["agent", "init", "--with-opencode"], home);
    const r = runCli(["agent", "list", "--json"], home);
    const parsed = JSON.parse(r.stdout);
    const opencode = parsed.components.find((c: any) => c.id === "opencode.mcp");
    expect(opencode).toBeDefined();
    expect(opencode.installed).toBe(true);
    expect(opencode.detected).toBe(true);
  });
});
