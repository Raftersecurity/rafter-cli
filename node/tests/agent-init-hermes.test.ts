/**
 * Tests for the Hermes platform integration (sable-gyw).
 *
 * Runs the built CLI as a subprocess against a tempdir HOME so the test
 * exercises the real --with-hermes code path (option parsing →
 * detection → installer → YAML write), not just the installer in
 * isolation. Mirrors the pattern used by agent-commands.test.ts.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { execSync, spawnSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { randomBytes } from "crypto";
import yaml from "js-yaml";

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
    `rafter-hermes-test-${Date.now()}-${randomBytes(4).toString("hex")}`,
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

function readHermesConfig(home: string): Record<string, any> {
  const raw = fs.readFileSync(path.join(home, ".hermes", "config.yaml"), "utf-8");
  return yaml.load(raw) as Record<string, any>;
}

describe("agent init --with-hermes", () => {
  let home: string;

  beforeEach(() => {
    home = createTempHome();
    fs.mkdirSync(path.join(home, ".hermes"), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("creates config.yaml from scratch with mcp_servers.rafter populated", () => {
    const r = runCli(["agent", "init", "--with-hermes"], home);
    expect(r.exitCode).toBe(0);
    const cfg = readHermesConfig(home);
    expect(cfg.mcp_servers?.rafter?.command).toBe("rafter");
    expect(cfg.mcp_servers?.rafter?.args).toEqual(["mcp", "serve"]);
  });

  it("preserves existing mcp_servers entries and other top-level keys", () => {
    fs.writeFileSync(
      path.join(home, ".hermes", "config.yaml"),
      yaml.dump({
        mcp_servers: { other: { command: "other", args: ["go"] } },
        log_level: "debug",
      }),
      "utf-8",
    );

    const r = runCli(["agent", "init", "--with-hermes"], home);
    expect(r.exitCode).toBe(0);

    const cfg = readHermesConfig(home);
    expect(cfg.mcp_servers.other.command).toBe("other");
    expect(cfg.mcp_servers.rafter).toBeDefined();
    expect(cfg.log_level).toBe("debug");
  });

  it("is idempotent on a second run", () => {
    runCli(["agent", "init", "--with-hermes"], home);
    const first = fs.readFileSync(path.join(home, ".hermes", "config.yaml"), "utf-8");
    runCli(["agent", "init", "--with-hermes"], home);
    const second = fs.readFileSync(path.join(home, ".hermes", "config.yaml"), "utf-8");
    expect(second).toBe(first);
  });

  it("recovers from an unreadable / malformed YAML config", () => {
    fs.writeFileSync(
      path.join(home, ".hermes", "config.yaml"),
      "mcp_servers: [this is not\n  a valid: mapping",
      "utf-8",
    );

    const r = runCli(["agent", "init", "--with-hermes"], home);
    expect(r.exitCode).toBe(0);
    const cfg = readHermesConfig(home);
    expect(cfg.mcp_servers?.rafter?.command).toBe("rafter");
  });

  it("coerces an array-shaped mcp_servers (wrong shape) into a dict", () => {
    fs.writeFileSync(
      path.join(home, ".hermes", "config.yaml"),
      yaml.dump({ mcp_servers: ["junk"] }),
      "utf-8",
    );

    const r = runCli(["agent", "init", "--with-hermes"], home);
    expect(r.exitCode).toBe(0);
    const cfg = readHermesConfig(home);
    expect(typeof cfg.mcp_servers).toBe("object");
    expect(Array.isArray(cfg.mcp_servers)).toBe(false);
    expect(cfg.mcp_servers.rafter?.command).toBe("rafter");
  });

  it("warns when --with-hermes is requested but ~/.hermes does not exist", () => {
    // Tear down the dir we created in beforeEach
    fs.rmSync(path.join(home, ".hermes"), { recursive: true, force: true });

    const r = runCli(["agent", "init", "--with-hermes"], home);
    expect(r.exitCode).toBe(0); // not detected ≠ failure
    expect(r.stdout + r.stderr).toMatch(/Hermes requested but not detected/);
    expect(fs.existsSync(path.join(home, ".hermes", "config.yaml"))).toBe(false);
  });

  it("lists Hermes in the dry-run plan when detected", () => {
    const r = runCli(["agent", "init", "--with-hermes", "--dry-run"], home);
    expect(r.exitCode).toBe(0);
    expect(r.stdout + r.stderr).toMatch(/Hermes \(--with-hermes\):/);
    expect(r.stdout + r.stderr).toMatch(/\.hermes\/config\.yaml/);
    // No actual file written under --dry-run.
    expect(fs.existsSync(path.join(home, ".hermes", "config.yaml"))).toBe(false);
  });
});
