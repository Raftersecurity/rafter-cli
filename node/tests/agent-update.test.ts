import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { spawnSync, execSync } from "child_process";
import { randomBytes } from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";

/**
 * `rafter agent update` re-applies only the integrations already installed,
 * and `agent status` / `agent verify` say when what is installed is older
 * than this CLI. Runs the built CLI against fixtures/install-0.11.2/home, the
 * real state of a published 0.11.2 `agent init --all`.
 * Mirrors python/tests/test_agent_update.py.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");
const FIXTURE = path.resolve(PROJECT_ROOT, "..", "fixtures", "install-0.11.2", "home");
const CLI_DIST = path.join(PROJECT_ROOT, "dist", "index.js");

let home: string;

beforeAll(() => {
  if (!fs.existsSync(CLI_DIST)) execSync("pnpm run build", { cwd: PROJECT_ROOT, stdio: "inherit" });
});

beforeEach(() => {
  home = path.join(fs.realpathSync(os.tmpdir()), `rafter-update-${Date.now()}-${randomBytes(4).toString("hex")}`);
  fs.mkdirSync(home, { recursive: true });
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

function copyFixture(): void {
  fs.cpSync(FIXTURE, home, { recursive: true });
  for (const rel of [".claude/settings.json", ".codex/hooks.json", ".cursor/hooks.json", ".gemini/settings.json"]) {
    const p = path.join(home, rel);
    fs.writeFileSync(p, fs.readFileSync(p, "utf-8").replaceAll("__RAFTER_BIN__", "/usr/local/bin/rafter"));
  }
}

function cli(args: string[]): { stdout: string; status: number } {
  const r = spawnSync(process.execPath, [CLI_DIST, ...args], {
    cwd: home,
    encoding: "utf-8",
    timeout: 60_000,
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: path.join(home, ".config"), CI: "1", PATH: "/usr/bin:/bin" },
  });
  return { stdout: r.stdout + r.stderr, status: r.status ?? 1 };
}

type Outcomes = { files: string[][]; unchanged: number };
const unchangedCount = (out: string) => Number(out.match(/(\d+) files? unchanged/)?.[1] ?? 0);
const realOutcomes = (out: string): Outcomes => ({
  files: [...out.matchAll(/(added|updated|kept|replaced) +(\/\S+)/g)].map((m) => [m[2], m[1]]),
  unchanged: unchangedCount(out),
});
const plannedOutcomes = (out: string): Outcomes => ({
  files: [...out.matchAll(/^\s+WRITE\s+(\S+)\s+\((added|updated|(\S+) kept: modified)\)/gm)]
    .map((m) => (m[3] ? [m[3], "kept"] : [m[1], m[2]])),
  unchanged: unchangedCount(out),
});

describe("rafter agent update", () => {
  it("re-applies only the installed platforms, matches its dry run, and is a no-op the second time", () => {
    copyFixture();
    // Leave Claude Code, Codex and Gemini installed. The other platforms'
    // directories stay (so they are "detected"), but rafter's files go.
    for (const rel of [
      ".cursor/rules", ".cursor/agents", ".cursor/hooks.json", ".cursor/mcp.json",
      ".windsurf", ".codeium/windsurf/mcp_config.json", ".continue/rules", ".continue/config.json",
      "RAFTER.md", ".aider.conf.yml", ".hermes/config.yaml", ".config/opencode/opencode.json", ".openclaw/workspace",
    ]) fs.rmSync(path.join(home, rel), { recursive: true, force: true });

    const plan = plannedOutcomes(cli(["agent", "update", "--dry-run"]).stdout);
    const run = cli(["agent", "update"]);
    expect(run.status, run.stdout).toBe(0);
    const first = realOutcomes(run.stdout);
    expect(plan).toEqual(first);
    expect(first.files.filter(([, o]) => o === "updated").length).toBeGreaterThan(0);
    const reported = first.files.map(([p]) => path.relative(home, p).split(path.sep)[0]);
    expect(new Set(reported)).toEqual(new Set([".claude", ".agents"]));

    for (const rel of [
      ".cursor/rules", ".cursor/mcp.json", ".windsurf", ".continue/rules", ".continue/config.json",
      "RAFTER.md", ".aider.conf.yml", ".hermes/config.yaml", ".config/opencode/opencode.json", ".openclaw/workspace",
    ]) expect(fs.existsSync(path.join(home, rel)), rel).toBe(false);
    expect(fs.readFileSync(path.join(home, ".gemini", "settings.json"), "utf-8")).toContain("hook pretool");

    const second = realOutcomes(cli(["agent", "update"]).stdout);
    expect(second.files).toEqual([]);
    expect(second.unchanged).toBe(first.files.length + first.unchanged);
  });

  it("with nothing installed, says so and writes nothing", () => {
    fs.mkdirSync(path.join(home, ".claude"));
    const r = cli(["agent", "update"]);
    expect(r.status, r.stdout).toBe(0);
    expect(r.stdout).toContain("No rafter integrations found");
    expect(fs.readdirSync(home)).toEqual([".claude"]);
    expect(fs.readdirSync(path.join(home, ".claude"))).toEqual([]);
  });
});

describe("agent status / verify report an out-of-date install", () => {
  it("flags the 0.11.2 install, clears after update, and never changes verify's exit code", () => {
    copyFixture();
    const before = JSON.parse(cli(["agent", "status", "--json"]).stdout);
    expect(before.stale).toBe(true);
    expect(before.installed_version).toBeNull();
    expect(cli(["agent", "status"]).stdout).toContain("rafter agent update");

    expect(cli(["agent", "update", "--quiet"]).status).toBe(0);
    const after = JSON.parse(cli(["agent", "status", "--json"]).stdout);
    expect(after.stale).toBe(false);
    expect(after.installed_version).toBe(after.version);
    const fresh = cli(["agent", "verify", "--json"]);
    expect(JSON.parse(fresh.stdout.split("\n")[0]).stale).toBe(false);
    expect(cli(["agent", "status"]).stdout).not.toContain("rafter agent update");

    // An older recorded version alone makes it stale, without failing verify.
    const manifest = path.join(home, ".rafter", "installed.json");
    const doc = JSON.parse(fs.readFileSync(manifest, "utf-8"));
    fs.writeFileSync(manifest, JSON.stringify({ ...doc, cliVersion: "0.0.1" }));
    const old = cli(["agent", "verify", "--json"]);
    const oldJson = JSON.parse(old.stdout.split("\n")[0]);
    expect(oldJson.stale).toBe(true);
    expect(oldJson.installed_version).toBe("0.0.1");
    expect(old.status).toBe(fresh.status);
    expect(cli(["agent", "verify"]).stdout).toContain("rafter agent update");
  });
});
