import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { execSync, spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { randomBytes } from "crypto";
import { fileURLToPath } from "url";

/**
 * #231: `agent init --dry-run` must describe what the real run does, and the
 * instruction block a real run installs must not point at a skill it skipped.
 * Each test runs the dry run and the real run against the same fresh HOME and
 * compares the plan with what landed on disk.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_DIST = path.join(PROJECT_ROOT, "dist", "index.js");

beforeAll(() => {
  if (!fs.existsSync(CLI_DIST)) {
    execSync("pnpm run build", { cwd: PROJECT_ROOT, stdio: "inherit" });
  }
});

let home: string;
let proj: string;

beforeEach(() => {
  // realpath: on macOS os.tmpdir() is under /var, a symlink to /private/var,
  // and the CLI reports paths from its resolved cwd.
  home = path.join(fs.realpathSync(os.tmpdir()), `rafter-plan-${Date.now()}-${randomBytes(4).toString("hex")}`);
  proj = path.join(home, "proj");
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  fs.mkdirSync(proj, { recursive: true });
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

function run(args: string[], extraEnv: Record<string, string> = {}): string {
  const r = spawnSync(process.execPath, [CLI_DIST, ...args], {
    cwd: proj,
    encoding: "utf-8",
    timeout: 60_000,
    env: {
      ...process.env,
      HOME: home,
      XDG_CONFIG_HOME: path.join(home, ".config"),
      CI: "1",
      ...extraEnv,
    },
  });
  expect(r.status, r.stderr).toBe(0);
  return r.stdout;
}

/** Files (not directories) the dry run says it will WRITE. */
function plannedWrites(stdout: string): string[] {
  return stdout
    .split("\n")
    .map((l) => l.match(/^\s+WRITE\s+(\S+)/)?.[1])
    .filter((p): p is string => !!p && !p.endsWith("/"));
}

function installedClaudeSkills(): string[] {
  const dir = path.join(home, ".claude", "skills");
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((d) => fs.existsSync(path.join(dir, d, "SKILL.md")));
}

describe("agent init: dry-run plan matches the real run (#231)", () => {
  it("user scope --with-claude-code: every planned write lands, every installed skill was planned", () => {
    const plan = plannedWrites(run(["agent", "init", "--with-claude-code", "--dry-run"]));
    run(["agent", "init", "--with-claude-code"]);

    const missing = plan.filter((p) => !fs.existsSync(p));
    expect(missing, "planned but not written").toEqual([]);

    const unplanned = installedClaudeSkills()
      .map((s) => path.join(home, ".claude", "skills", s, "SKILL.md"))
      .filter((p) => !plan.includes(p));
    expect(unplanned, "written but not planned").toEqual([]);
  });

  it("user scope: every rafter skill the installed CLAUDE.md names is installed", () => {
    run(["agent", "init", "--with-claude-code"]);
    const claudeMd = fs.readFileSync(path.join(home, ".claude", "CLAUDE.md"), "utf-8");
    const referenced = [...new Set(claudeMd.match(/\brafter-[a-z-]+-[a-z]+\b/g) ?? [])]
      .filter((n) => fs.existsSync(path.join(PROJECT_ROOT, "resources", "skills", n)));
    expect(referenced).toContain("rafter-skill-review");
    const installed = installedClaudeSkills();
    expect(referenced.filter((n) => !installed.includes(n))).toEqual([]);
  });

  it("project scope --local --all: every planned write lands", () => {
    const plan = plannedWrites(run(["agent", "init", "--local", "--all", "--dry-run"]));
    run(["agent", "init", "--local", "--all"]);
    expect(plan.filter((p) => !fs.existsSync(p)), "planned but not written").toEqual([]);
    expect(plan).toContain(path.join(proj, ".mcp.json"));
  });

  it("a skipped write is reported as SKIP, not WRITE, and is not written", () => {
    run(["agent", "init"]);
    const cfgPath = path.join(home, ".rafter", "config.json");
    const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
    cfg.agent.components = { "claude-code.mcp": { enabled: false } };
    fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));

    const out = run(["agent", "init", "--local", "--with-claude-code", "--dry-run"]);
    const mcp = path.join(proj, ".mcp.json");
    expect(plannedWrites(out)).not.toContain(mcp);
    expect(out).toMatch(/SKIP\s+\S*\.mcp\.json/);

    run(["agent", "init", "--local", "--with-claude-code"]);
    expect(fs.existsSync(mcp)).toBe(false);
  });

  it("betterleaks already at ~/.rafter/bin is not planned as a download", () => {
    const bin = path.join(home, ".rafter", "bin", "betterleaks");
    fs.mkdirSync(path.dirname(bin), { recursive: true });
    fs.writeFileSync(bin, "");
    const out = run(["agent", "init", "--with-betterleaks", "--dry-run"], { PATH: "/usr/bin:/bin" });
    expect(out).not.toMatch(/DOWNLOAD\s+\S*betterleaks/);
    expect(out).toContain("0 downloads");
  });
});
