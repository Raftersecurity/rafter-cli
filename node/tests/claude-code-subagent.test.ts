import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { randomBytes } from "crypto";
import { spawnSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";

vi.setConfig({ testTimeout: 30_000 });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_ENTRY = path.join(PROJECT_ROOT, "dist", "index.js");

function createTempDir(prefix: string): string {
  const tmpDir = path.join(
    os.tmpdir(),
    `${prefix}-${Date.now()}-${randomBytes(6).toString("hex")}`
  );
  fs.mkdirSync(tmpDir, { recursive: true });
  return tmpDir;
}

function cleanupDir(dir: string) {
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// 30s default per-call timeout. The original 15s flaked on slow CI runners
// (rf-of20 documented the same root cause for the idempotency test: cold-start
// ubuntu+node-22 + spawnSync with shell:true occasionally takes >15s for a
// single `agent init` run). Apply the same fix to every install-doing test
// here rather than just the idempotent one.
function runCli(
  args: string,
  homeDir: string,
  timeout = 30_000
): { stdout: string; stderr: string; exitCode: number } {
  const result = spawnSync(`node ${CLI_ENTRY} ${args}`, {
    cwd: PROJECT_ROOT,
    encoding: "utf-8",
    timeout,
    shell: true,
    env: {
      ...process.env,
      HOME: homeDir,
      XDG_CONFIG_HOME: path.join(homeDir, ".config"),
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  return {
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    exitCode: result.status ?? 1,
  };
}

describe("Claude Code rafter sub-agent install (--with-claude-code)", () => {
  let testHomeDir: string;

  beforeEach(() => {
    testHomeDir = createTempDir("rafter-subagent-test");
  });

  afterEach(() => {
    cleanupDir(testHomeDir);
  });

  it("writes <home>/.claude/agents/rafter.md when --with-claude-code is passed", () => {
    fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });

    const result = runCli("agent init --with-claude-code", testHomeDir);
    expect(result.exitCode).toBe(0);

    const subagentPath = path.join(testHomeDir, ".claude", "agents", "rafter.md");
    expect(fs.existsSync(subagentPath)).toBe(true);
  });

  it("sub-agent file has the required frontmatter (name, description, tools)", () => {
    fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });
    const r = runCli("agent init --with-claude-code", testHomeDir);

    // Diagnostic gate before readFileSync — without this, a slow CI install
    // surfaces as a bare ENOENT that hides whether `agent init` returned
    // non-zero (real bug) or silently exceeded the timeout (timing/fs issue).
    // Mirrors the rf-of20 pattern from the idempotency test.
    const subagentPath = path.join(testHomeDir, ".claude", "agents", "rafter.md");
    expect(r.exitCode, `agent init failed: ${r.stderr || r.stdout}`).toBe(0);
    expect(
      fs.existsSync(subagentPath),
      `subagent missing after install. stdout=${r.stdout} stderr=${r.stderr}`,
    ).toBe(true);

    const content = fs.readFileSync(subagentPath, "utf-8");

    // Frontmatter delimiters
    expect(content.startsWith("---\n")).toBe(true);
    const closing = content.indexOf("\n---\n", 4);
    expect(closing).toBeGreaterThan(0);

    const frontmatter = content.slice(4, closing);
    expect(frontmatter).toMatch(/^name:\s*rafter\s*$/m);
    expect(frontmatter).toMatch(/^description:\s+\S/m);
    expect(frontmatter).toMatch(/^tools:\s+.*Bash/m);
  });

  it("sub-agent body references current rafter commands and tier hierarchy", () => {
    fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });
    const r = runCli("agent init --with-claude-code", testHomeDir);

    const subagentPath = path.join(testHomeDir, ".claude", "agents", "rafter.md");
    expect(r.exitCode, `agent init failed: ${r.stderr || r.stdout}`).toBe(0);
    expect(
      fs.existsSync(subagentPath),
      `subagent missing after install. stdout=${r.stdout} stderr=${r.stderr}`,
    ).toBe(true);

    const content = fs.readFileSync(subagentPath, "utf-8");

    // Trigger phrasing that maps to user's question
    expect(content).toContain("safe / secure / production worthy");
    // Default tier — remote SAST/SCA
    expect(content).toContain("rafter run");
    // Deep-dive tier
    expect(content).toContain("--mode plus");
    // Fallback tier — secrets only
    expect(content).toContain("rafter secrets");
    // Make sure the doc is honest about scope of secrets
    expect(content).toContain("NOT a code security scan");
  });

  it("is idempotent on repeated installs", () => {
    fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });

    // Bumped from default 15s → 30s. rf-of20 flaked on cross-platform
    // (ubuntu-latest, 18) once: spawnSync with shell:true on cold-start
    // ubuntu+node-18 occasionally exceeds 15s for two back-to-back
    // `agent init` runs. Keep diagnostics below so a real install
    // failure is distinguishable from a missing file.
    const r1 = runCli("agent init --with-claude-code", testHomeDir, 30_000);
    const subagentPath = path.join(testHomeDir, ".claude", "agents", "rafter.md");
    expect(r1.exitCode, `first install failed: ${r1.stderr || r1.stdout}`).toBe(0);
    expect(fs.existsSync(subagentPath), `subagent missing after first install. stdout=${r1.stdout} stderr=${r1.stderr}`).toBe(true);
    const first = fs.readFileSync(subagentPath, "utf-8");

    const r2 = runCli("agent init --with-claude-code", testHomeDir, 30_000);
    expect(r2.exitCode, `second install failed: ${r2.stderr || r2.stdout}`).toBe(0);
    const second = fs.readFileSync(subagentPath, "utf-8");

    expect(second).toBe(first);
  });

  it("does NOT write .claude/agents/rafter.md without a Claude Code install path", () => {
    // No --with-claude-code, no detectable .claude dir → nothing should be installed
    runCli("agent init --with-codex", testHomeDir);

    const subagentPath = path.join(testHomeDir, ".claude", "agents", "rafter.md");
    expect(fs.existsSync(subagentPath)).toBe(false);
  });

  it("works under --local in a project directory", () => {
    const projectDir = createTempDir("rafter-subagent-project");
    try {
      const result = spawnSync(`node ${CLI_ENTRY} agent init --local --with-claude-code`, {
        cwd: projectDir,
        encoding: "utf-8",
        timeout: 30_000,
        shell: true,
        env: {
          ...process.env,
          HOME: testHomeDir,
          XDG_CONFIG_HOME: path.join(testHomeDir, ".config"),
        },
        stdio: ["pipe", "pipe", "pipe"],
      });
      const subagentPath = path.join(projectDir, ".claude", "agents", "rafter.md");
      expect(result.status, `agent init --local failed: ${result.stderr || result.stdout}`).toBe(0);
      expect(
        fs.existsSync(subagentPath),
        `subagent missing after --local install. stdout=${result.stdout} stderr=${result.stderr}`,
      ).toBe(true);
    } finally {
      cleanupDir(projectDir);
    }
  });
});
