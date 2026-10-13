import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { randomBytes } from "crypto";
import { spawnSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";

// CLI integration tests spawn subprocesses — allow generous timeouts
vi.setConfig({ testTimeout: 30_000 });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_ENTRY = path.join(PROJECT_ROOT, "dist", "index.js");

// Test helper to create temporary directories
function createTempDir(prefix: string): string {
  const tmpDir = path.join(
    os.tmpdir(),
    `${prefix}-${Date.now()}-${randomBytes(6).toString("hex")}`
  );
  fs.mkdirSync(tmpDir, { recursive: true });
  return tmpDir;
}

// Test helper to cleanup directory
function cleanupDir(dir: string) {
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Run the CLI with a fake HOME directory.
 * Returns { stdout, stderr, exitCode }.
 */
// A full `agent init` install (config + skills + MCP registration + hooks) runs
// ~8-24s on its own — the old 15s default left no headroom, so under concurrent
// suite load spawnSync would time out, return status:null, and a downstream
// readFileSync would ENOENT on the file the killed child never wrote (sable-784).
// 60s gives ample margin while still bounding a genuine hang.
function runCli(
  args: string,
  homeDir: string,
  timeout = 60_000
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

// Run the CLI and assert it exited 0 before the caller reads files it wrote.
// spawnSync waits for child exit, so a 0 exit code means writeFileSync has
// flushed to disk — guarding here turns an opaque downstream ENOENT into a
// legible "CLI failed: <stderr>" and catches a real install regression that a
// delayed/absent write would otherwise mask (sable-784).
function runCliOk(args: string, homeDir: string, timeout?: number) {
  const result = runCli(args, homeDir, timeout);
  expect(
    result.exitCode,
    `CLI \`${args}\` failed (exit ${result.exitCode}): ${result.stderr}`
  ).toBe(0);
  return result;
}

// Run the CLI with a given cwd (for --local, which installs relative to cwd
// rather than HOME). Hoisted to module scope so it's usable both by the shared
// MCP_ADAPTERS table above and by the Claude Code --local scope test below.
function runCliInCwd(
  args: string,
  cwd: string,
  homeDir: string
): { stdout: string; stderr: string; exitCode: number } {
  const result = spawnSync(`node ${CLI_ENTRY} ${args}`, {
    cwd,
    encoding: "utf-8",
    timeout: 15_000,
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

describe("Platform Integration — MCP Installs via CLI", () => {
  let testHomeDir: string;

  beforeEach(() => {
    testHomeDir = createTempDir("rafter-platform-test");
  });

  afterEach(() => {
    cleanupDir(testHomeDir);
  });

  // ── 1. Flag rejection ──────────────────────────────────────────────

  describe("Flag rejection", () => {
    it.each(["--skip-openclaw", "--skip-claude-code"])(
      "should reject %s as unknown option",
      (flag) => {
        const result = runCli(`agent init ${flag}`, testHomeDir);
        expect(result.exitCode).not.toBe(0);
        expect(result.stderr).toContain("unknown option");
      }
    );
  });

  // ── 2/3/4/11b. MCP adapters — shared install behavior ───────────────
  //
  // installGeminiMcp / installCursorMcp / installWindsurfMcp / installClaudeCodeMcp
  // (node/src/commands/agent/init.ts) are structurally identical read-merge-write
  // functions, differing only in path. One parameterized table covers fresh
  // install, no-duplicate-on-reinstall, preserving a pre-existing non-rafter
  // entry, and overwriting a stale rafter entry for all four — proving the four
  // adapters produce an identical rafter entry shape as a side effect of the
  // fresh-install assertion (replaces the former standalone "MCP entry structure
  // validation" test). Continue.dev is NOT in this table: its mcpServers field
  // has a real array-vs-object format fork and is tested on its own below.

  type McpAdapterSpec = {
    name: string;
    installArgs: string;
    run: (args: string, home: string) => { stdout: string; stderr: string; exitCode: number };
    setupDir?: (home: string) => void;
    configPath: (home: string) => string;
  };

  const MCP_ADAPTERS: McpAdapterSpec[] = [
    {
      name: "Gemini",
      installArgs: "agent init --with-gemini",
      run: runCli,
      setupDir: (home) => fs.mkdirSync(path.join(home, ".gemini"), { recursive: true }),
      configPath: (home) => path.join(home, ".gemini", "settings.json"),
    },
    {
      name: "Cursor",
      installArgs: "agent init --with-cursor",
      run: runCli,
      setupDir: (home) => fs.mkdirSync(path.join(home, ".cursor"), { recursive: true }),
      configPath: (home) => path.join(home, ".cursor", "mcp.json"),
    },
    {
      name: "Windsurf",
      installArgs: "agent init --with-windsurf",
      run: runCli,
      setupDir: (home) => fs.mkdirSync(path.join(home, ".codeium", "windsurf"), { recursive: true }),
      configPath: (home) => path.join(home, ".codeium", "windsurf", "mcp_config.json"),
    },
    {
      name: "Claude Code (--local)",
      installArgs: "agent init --local --with-claude-code",
      run: (args, home) => runCliInCwd(args, home, home),
      // No setupDir: --local installs unconditionally into cwd, no detection gate.
      configPath: (home) => path.join(home, ".mcp.json"),
    },
  ];

  describe("MCP adapters — shared install behavior (Gemini/Cursor/Windsurf/Claude Code --local)", () => {
    it.each(MCP_ADAPTERS)(
      "$name: fresh install creates mcpServers.rafter = {command, args}",
      ({ setupDir, configPath, installArgs, run }) => {
        setupDir?.(testHomeDir);
        const result = run(installArgs, testHomeDir);
        expect(result.exitCode, `CLI failed (exit ${result.exitCode}): ${result.stderr}`).toBe(0);

        const cfgPath = configPath(testHomeDir);
        expect(fs.existsSync(cfgPath)).toBe(true);

        const config = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
        expect(config.mcpServers).toBeDefined();
        expect(config.mcpServers.rafter).toEqual({ command: "rafter", args: ["mcp", "serve"] });
      }
    );

    it.each(MCP_ADAPTERS)(
      "$name: does not duplicate rafter entry on repeated installs",
      ({ setupDir, configPath, installArgs, run }) => {
        setupDir?.(testHomeDir);
        run(installArgs, testHomeDir);
        run(installArgs, testHomeDir);

        const config = JSON.parse(fs.readFileSync(configPath(testHomeDir), "utf-8"));
        expect(Object.keys(config.mcpServers)).toEqual(["rafter"]);
      }
    );

    it.each(MCP_ADAPTERS)(
      "$name: preserves an existing non-rafter MCP server",
      ({ setupDir, configPath, installArgs, run }) => {
        setupDir?.(testHomeDir);
        const cfgPath = configPath(testHomeDir);
        fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
        fs.writeFileSync(
          cfgPath,
          JSON.stringify({ mcpServers: { "other-tool": { command: "other", args: ["serve"] } } }, null, 2)
        );

        run(installArgs, testHomeDir);

        const config = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
        expect(config.mcpServers["other-tool"]).toBeDefined();
        expect(config.mcpServers.rafter).toBeDefined();
      }
    );

    it.each(MCP_ADAPTERS)(
      "$name: overwrites a stale rafter entry on re-install",
      ({ setupDir, configPath, installArgs, run }) => {
        setupDir?.(testHomeDir);
        const cfgPath = configPath(testHomeDir);
        fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
        fs.writeFileSync(
          cfgPath,
          JSON.stringify({ mcpServers: { rafter: { command: "old-rafter", args: ["old-arg"] } } }, null, 2)
        );

        run(installArgs, testHomeDir);

        const config = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
        expect(config.mcpServers.rafter).toEqual({ command: "rafter", args: ["mcp", "serve"] });
      }
    );
  });

  // Shape-agnostic behavior shared with Continue.dev too (its mcpServers can be
  // an array OR an object — see "Continue.dev MCP idempotency" below for its own
  // format-specific tests). rafterPresent() abstracts over both shapes so these
  // two scenarios cover Gemini/Cursor/Windsurf/Continue.dev in one table.
  const MCP_SIBLING_ADAPTERS: (McpAdapterSpec & { rafterPresent: (config: any) => boolean })[] = [
    ...MCP_ADAPTERS.filter((a) => a.name !== "Claude Code (--local)").map((a) => ({
      ...a,
      rafterPresent: (config: any) => !!config?.mcpServers?.rafter?.command,
    })),
    {
      name: "Continue.dev",
      installArgs: "agent init --with-continue",
      run: runCli,
      setupDir: (home) => fs.mkdirSync(path.join(home, ".continue"), { recursive: true }),
      configPath: (home) => path.join(home, ".continue", "config.json"),
      rafterPresent: (config: any) =>
        Array.isArray(config?.mcpServers)
          ? config.mcpServers.some((s: any) => s.name === "rafter")
          : !!config?.mcpServers?.rafter,
    },
  ];

  describe("MCP adapters — shared non-MCP-settings preservation + corrupted-JSON recovery (Gemini/Cursor/Windsurf/Continue.dev)", () => {
    it.each(MCP_SIBLING_ADAPTERS)(
      "$name: preserves existing non-MCP sibling settings",
      ({ setupDir, configPath, installArgs, run, rafterPresent }) => {
        setupDir?.(testHomeDir);
        const cfgPath = configPath(testHomeDir);
        fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
        fs.writeFileSync(cfgPath, JSON.stringify({ theme: "monokai", fontSize: 14 }, null, 2));

        run(installArgs, testHomeDir);

        const config = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
        expect(config.theme).toBe("monokai");
        expect(config.fontSize).toBe(14);
        expect(rafterPresent(config)).toBe(true);
      }
    );

    it.each(MCP_SIBLING_ADAPTERS)(
      "$name: recovers from a corrupted existing config file",
      ({ setupDir, configPath, installArgs, run, rafterPresent }) => {
        setupDir?.(testHomeDir);
        const cfgPath = configPath(testHomeDir);
        fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
        fs.writeFileSync(cfgPath, "{not valid json!!");

        const result = run(installArgs, testHomeDir);
        expect(result.exitCode).toBe(0);

        const config = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
        expect(rafterPresent(config)).toBe(true);
      }
    );
  });

  // ── 2c/3c/4c/5c/6c. Platform requested but not detected ─────────────
  //
  // CLI_SPEC.md's "agent verify" table documents one detection dir/file and one
  // warning per platform (shared-docs/CLI_SPEC.md ~L954-961). One parameterized
  // table replaces five near-identical per-platform tests.

  const NOT_DETECTED_CASES: {
    name: string;
    installArgs: string;
    warning: string;
    artifact?: (home: string) => string;
  }[] = [
    {
      name: "Gemini",
      installArgs: "agent init --with-gemini",
      warning: "Gemini CLI requested but not detected",
      artifact: (home) => path.join(home, ".gemini", "settings.json"),
    },
    {
      name: "Cursor",
      installArgs: "agent init --with-cursor",
      warning: "Cursor requested but not detected",
      artifact: (home) => path.join(home, ".cursor", "mcp.json"),
    },
    {
      name: "Windsurf",
      installArgs: "agent init --with-windsurf",
      warning: "Windsurf requested but not detected",
      artifact: (home) => path.join(home, ".codeium", "windsurf", "mcp_config.json"),
    },
    {
      name: "Continue.dev",
      installArgs: "agent init --with-continue",
      warning: "Continue.dev requested but not detected",
      artifact: (home) => path.join(home, ".continue", "config.json"),
    },
    {
      name: "Aider",
      installArgs: "agent init --with-aider",
      warning: "Aider requested but not detected",
    },
  ];

  describe("Platform requested but not detected — warns, does not install", () => {
    it.each(NOT_DETECTED_CASES)(
      "$name: warns and skips install when its directory/file is absent",
      ({ installArgs, warning, artifact }) => {
        const result = runCli(installArgs, testHomeDir);
        expect(result.exitCode).toBe(0);
        expect(result.stdout).toContain(warning);
        if (artifact) {
          expect(fs.existsSync(artifact(testHomeDir))).toBe(false);
        }
      }
    );
  });

  // ── 2b-ii. Gemini GEMINI.md instruction file ────────────────────

  describe("Gemini GEMINI.md instruction file", () => {
    it("writes ~/.gemini/GEMINI.md with the rafter marker block at user scope", () => {
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });

      const result = runCli("agent init --with-gemini", testHomeDir);
      expect(result.exitCode).toBe(0);

      const geminiPath = path.join(testHomeDir, ".gemini", "GEMINI.md");
      expect(fs.existsSync(geminiPath)).toBe(true);

      const content = fs.readFileSync(geminiPath, "utf-8");
      expect(content).toContain("<!-- rafter:start -->");
      expect(content).toContain("<!-- rafter:end -->");
    });

    it("is idempotent on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });

      runCli("agent init --with-gemini", testHomeDir);
      const first = fs.readFileSync(
        path.join(testHomeDir, ".gemini", "GEMINI.md"),
        "utf-8"
      );

      runCli("agent init --with-gemini", testHomeDir);
      const second = fs.readFileSync(
        path.join(testHomeDir, ".gemini", "GEMINI.md"),
        "utf-8"
      );

      expect(second).toBe(first);
    });

    it("preserves existing user content outside the marker block", () => {
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });
      const geminiPath = path.join(testHomeDir, ".gemini", "GEMINI.md");
      fs.writeFileSync(geminiPath, "# My personal instructions\n\nDo the thing.\n");

      runCli("agent init --with-gemini", testHomeDir);

      const content = fs.readFileSync(geminiPath, "utf-8");
      expect(content).toContain("# My personal instructions");
      expect(content).toContain("Do the thing.");
      expect(content).toContain("<!-- rafter:start -->");
    });

    it("does NOT write GEMINI.md if --with-gemini is not passed", () => {
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });

      runCli("agent init --with-claude-code", testHomeDir);

      expect(
        fs.existsSync(path.join(testHomeDir, ".gemini", "GEMINI.md"))
      ).toBe(false);
    });
  });

  // ── 2b-iii. Gemini skill install + registration ──────────────────

  describe("Gemini skills install (--with-gemini)", () => {
    it("installs rafter skills to <home>/.agents/skills/ (mirrors codex)", () => {
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });

      const result = runCli("agent init --with-gemini", testHomeDir);
      expect(result.exitCode).toBe(0);

      // All three AGENT_SKILLS must land on disk regardless of whether the
      // gemini CLI is available for registration.
      for (const name of ["rafter", "rafter-secure-design", "rafter-code-review"]) {
        const skillPath = path.join(testHomeDir, ".agents", "skills", name, "SKILL.md");
        expect(fs.existsSync(skillPath), `${name} SKILL.md should be installed`).toBe(true);
      }
    });

    it("warns but succeeds when gemini CLI is not on PATH", () => {
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });

      // Build a scrubbed PATH containing only a symlink to the node binary,
      // so that `gemini` cannot be resolved even on dev machines where it's
      // installed alongside node in the same nvm bin dir.
      const isolatedBin = path.join(testHomeDir, "_bin");
      fs.mkdirSync(isolatedBin, { recursive: true });
      fs.symlinkSync(process.execPath, path.join(isolatedBin, "node"));

      const result = spawnSync(process.execPath, [CLI_ENTRY, "agent", "init", "--with-gemini"], {
        cwd: PROJECT_ROOT,
        encoding: "utf-8",
        timeout: 15_000,
        env: {
          HOME: testHomeDir,
          XDG_CONFIG_HOME: path.join(testHomeDir, ".config"),
          PATH: isolatedBin,
        },
        stdio: ["pipe", "pipe", "pipe"],
      });

      expect(result.status ?? 1, `stderr: ${result.stderr}`).toBe(0);
      // Skills still written to disk
      const skillPath = path.join(testHomeDir, ".agents", "skills", "rafter", "SKILL.md");
      expect(fs.existsSync(skillPath)).toBe(true);
      // Warning surfaces
      expect(result.stdout).toMatch(/gemini CLI not found on PATH/i);
    });

    it("shares skill dir with codex when both flags are passed", () => {
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });

      const result = runCli("agent init --with-gemini --with-codex", testHomeDir);
      expect(result.exitCode).toBe(0);

      const skillPath = path.join(testHomeDir, ".agents", "skills", "rafter", "SKILL.md");
      expect(fs.existsSync(skillPath)).toBe(true);
    });
  });

  // ── 5. Continue.dev rules + MCP install (rf-acz0) ─────────────────

  describe("Continue.dev rules (--with-continue)", () => {
    it("writes per-skill rules under .continue/rules/<skill>.md", () => {
      fs.mkdirSync(path.join(testHomeDir, ".continue"), { recursive: true });

      runCli("agent init --with-continue", testHomeDir);

      for (const name of ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"]) {
        const rulePath = path.join(testHomeDir, ".continue", "rules", `${name}.md`);
        expect(fs.existsSync(rulePath), `continue rule missing: ${name}`).toBe(true);
        const body = fs.readFileSync(rulePath, "utf-8");
        expect(body).toMatch(/^---\nname:\s+/m);
        expect(body).toMatch(/^description:\s+"/m);
        expect(body).toMatch(/^alwaysApply:\s+false$/m);
      }
    });

    it("is idempotent on repeat installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".continue"), { recursive: true });

      runCli("agent init --with-continue", testHomeDir);
      runCli("agent init --with-continue", testHomeDir);

      const rulesDir = path.join(testHomeDir, ".continue", "rules");
      const files = fs.readdirSync(rulesDir).sort();
      expect(files).toEqual([
        "rafter-code-review.md",
        "rafter-secure-design.md",
        "rafter-skill-review.md",
        "rafter.md",
      ]);
    });
  });

  describe("Continue.dev MCP install (--with-continue)", () => {
    it("should create config.json with mcpServers containing rafter (fresh)", () => {
      fs.mkdirSync(path.join(testHomeDir, ".continue"), { recursive: true });

      const result = runCli("agent init --with-continue", testHomeDir);
      expect(result.exitCode).toBe(0);

      const configPath = path.join(testHomeDir, ".continue", "config.json");
      expect(fs.existsSync(configPath)).toBe(true);

      const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
      expect(config.mcpServers).toBeDefined();

      // Continue.dev uses array format by default (fresh config)
      if (Array.isArray(config.mcpServers)) {
        const rafterEntry = config.mcpServers.find(
          (s: any) => s.name === "rafter"
        );
        expect(rafterEntry).toBeDefined();
        expect(rafterEntry.command).toBe("rafter");
        expect(rafterEntry.args).toEqual(["mcp", "serve"]);
      } else {
        // Object format (newer Continue.dev versions)
        expect(config.mcpServers.rafter).toBeDefined();
        expect(config.mcpServers.rafter.command).toBe("rafter");
        expect(config.mcpServers.rafter.args).toEqual(["mcp", "serve"]);
      }
    });
  });

  // ── 5b. Continue.dev idempotency and preservation ─────────────────

  describe("Continue.dev MCP idempotency", () => {
    it("should not duplicate rafter in array format on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".continue"), { recursive: true });

      runCli("agent init --with-continue", testHomeDir);
      runCli("agent init --with-continue", testHomeDir);

      const configPath = path.join(testHomeDir, ".continue", "config.json");
      const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));

      if (Array.isArray(config.mcpServers)) {
        const rafterEntries = config.mcpServers.filter(
          (s: any) => s.name === "rafter"
        );
        expect(rafterEntries).toHaveLength(1);
      } else {
        expect(Object.keys(config.mcpServers).filter(k => k === "rafter")).toHaveLength(1);
      }
    });

    it("should preserve existing non-rafter MCP servers (array format)", () => {
      const continueDir = path.join(testHomeDir, ".continue");
      fs.mkdirSync(continueDir, { recursive: true });
      fs.writeFileSync(
        path.join(continueDir, "config.json"),
        JSON.stringify({
          mcpServers: [
            { name: "other-tool", command: "other", args: ["run"] },
          ],
        }, null, 2)
      );

      runCli("agent init --with-continue", testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(continueDir, "config.json"), "utf-8")
      );
      expect(Array.isArray(config.mcpServers)).toBe(true);
      const otherEntry = config.mcpServers.find(
        (s: any) => s.name === "other-tool"
      );
      expect(otherEntry).toBeDefined();
      const rafterEntry = config.mcpServers.find(
        (s: any) => s.name === "rafter"
      );
      expect(rafterEntry).toBeDefined();
    });

    it("should handle object format mcpServers (newer Continue.dev)", () => {
      const continueDir = path.join(testHomeDir, ".continue");
      fs.mkdirSync(continueDir, { recursive: true });
      fs.writeFileSync(
        path.join(continueDir, "config.json"),
        JSON.stringify({
          mcpServers: {
            "existing-server": { command: "existing", args: ["serve"] },
          },
        }, null, 2)
      );

      runCli("agent init --with-continue", testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(continueDir, "config.json"), "utf-8")
      );
      // Should preserve object format, not convert to array
      expect(Array.isArray(config.mcpServers)).toBe(false);
      expect(config.mcpServers["existing-server"]).toBeDefined();
      expect(config.mcpServers.rafter).toBeDefined();
      expect(config.mcpServers.rafter.command).toBe("rafter");
    });
  });

  // ── 6. Aider read-only context (rf-du2o) ──────────────────────────
  //
  // Earlier rafter versions appended `mcp-server-command: rafter mcp serve`
  // to .aider.conf.yml — Aider has no native MCP support and silently
  // ignores unknown YAML keys per its docs. That install was a no-op.
  //
  // Replaced by RAFTER.md + .aider.conf.yml `read:` entry, Aider's only
  // documented persistent-context primitive.

  describe("Aider read-only context (--with-aider)", () => {
    it("writes RAFTER.md at workspace root with the rafter marker block", () => {
      fs.writeFileSync(path.join(testHomeDir, ".aider.conf.yml"), "# existing aider config\n");

      const result = runCli("agent init --with-aider", testHomeDir);
      expect(result.exitCode).toBe(0);

      const rafterMd = path.join(testHomeDir, "RAFTER.md");
      expect(fs.existsSync(rafterMd)).toBe(true);
      const body = fs.readFileSync(rafterMd, "utf-8");
      expect(body).toContain("<!-- rafter:start -->");
      expect(body).toContain("<!-- rafter:end -->");
    });

    it("adds RAFTER.md to .aider.conf.yml `read:` list (preserving existing keys)", () => {
      const existingConfig = [
        "model: gpt-4-turbo",
        "auto-commits: false",
        "dark-mode: true",
        "map-tokens: 1024",
      ].join("\n") + "\n";
      fs.writeFileSync(path.join(testHomeDir, ".aider.conf.yml"), existingConfig);

      runCli("agent init --with-aider", testHomeDir);

      const content = fs.readFileSync(path.join(testHomeDir, ".aider.conf.yml"), "utf-8");
      expect(content).toContain("model: gpt-4-turbo");
      expect(content).toContain("auto-commits: false");
      expect(content).toContain("dark-mode: true");
      expect(content).toContain("map-tokens: 1024");
      expect(content).toContain("RAFTER.md");
    });

    it("does NOT write the legacy mcp-server-command (silent no-op pruned)", () => {
      fs.writeFileSync(path.join(testHomeDir, ".aider.conf.yml"), "# fresh\n");

      runCli("agent init --with-aider", testHomeDir);

      const content = fs.readFileSync(path.join(testHomeDir, ".aider.conf.yml"), "utf-8");
      expect(content).not.toContain("mcp-server-command");
      expect(content).not.toContain("rafter mcp serve");
    });

    it("strips a pre-existing legacy mcp-server-command on reinstall (rf-du2o migration)", () => {
      fs.writeFileSync(
        path.join(testHomeDir, ".aider.conf.yml"),
        "model: gpt-5\n\n# Rafter security MCP server\nmcp-server-command: rafter mcp serve\n",
      );

      runCli("agent init --with-aider", testHomeDir);

      const content = fs.readFileSync(path.join(testHomeDir, ".aider.conf.yml"), "utf-8");
      expect(content).not.toContain("mcp-server-command");
      expect(content).not.toContain("Rafter security MCP server");
      expect(content).toContain("model: gpt-5");
      expect(content).toContain("RAFTER.md");
    });

    it("is idempotent across repeated installs (RAFTER.md listed once)", () => {
      fs.writeFileSync(path.join(testHomeDir, ".aider.conf.yml"), "model: gpt-5\n");

      runCli("agent init --with-aider", testHomeDir);
      runCli("agent init --with-aider", testHomeDir);

      const content = fs.readFileSync(path.join(testHomeDir, ".aider.conf.yml"), "utf-8");
      const matches = content.match(/RAFTER\.md/g) || [];
      expect(matches).toHaveLength(1);
    });

    it("preserves existing read: entries", () => {
      fs.writeFileSync(
        path.join(testHomeDir, ".aider.conf.yml"),
        "read:\n  - CONVENTIONS.md\n  - DESIGN.md\n",
      );

      runCli("agent init --with-aider", testHomeDir);

      const content = fs.readFileSync(path.join(testHomeDir, ".aider.conf.yml"), "utf-8");
      expect(content).toContain("CONVENTIONS.md");
      expect(content).toContain("DESIGN.md");
      expect(content).toContain("RAFTER.md");
    });
  });

  // ── 7. Opt-in gating ──────────────────────────────────────────────

  describe("Opt-in gating", () => {
    it("plain 'agent init' should NOT install any platform configs", () => {
      // Pre-create all platform directories so they would be "detected"
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".cursor"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".codeium", "windsurf"), {
        recursive: true,
      });
      fs.mkdirSync(path.join(testHomeDir, ".continue"), { recursive: true });
      fs.writeFileSync(
        path.join(testHomeDir, ".aider.conf.yml"),
        "# config\n"
      );

      const result = runCli("agent init", testHomeDir);
      expect(result.exitCode).toBe(0);

      // None of the MCP config files should have been created/modified
      expect(
        fs.existsSync(path.join(testHomeDir, ".gemini", "settings.json"))
      ).toBe(false);
      expect(
        fs.existsSync(path.join(testHomeDir, ".cursor", "mcp.json"))
      ).toBe(false);
      expect(
        fs.existsSync(
          path.join(testHomeDir, ".codeium", "windsurf", "mcp_config.json")
        )
      ).toBe(false);
      expect(
        fs.existsSync(path.join(testHomeDir, ".continue", "config.json"))
      ).toBe(false);
      // Aider file existed before but should NOT have rafter touch it.
      const aiderContent = fs.readFileSync(
        path.join(testHomeDir, ".aider.conf.yml"),
        "utf-8"
      );
      expect(aiderContent).not.toContain("RAFTER.md");
      expect(aiderContent).not.toContain("rafter mcp serve");
    });
  });

  // ── 9. Mixed flag combinations ────────────────────────────────────

  describe("Mixed flag combinations", () => {
    it("should install only the requested platforms", () => {
      // Create ALL platform dirs
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".cursor"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".codeium", "windsurf"), {
        recursive: true,
      });
      fs.mkdirSync(path.join(testHomeDir, ".continue"), { recursive: true });
      fs.writeFileSync(
        path.join(testHomeDir, ".aider.conf.yml"),
        "# config\n"
      );

      // Only request gemini + cursor
      const result = runCli(
        "agent init --with-gemini --with-cursor",
        testHomeDir
      );
      expect(result.exitCode).toBe(0);

      // Gemini and Cursor should be installed
      expect(
        fs.existsSync(path.join(testHomeDir, ".gemini", "settings.json"))
      ).toBe(true);
      expect(
        fs.existsSync(path.join(testHomeDir, ".cursor", "mcp.json"))
      ).toBe(true);

      // Others should NOT be installed
      expect(
        fs.existsSync(
          path.join(testHomeDir, ".codeium", "windsurf", "mcp_config.json")
        )
      ).toBe(false);
      expect(
        fs.existsSync(path.join(testHomeDir, ".continue", "config.json"))
      ).toBe(false);
      const aiderContent = fs.readFileSync(
        path.join(testHomeDir, ".aider.conf.yml"),
        "utf-8"
      );
      // Aider not requested — its config file remains untouched.
      expect(aiderContent).not.toContain("RAFTER.md");
      expect(aiderContent).not.toContain("rafter mcp serve");
    });

    it("should handle --with-windsurf --with-aider together", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codeium", "windsurf"), {
        recursive: true,
      });
      fs.writeFileSync(
        path.join(testHomeDir, ".aider.conf.yml"),
        "# config\n"
      );

      const result = runCli(
        "agent init --with-windsurf --with-aider",
        testHomeDir
      );
      expect(result.exitCode).toBe(0);

      // Both should be installed
      expect(
        fs.existsSync(
          path.join(testHomeDir, ".codeium", "windsurf", "mcp_config.json")
        )
      ).toBe(true);
      // Aider — RAFTER.md + read: entry (rf-du2o)
      const aiderContent = fs.readFileSync(
        path.join(testHomeDir, ".aider.conf.yml"),
        "utf-8"
      );
      expect(aiderContent).toContain("RAFTER.md");
      expect(fs.existsSync(path.join(testHomeDir, "RAFTER.md"))).toBe(true);
    });
  });

  // ── 11. Claude Code hooks + skills + instructions ─────────────────

  describe("Claude Code full integration (--with-claude-code)", () => {
    it("should install hooks to ~/.claude/settings.json", () => {
      fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });

      const result = runCli("agent init --with-claude-code", testHomeDir);
      expect(result.exitCode).toBe(0);

      const settingsPath = path.join(testHomeDir, ".claude", "settings.json");
      expect(fs.existsSync(settingsPath)).toBe(true);

      const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
      expect(settings.hooks).toBeDefined();
      expect(settings.hooks.PreToolUse).toBeDefined();
      expect(settings.hooks.PostToolUse).toBeDefined();

      // Verify PreToolUse hook matchers
      const preMatchers = settings.hooks.PreToolUse.map((e: any) => e.matcher);
      expect(preMatchers).toContain("Bash");
      expect(preMatchers).toContain("Write|Edit");

      // Verify hook commands
      // rf-er8a: a RESOLVABLE ABSOLUTE command (`<node> <entrypoint> hook …`),
      // not the bare `rafter hook …` that exits 127 off PATH.
      const isAbs = (c: string) => path.isAbsolute(String(c ?? "").split(" ")[0]);
      const preCommands = settings.hooks.PreToolUse.flatMap(
        (e: any) => (e.hooks || []).map((h: any) => h.command)
      );
      expect(preCommands.some((c: string) => c.endsWith("hook pretool") && isAbs(c))).toBe(true);

      const postCommands = settings.hooks.PostToolUse.flatMap(
        (e: any) => (e.hooks || []).map((h: any) => h.command)
      );
      expect(postCommands.some((c: string) => c.endsWith("hook posttool") && isAbs(c))).toBe(true);

      // PostToolUse matcher is scoped to tools that produce scannable output
      // (shell output + file writes) rather than firing on every tool call.
      const postMatchers = settings.hooks.PostToolUse.map((e: any) => e.matcher);
      expect(postMatchers).toContain("Bash|Write|Edit|MultiEdit");
    });

    it("should install skills to ~/.claude/skills/", () => {
      fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });

      const result = runCli("agent init --with-claude-code", testHomeDir);
      expect(result.exitCode).toBe(0);

      const backendSkill = path.join(testHomeDir, ".claude", "skills", "rafter", "SKILL.md");
      const secureDesignSkill = path.join(testHomeDir, ".claude", "skills", "rafter-secure-design", "SKILL.md");
      const codeReviewSkill = path.join(testHomeDir, ".claude", "skills", "rafter-code-review", "SKILL.md");

      expect(fs.existsSync(backendSkill)).toBe(true);
      expect(fs.existsSync(secureDesignSkill)).toBe(true);
      expect(fs.existsSync(codeReviewSkill)).toBe(true);

      // Validate skill content
      const backendContent = fs.readFileSync(backendSkill, "utf-8");
      expect(backendContent).toMatch(/^---\n/);
      expect(backendContent).toContain("rafter");
    });

    it("should install global instruction file to ~/.claude/CLAUDE.md", () => {
      fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });

      const result = runCli("agent init --with-claude-code", testHomeDir);
      expect(result.exitCode).toBe(0);

      const instructionPath = path.join(testHomeDir, ".claude", "CLAUDE.md");
      expect(fs.existsSync(instructionPath)).toBe(true);

      const content = fs.readFileSync(instructionPath, "utf-8");
      expect(content).toContain("<!-- rafter:start -->");
      expect(content).toContain("<!-- rafter:end -->");
      expect(content).toContain("rafter-secure-design");
      expect(content).toContain("rafter-code-review");
    });

    it("should preserve existing CLAUDE.md content when adding instructions", () => {
      const claudeDir = path.join(testHomeDir, ".claude");
      fs.mkdirSync(claudeDir, { recursive: true });
      fs.writeFileSync(
        path.join(claudeDir, "CLAUDE.md"),
        "# My Project\n\nExisting instructions here.\n"
      );

      runCli("agent init --with-claude-code", testHomeDir);

      const content = fs.readFileSync(path.join(claudeDir, "CLAUDE.md"), "utf-8");
      expect(content).toContain("# My Project");
      expect(content).toContain("Existing instructions here.");
      expect(content).toContain("<!-- rafter:start -->");
    });

    it("should deduplicate hooks on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });

      runCli("agent init --with-claude-code", testHomeDir);
      runCli("agent init --with-claude-code", testHomeDir);

      const settings = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".claude", "settings.json"), "utf-8")
      );

      // Should have exactly 2 PreToolUse entries (Bash + Write|Edit), not 4.
      // rf-er8a writes an absolute command, so match the `hook pretool` tail
      // (the dedup removal filter keys on the same substring).
      const rafterPreHooks = settings.hooks.PreToolUse.filter(
        (e: any) => (e.hooks || []).some((h: any) => String(h.command ?? "").endsWith("hook pretool"))
      );
      expect(rafterPreHooks).toHaveLength(2);

      // Exactly 1 PostToolUse entry
      const rafterPostHooks = settings.hooks.PostToolUse.filter(
        (e: any) => (e.hooks || []).some((h: any) => String(h.command ?? "").endsWith("hook posttool"))
      );
      expect(rafterPostHooks).toHaveLength(1);
    });

    it("should preserve non-rafter hooks in settings.json", () => {
      const claudeDir = path.join(testHomeDir, ".claude");
      fs.mkdirSync(claudeDir, { recursive: true });
      fs.writeFileSync(
        path.join(claudeDir, "settings.json"),
        JSON.stringify({
          hooks: {
            PreToolUse: [
              { matcher: "Bash", hooks: [{ type: "command", command: "other-tool check" }] },
            ],
          },
        }, null, 2)
      );

      runCli("agent init --with-claude-code", testHomeDir);

      const settings = JSON.parse(
        fs.readFileSync(path.join(claudeDir, "settings.json"), "utf-8")
      );
      const otherHook = settings.hooks.PreToolUse.find(
        (e: any) => (e.hooks || []).some((h: any) => h.command === "other-tool check")
      );
      expect(otherHook).toBeDefined();
    });
  });

  // ── 11b. Claude Code project-scope MCP install (--local --with-claude-code) ──

  describe("Claude Code MCP install (--local --with-claude-code)", () => {
    // Fresh install, idempotency, and non-rafter-server preservation for this
    // adapter are covered by the "MCP adapters — shared install behavior" table
    // above ("Claude Code (--local)" entry, using the hoisted runCliInCwd).
    // The one behavior genuinely unique to --local is scope-gating, below.

    it("does NOT write .mcp.json in user scope (without --local)", () => {
      fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });
      runCli("agent init --with-claude-code", testHomeDir);

      expect(fs.existsSync(path.join(testHomeDir, ".mcp.json"))).toBe(false);
    });
  });

  // ── 12. Codex CLI hooks + skills via CLI ──────────────────────────

  describe("Codex CLI hooks (--with-codex)", () => {
    it("should install hooks to ~/.codex/hooks.json", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });

      const result = runCli("agent init --with-codex", testHomeDir);
      expect(result.exitCode).toBe(0);

      const hooksPath = path.join(testHomeDir, ".codex", "hooks.json");
      expect(fs.existsSync(hooksPath)).toBe(true);

      const config = JSON.parse(fs.readFileSync(hooksPath, "utf-8"));
      expect(config.hooks).toBeDefined();
      expect(config.hooks.PreToolUse).toBeDefined();
      expect(config.hooks.PostToolUse).toBeDefined();

      // Codex matchers per developers.openai.com/codex/hooks (rf-ovql verified):
      // PreToolUse intercepts Bash + apply_patch (file edits via apply_patch).
      // PostToolUse mirrors that write/exec surface (narrowed from `.*` to skip
      // Read/MCP log noise), matching claude-code posttool scoping (sable-h0ah).
      const preMatchers = config.hooks.PreToolUse.map((e: any) => e.matcher);
      expect(preMatchers).toContain("Bash|apply_patch");

      const postMatchers = config.hooks.PostToolUse.map((e: any) => e.matcher);
      expect(postMatchers).toContain("Bash|apply_patch");
    });

    it("should deduplicate hooks on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });

      runCli("agent init --with-codex", testHomeDir);
      runCli("agent init --with-codex", testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".codex", "hooks.json"), "utf-8")
      );
      const rafterPre = config.hooks.PreToolUse.filter(
        (e: any) => (e.hooks || []).some((h: any) => String(h.command ?? "").includes("hook pretool"))
      );
      expect(rafterPre).toHaveLength(1);
    });
  });

  // ── 13. Gemini hooks ──────────────────────────────────────────────

  describe("Gemini hooks (--with-gemini)", () => {
    it("should install BeforeTool/AfterTool hooks to settings.json", () => {
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });

      runCliOk("agent init --with-gemini", testHomeDir);

      const settings = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".gemini", "settings.json"), "utf-8")
      );

      // Should have both MCP and hooks
      expect(settings.mcpServers.rafter).toBeDefined();
      expect(settings.hooks).toBeDefined();
      expect(settings.hooks.BeforeTool).toBeDefined();
      expect(settings.hooks.AfterTool).toBeDefined();

      // BeforeTool matcher targets the mutating Gemini built-in tools by
      // exact name (rf-044o verified against geminicli.com/docs/hooks/reference).
      const beforeMatchers = settings.hooks.BeforeTool.map((e: any) => e.matcher);
      expect(beforeMatchers).toContain("run_shell_command|write_file|replace|edit");

      // Commands use --format gemini
      const beforeCommands = settings.hooks.BeforeTool.flatMap(
        (e: any) => (e.hooks || []).map((h: any) => h.command)
      );
      expect(beforeCommands.some((c: string) => c.includes("--format gemini"))).toBe(true);

      // AfterTool has catch-all
      const afterMatchers = settings.hooks.AfterTool.map((e: any) => e.matcher);
      expect(afterMatchers).toContain(".*");
    });

    it("should deduplicate hooks on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });

      runCliOk("agent init --with-gemini", testHomeDir);
      runCliOk("agent init --with-gemini", testHomeDir);

      const settings = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".gemini", "settings.json"), "utf-8")
      );
      expect(settings.hooks.BeforeTool).toHaveLength(1);
      expect(settings.hooks.AfterTool).toHaveLength(1);
    });
  });

  // ── 14. Cursor hooks + instructions ───────────────────────────────

  describe("Cursor hooks + instructions (--with-cursor)", () => {
    it("should install beforeShellExecution hooks to ~/.cursor/hooks.json", () => {
      fs.mkdirSync(path.join(testHomeDir, ".cursor"), { recursive: true });

      runCli("agent init --with-cursor", testHomeDir);

      const hooksPath = path.join(testHomeDir, ".cursor", "hooks.json");
      expect(fs.existsSync(hooksPath)).toBe(true);

      const config = JSON.parse(fs.readFileSync(hooksPath, "utf-8"));
      expect(config.version).toBe(1);
      expect(config.hooks).toBeDefined();
      expect(config.hooks.beforeShellExecution).toBeDefined();
      expect(config.hooks.beforeShellExecution.length).toBeGreaterThan(0);

      // Verify hook uses --format cursor
      const hook = config.hooks.beforeShellExecution.find(
        (e: any) => e.command?.includes("rafter")
      );
      expect(hook).toBeDefined();
      expect(hook.command).toContain("--format cursor");
      expect(hook.type).toBe("command");
      expect(hook.timeout).toBe(5000);
    });

    it("should install per-skill rule files under ~/.cursor/rules/ (rf-svn3)", () => {
      fs.mkdirSync(path.join(testHomeDir, ".cursor"), { recursive: true });

      runCli("agent init --with-cursor", testHomeDir);

      // The legacy consolidated rafter-security.mdc was retired in rf-svn3 in
      // favor of per-skill rules with trigger-first descriptions.
      const legacy = path.join(testHomeDir, ".cursor", "rules", "rafter-security.mdc");
      expect(fs.existsSync(legacy)).toBe(false);

      for (const name of ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"]) {
        const p = path.join(testHomeDir, ".cursor", "rules", `${name}.mdc`);
        expect(fs.existsSync(p), `missing ${p}`).toBe(true);
      }
    });

    it("should deduplicate hooks on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".cursor"), { recursive: true });

      runCli("agent init --with-cursor", testHomeDir);
      runCli("agent init --with-cursor", testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".cursor", "hooks.json"), "utf-8")
      );
      const rafterHooks = config.hooks.beforeShellExecution.filter(
        (e: any) => e.command?.includes("rafter")
      );
      expect(rafterHooks).toHaveLength(1);
    });
  });

  // ── 15. Windsurf integration (rf-0vr3) ─────────────────────────────
  //
  // The prior install wrote ~/.windsurf/hooks.json with pre_run_command /
  // pre_write_code entries — Windsurf has no documented hook surface, so
  // that file was a silent no-op (research bead rf-s1n3, gap reports
  // rf-p1ri / rf-vayl). Pruned in rf-0vr3 along the same pattern as the
  // Continue.dev prune (rf-cia phase b).
  //
  // Replaced by per-skill rules at .windsurf/rules/<skill>.md (workspace
  // scope per Windsurf docs) + AGENTS.md (Windsurf reads it natively).

  describe("Windsurf integration (--with-windsurf)", () => {
    it("does NOT write ~/.windsurf/hooks.json (Windsurf has no hook surface)", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codeium", "windsurf"), { recursive: true });

      runCli("agent init --with-windsurf", testHomeDir);

      expect(fs.existsSync(path.join(testHomeDir, ".windsurf", "hooks.json"))).toBe(false);
    });

    it("writes per-skill rules under .windsurf/rules/<skill>.md", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codeium", "windsurf"), { recursive: true });

      runCli("agent init --with-windsurf", testHomeDir);

      for (const name of ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"]) {
        const rulePath = path.join(testHomeDir, ".windsurf", "rules", `${name}.md`);
        expect(fs.existsSync(rulePath), `windsurf rule missing: ${name}`).toBe(true);

        const body = fs.readFileSync(rulePath, "utf-8");
        expect(body, `windsurf rule ${name} missing trigger`).toMatch(/^---\ntrigger:\s*model_decision/m);
        expect(body, `windsurf rule ${name} missing description`).toMatch(/^description:\s*"/m);
      }
    });

    it("writes AGENTS.md at workspace root (read natively by Windsurf)", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codeium", "windsurf"), { recursive: true });

      runCli("agent init --with-windsurf", testHomeDir);

      const agentsMd = path.join(testHomeDir, "AGENTS.md");
      expect(fs.existsSync(agentsMd)).toBe(true);
      const body = fs.readFileSync(agentsMd, "utf-8");
      expect(body).toContain("<!-- rafter:start -->");
      expect(body).toContain("<!-- rafter:end -->");
    });

    it("still installs MCP entry under ~/.codeium/windsurf/mcp_config.json", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codeium", "windsurf"), { recursive: true });

      runCli("agent init --with-windsurf", testHomeDir);

      const mcpPath = path.join(testHomeDir, ".codeium", "windsurf", "mcp_config.json");
      expect(fs.existsSync(mcpPath)).toBe(true);
      const cfg = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
      expect(cfg.mcpServers?.rafter).toBeDefined();
    });

    it("is idempotent across repeat installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codeium", "windsurf"), { recursive: true });

      runCli("agent init --with-windsurf", testHomeDir);
      runCli("agent init --with-windsurf", testHomeDir);

      // Rules still present, AGENTS.md still has exactly one rafter block.
      const agentsMd = fs.readFileSync(path.join(testHomeDir, "AGENTS.md"), "utf-8");
      expect((agentsMd.match(/<!-- rafter:start -->/g) ?? []).length).toBe(1);

      for (const name of ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"]) {
        expect(
          fs.existsSync(path.join(testHomeDir, ".windsurf", "rules", `${name}.md`)),
        ).toBe(true);
      }
    });
  });

  // ── 16. Continue.dev hooks (PRUNED in rf-cia phase b) ─────────────
  //
  // Continue.dev does NOT read ~/.continue/settings.json and has no
  // hooks.PreToolUse / PostToolUse field in its config schema. Earlier
  // versions of rafter wrote that file silently; the install was a no-op
  // at runtime. These tests pin the new behavior: NO hook file is written
  // for --with-continue. MCP install (.continue/config.json) is unchanged.

  describe("Continue.dev hooks pruned (--with-continue)", () => {
    it("does NOT write ~/.continue/settings.json (Continue.dev doesn't read it)", () => {
      fs.mkdirSync(path.join(testHomeDir, ".continue"), { recursive: true });

      const result = runCli("agent init --with-continue", testHomeDir);
      expect(result.exitCode).toBe(0);

      const settingsPath = path.join(testHomeDir, ".continue", "settings.json");
      expect(fs.existsSync(settingsPath)).toBe(false);
    });

    it("does NOT touch a pre-existing .continue/settings.json", () => {
      fs.mkdirSync(path.join(testHomeDir, ".continue"), { recursive: true });
      const settingsPath = path.join(testHomeDir, ".continue", "settings.json");
      const userContent = '{"theme":"dark"}';
      fs.writeFileSync(settingsPath, userContent, "utf-8");

      runCli("agent init --with-continue", testHomeDir);

      expect(fs.readFileSync(settingsPath, "utf-8")).toBe(userContent);
    });

    it("still installs MCP server to .continue/config.json", () => {
      fs.mkdirSync(path.join(testHomeDir, ".continue"), { recursive: true });

      runCli("agent init --with-continue", testHomeDir);

      const configPath = path.join(testHomeDir, ".continue", "config.json");
      expect(fs.existsSync(configPath)).toBe(true);
      const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
      const servers = Array.isArray(config.mcpServers)
        ? config.mcpServers
        : Object.values(config.mcpServers || {}).concat(
            Object.entries(config.mcpServers || {}).map(([k, v]: [string, any]) => ({ name: k, ...v }))
          );
      const hasRafter = Array.isArray(config.mcpServers)
        ? config.mcpServers.some((s: any) => s.name === "rafter")
        : !!(config.mcpServers && config.mcpServers.rafter);
      expect(hasRafter).toBe(true);
    });
  });

  // ── 17. Instruction file idempotency ──────────────────────────────

  describe("Instruction file idempotency", () => {
    it("should not duplicate rafter block in CLAUDE.md on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });

      runCli("agent init --with-claude-code", testHomeDir);
      runCli("agent init --with-claude-code", testHomeDir);

      const content = fs.readFileSync(
        path.join(testHomeDir, ".claude", "CLAUDE.md"), "utf-8"
      );
      const starts = (content.match(/<!-- rafter:start -->/g) || []).length;
      expect(starts).toBe(1);
    });

    it("should not duplicate per-skill rule files in Cursor rules on repeated installs (rf-svn3)", () => {
      fs.mkdirSync(path.join(testHomeDir, ".cursor"), { recursive: true });

      runCli("agent init --with-cursor", testHomeDir);
      runCli("agent init --with-cursor", testHomeDir);

      const rulesDir = path.join(testHomeDir, ".cursor", "rules");
      const files = fs.readdirSync(rulesDir).sort();
      // Exactly the four shipped per-skill rules — no duplicates, no legacy.
      expect(files).toEqual([
        "rafter-code-review.mdc",
        "rafter-secure-design.mdc",
        "rafter-skill-review.mdc",
        "rafter.mdc",
      ]);
    });
  });

  // ── 18. All 8 platforms together ──────────────────────────────────

  describe("All 8 platforms config validation", { timeout: 120_000 }, () => {
    it("should generate correct config files for every platform", () => {
      // Set up all platform directories
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".cursor"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".codeium", "windsurf"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".continue"), { recursive: true });
      fs.writeFileSync(path.join(testHomeDir, ".aider.conf.yml"), "# config\n");

      const result = runCli("agent init --all", testHomeDir, 90_000);
      expect(result.exitCode).toBe(0);

      // ── OpenClaw: ClawHub-shaped skill (rf-zgwj) ──
      const openclawSkill = path.join(
        testHomeDir, ".openclaw", "workspace", "skills", "rafter-security", "SKILL.md"
      );
      expect(fs.existsSync(openclawSkill)).toBe(true);
      expect(fs.readFileSync(openclawSkill, "utf-8")).toContain("rafter");

      // ── Claude Code: hooks + skills + instructions ──
      const claudeSettings = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".claude", "settings.json"), "utf-8")
      );
      expect(claudeSettings.hooks.PreToolUse.length).toBeGreaterThanOrEqual(2);
      expect(claudeSettings.hooks.PostToolUse.length).toBeGreaterThanOrEqual(1);
      expect(fs.existsSync(path.join(testHomeDir, ".claude", "skills", "rafter", "SKILL.md"))).toBe(true);
      expect(fs.existsSync(path.join(testHomeDir, ".claude", "CLAUDE.md"))).toBe(true);

      // ── Codex: hooks + skills ──
      expect(fs.existsSync(path.join(testHomeDir, ".codex", "hooks.json"))).toBe(true);
      const codexHooks = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".codex", "hooks.json"), "utf-8")
      );
      expect(codexHooks.hooks.PreToolUse).toBeDefined();
      expect(fs.existsSync(path.join(testHomeDir, ".agents", "skills", "rafter", "SKILL.md"))).toBe(true);

      // ── Gemini: MCP + hooks ──
      const geminiSettings = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".gemini", "settings.json"), "utf-8")
      );
      expect(geminiSettings.mcpServers.rafter).toBeDefined();
      expect(geminiSettings.hooks.BeforeTool).toBeDefined();
      expect(geminiSettings.hooks.AfterTool).toBeDefined();

      // ── Cursor: MCP + hooks + per-skill rules + sub-agent (rf-svn3) ──
      expect(fs.existsSync(path.join(testHomeDir, ".cursor", "mcp.json"))).toBe(true);
      expect(fs.existsSync(path.join(testHomeDir, ".cursor", "hooks.json"))).toBe(true);
      for (const name of ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"]) {
        expect(
          fs.existsSync(path.join(testHomeDir, ".cursor", "rules", `${name}.mdc`)),
          `cursor rule missing: ${name}`,
        ).toBe(true);
      }
      expect(
        fs.existsSync(path.join(testHomeDir, ".cursor", "agents", "rafter.md")),
      ).toBe(true);

      // ── Windsurf: MCP + per-skill rules + AGENTS.md (rf-0vr3) ──
      // hooks.json is NOT written (Windsurf has no hook surface, pruned in rf-0vr3).
      expect(fs.existsSync(path.join(testHomeDir, ".codeium", "windsurf", "mcp_config.json"))).toBe(true);
      expect(fs.existsSync(path.join(testHomeDir, ".windsurf", "hooks.json"))).toBe(false);
      for (const name of ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"]) {
        expect(
          fs.existsSync(path.join(testHomeDir, ".windsurf", "rules", `${name}.md`)),
          `windsurf rule missing: ${name}`,
        ).toBe(true);
      }
      expect(fs.existsSync(path.join(testHomeDir, "AGENTS.md"))).toBe(true);

      // ── Continue.dev: MCP + per-skill rules (rf-acz0); hooks pruned in rf-cia phase b ──
      expect(fs.existsSync(path.join(testHomeDir, ".continue", "config.json"))).toBe(true);
      expect(fs.existsSync(path.join(testHomeDir, ".continue", "settings.json"))).toBe(false);
      const continueConfig = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".continue", "config.json"), "utf-8")
      );
      const continueHasRafter = Array.isArray(continueConfig.mcpServers)
        ? continueConfig.mcpServers.some((s: any) => s.name === "rafter")
        : !!continueConfig.mcpServers?.rafter;
      expect(continueHasRafter).toBe(true);
      for (const name of ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"]) {
        expect(
          fs.existsSync(path.join(testHomeDir, ".continue", "rules", `${name}.md`)),
          `continue rule missing: ${name}`,
        ).toBe(true);
      }

      // ── Aider: RAFTER.md + read: entry (rf-du2o; legacy mcp line not written) ──
      const aiderContent = fs.readFileSync(
        path.join(testHomeDir, ".aider.conf.yml"), "utf-8"
      );
      expect(aiderContent).not.toContain("rafter mcp serve");
      expect(aiderContent).toContain("RAFTER.md");
      expect(fs.existsSync(path.join(testHomeDir, "RAFTER.md"))).toBe(true);
    });
  });
});
