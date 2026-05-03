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
function runCli(
  args: string,
  homeDir: string,
  timeout = 15_000
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
    it("should reject --skip-openclaw as unknown option", () => {
      const result = runCli("agent init --skip-openclaw", testHomeDir);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("unknown option");
    });

    it("should reject --skip-claude-code as unknown option", () => {
      const result = runCli("agent init --skip-claude-code", testHomeDir);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("unknown option");
    });
  });

  // ── 2. Gemini MCP install ──────────────────────────────────────────

  describe("Gemini MCP install (--with-gemini)", () => {
    it("should create settings.json with mcpServers.rafter", () => {
      // Pre-create the .gemini dir so it's "detected"
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });

      const result = runCli("agent init --with-gemini", testHomeDir);
      expect(result.exitCode).toBe(0);

      const settingsPath = path.join(testHomeDir, ".gemini", "settings.json");
      expect(fs.existsSync(settingsPath)).toBe(true);

      const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
      expect(settings.mcpServers).toBeDefined();
      expect(settings.mcpServers.rafter).toBeDefined();
      expect(settings.mcpServers.rafter.command).toBe("rafter");
      expect(settings.mcpServers.rafter.args).toEqual(["mcp", "serve"]);
    });
  });

  // ── 2b. Gemini idempotency and preservation ──────────────────────

  describe("Gemini MCP idempotency", () => {
    it("should not duplicate rafter entry on repeated installs", { timeout: 60_000 }, () => {
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });

      // Run twice
      runCli("agent init --with-gemini", testHomeDir);
      runCli("agent init --with-gemini", testHomeDir);

      const settingsPath = path.join(testHomeDir, ".gemini", "settings.json");
      const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));

      // Should have exactly one rafter entry
      expect(settings.mcpServers.rafter).toBeDefined();
      expect(Object.keys(settings.mcpServers)).toEqual(["rafter"]);
    });

    it("should preserve existing Gemini settings", { timeout: 30_000, retry: 2 }, () => {
      const geminiDir = path.join(testHomeDir, ".gemini");
      fs.mkdirSync(geminiDir, { recursive: true });
      fs.writeFileSync(
        path.join(geminiDir, "settings.json"),
        JSON.stringify({ model: "gemini-2.0-flash", theme: "dark" }, null, 2)
      );

      const result = runCli("agent init --with-gemini", testHomeDir);
      expect(result.exitCode, `CLI exited ${result.exitCode}; stderr: ${result.stderr}`).toBe(0);

      const settings = JSON.parse(
        fs.readFileSync(path.join(geminiDir, "settings.json"), "utf-8")
      );
      // Existing settings preserved
      expect(settings.model).toBe("gemini-2.0-flash");
      expect(settings.theme).toBe("dark");
      // Rafter MCP added
      expect(settings.mcpServers.rafter.command).toBe("rafter");
    });

    it("should preserve existing non-rafter MCP servers", { timeout: 30_000 }, () => {
      const geminiDir = path.join(testHomeDir, ".gemini");
      fs.mkdirSync(geminiDir, { recursive: true });
      fs.writeFileSync(
        path.join(geminiDir, "settings.json"),
        JSON.stringify({
          mcpServers: {
            "other-tool": { command: "other", args: ["serve"] },
          },
        }, null, 2)
      );

      runCli("agent init --with-gemini", testHomeDir);

      const settings = JSON.parse(
        fs.readFileSync(path.join(geminiDir, "settings.json"), "utf-8")
      );
      expect(settings.mcpServers["other-tool"]).toBeDefined();
      expect(settings.mcpServers.rafter).toBeDefined();
    });
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

  // ── 2c. Gemini environment detection ────────────────────────────

  describe("Gemini environment detection", () => {
    it("should warn when --with-gemini used without ~/.gemini", { timeout: 30_000 }, () => {
      // Do NOT create .gemini dir
      const result = runCli("agent init --with-gemini", testHomeDir);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Gemini CLI requested but not detected");

      // Should NOT create settings.json
      expect(
        fs.existsSync(path.join(testHomeDir, ".gemini", "settings.json"))
      ).toBe(false);
    });
  });

  // ── 2d. Gemini corrupted JSON recovery ────────────────────────────

  describe("Gemini corrupted JSON recovery", () => {
    it("should recover from corrupted settings.json", () => {
      const geminiDir = path.join(testHomeDir, ".gemini");
      fs.mkdirSync(geminiDir, { recursive: true });
      fs.writeFileSync(
        path.join(geminiDir, "settings.json"),
        "{not valid json!!"
      );

      const result = runCli("agent init --with-gemini", testHomeDir);
      expect(result.exitCode).toBe(0);

      const settings = JSON.parse(
        fs.readFileSync(path.join(geminiDir, "settings.json"), "utf-8")
      );
      expect(settings.mcpServers.rafter).toBeDefined();
      expect(settings.mcpServers.rafter.command).toBe("rafter");
    });

    it("should update stale rafter entry on re-install", () => {
      const geminiDir = path.join(testHomeDir, ".gemini");
      fs.mkdirSync(geminiDir, { recursive: true });
      // Write a stale rafter entry with wrong args
      fs.writeFileSync(
        path.join(geminiDir, "settings.json"),
        JSON.stringify({
          mcpServers: {
            rafter: { command: "old-rafter", args: ["old-arg"] },
          },
        }, null, 2)
      );

      runCli("agent init --with-gemini", testHomeDir);

      const settings = JSON.parse(
        fs.readFileSync(path.join(geminiDir, "settings.json"), "utf-8")
      );
      // Should be updated to current values
      expect(settings.mcpServers.rafter.command).toBe("rafter");
      expect(settings.mcpServers.rafter.args).toEqual(["mcp", "serve"]);
    });
  });

  // ── 3. Cursor MCP install ──────────────────────────────────────────

  describe("Cursor MCP install (--with-cursor)", () => {
    it("should create mcp.json with mcpServers.rafter", () => {
      fs.mkdirSync(path.join(testHomeDir, ".cursor"), { recursive: true });

      const result = runCli("agent init --with-cursor", testHomeDir);
      expect(result.exitCode).toBe(0);

      const mcpPath = path.join(testHomeDir, ".cursor", "mcp.json");
      expect(fs.existsSync(mcpPath)).toBe(true);

      const config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
      expect(config.mcpServers).toBeDefined();
      expect(config.mcpServers.rafter).toBeDefined();
      expect(config.mcpServers.rafter.command).toBe("rafter");
      expect(config.mcpServers.rafter.args).toEqual(["mcp", "serve"]);
    });
  });

  // ── 3b. Cursor idempotency and preservation ───────────────────────

  describe("Cursor MCP idempotency", () => {
    it("should not duplicate rafter entry on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".cursor"), { recursive: true });

      runCli("agent init --with-cursor", testHomeDir);
      runCli("agent init --with-cursor", testHomeDir);

      const mcpPath = path.join(testHomeDir, ".cursor", "mcp.json");
      const config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
      expect(Object.keys(config.mcpServers)).toEqual(["rafter"]);
    });

    it("should preserve existing non-rafter MCP servers", () => {
      const cursorDir = path.join(testHomeDir, ".cursor");
      fs.mkdirSync(cursorDir, { recursive: true });
      fs.writeFileSync(
        path.join(cursorDir, "mcp.json"),
        JSON.stringify({
          mcpServers: {
            "some-other-mcp": { command: "other", args: ["run"] },
          },
        }, null, 2)
      );

      runCli("agent init --with-cursor", testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(cursorDir, "mcp.json"), "utf-8")
      );
      expect(config.mcpServers["some-other-mcp"]).toBeDefined();
      expect(config.mcpServers.rafter).toBeDefined();
    });

    it("should preserve existing non-MCP settings", () => {
      const cursorDir = path.join(testHomeDir, ".cursor");
      fs.mkdirSync(cursorDir, { recursive: true });
      fs.writeFileSync(
        path.join(cursorDir, "mcp.json"),
        JSON.stringify({ theme: "monokai", fontSize: 14 }, null, 2)
      );

      runCli("agent init --with-cursor", testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(cursorDir, "mcp.json"), "utf-8")
      );
      expect(config.theme).toBe("monokai");
      expect(config.fontSize).toBe(14);
      expect(config.mcpServers.rafter).toBeDefined();
    });
  });

  // ── 3c. Cursor environment detection ──────────────────────────────

  describe("Cursor environment detection", () => {
    it("should warn when --with-cursor used without ~/.cursor", () => {
      const result = runCli("agent init --with-cursor", testHomeDir);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Cursor requested but not detected");
      expect(
        fs.existsSync(path.join(testHomeDir, ".cursor", "mcp.json"))
      ).toBe(false);
    });
  });

  // ── 3d. Cursor corrupted JSON recovery ────────────────────────────

  describe("Cursor corrupted JSON recovery", () => {
    it("should recover from corrupted mcp.json", () => {
      const cursorDir = path.join(testHomeDir, ".cursor");
      fs.mkdirSync(cursorDir, { recursive: true });
      fs.writeFileSync(path.join(cursorDir, "mcp.json"), "{{bad json}}");

      const result = runCli("agent init --with-cursor", testHomeDir);
      expect(result.exitCode).toBe(0);

      const config = JSON.parse(
        fs.readFileSync(path.join(cursorDir, "mcp.json"), "utf-8")
      );
      expect(config.mcpServers.rafter.command).toBe("rafter");
    });
  });

  // ── 4. Windsurf MCP install ────────────────────────────────────────

  describe("Windsurf MCP install (--with-windsurf)", () => {
    it("should create mcp_config.json with mcpServers.rafter", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codeium", "windsurf"), {
        recursive: true,
      });

      const result = runCli("agent init --with-windsurf", testHomeDir);
      expect(result.exitCode).toBe(0);

      const mcpPath = path.join(
        testHomeDir,
        ".codeium",
        "windsurf",
        "mcp_config.json"
      );
      expect(fs.existsSync(mcpPath)).toBe(true);

      const config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
      expect(config.mcpServers).toBeDefined();
      expect(config.mcpServers.rafter).toBeDefined();
      expect(config.mcpServers.rafter.command).toBe("rafter");
      expect(config.mcpServers.rafter.args).toEqual(["mcp", "serve"]);
    });
  });

  // ── 4b. Windsurf idempotency and preservation ─────────────────────

  describe("Windsurf MCP idempotency", () => {
    it("should not duplicate rafter entry on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codeium", "windsurf"), {
        recursive: true,
      });

      runCli("agent init --with-windsurf", testHomeDir);
      runCli("agent init --with-windsurf", testHomeDir);

      const mcpPath = path.join(
        testHomeDir,
        ".codeium",
        "windsurf",
        "mcp_config.json"
      );
      const config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
      expect(Object.keys(config.mcpServers)).toEqual(["rafter"]);
    });

    it("should preserve existing non-rafter MCP servers", () => {
      const windsurfDir = path.join(testHomeDir, ".codeium", "windsurf");
      fs.mkdirSync(windsurfDir, { recursive: true });
      fs.writeFileSync(
        path.join(windsurfDir, "mcp_config.json"),
        JSON.stringify({
          mcpServers: {
            "copilot-mcp": { command: "copilot", args: ["serve"] },
          },
        }, null, 2)
      );

      runCli("agent init --with-windsurf", testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(windsurfDir, "mcp_config.json"), "utf-8")
      );
      expect(config.mcpServers["copilot-mcp"]).toBeDefined();
      expect(config.mcpServers.rafter).toBeDefined();
    });

    it("should preserve existing non-MCP settings", () => {
      const windsurfDir = path.join(testHomeDir, ".codeium", "windsurf");
      fs.mkdirSync(windsurfDir, { recursive: true });
      fs.writeFileSync(
        path.join(windsurfDir, "mcp_config.json"),
        JSON.stringify({ editor: "windsurf", version: 2 }, null, 2)
      );

      runCli("agent init --with-windsurf", testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(windsurfDir, "mcp_config.json"), "utf-8")
      );
      expect(config.editor).toBe("windsurf");
      expect(config.version).toBe(2);
      expect(config.mcpServers.rafter).toBeDefined();
    });
  });

  // ── 4c. Windsurf environment detection ────────────────────────────

  describe("Windsurf environment detection", () => {
    it("should warn when --with-windsurf used without ~/.codeium/windsurf", () => {
      const result = runCli("agent init --with-windsurf", testHomeDir);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Windsurf requested but not detected");
      expect(
        fs.existsSync(
          path.join(testHomeDir, ".codeium", "windsurf", "mcp_config.json")
        )
      ).toBe(false);
    });
  });

  // ── 4d. Windsurf corrupted JSON recovery ──────────────────────────

  describe("Windsurf corrupted JSON recovery", () => {
    it("should recover from corrupted mcp_config.json", () => {
      const windsurfDir = path.join(testHomeDir, ".codeium", "windsurf");
      fs.mkdirSync(windsurfDir, { recursive: true });
      fs.writeFileSync(
        path.join(windsurfDir, "mcp_config.json"),
        "not json at all"
      );

      const result = runCli("agent init --with-windsurf", testHomeDir);
      expect(result.exitCode).toBe(0);

      const config = JSON.parse(
        fs.readFileSync(path.join(windsurfDir, "mcp_config.json"), "utf-8")
      );
      expect(config.mcpServers.rafter.command).toBe("rafter");
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

    it("should preserve existing non-MCP settings", () => {
      const continueDir = path.join(testHomeDir, ".continue");
      fs.mkdirSync(continueDir, { recursive: true });
      fs.writeFileSync(
        path.join(continueDir, "config.json"),
        JSON.stringify({
          models: [{ title: "GPT-4" }],
          allowAnonymousTelemetry: false,
        }, null, 2)
      );

      runCli("agent init --with-continue", testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(continueDir, "config.json"), "utf-8")
      );
      expect(config.models).toEqual([{ title: "GPT-4" }]);
      expect(config.allowAnonymousTelemetry).toBe(false);
      expect(config.mcpServers).toBeDefined();
    });
  });

  // ── 5c. Continue.dev environment detection ────────────────────────

  describe("Continue.dev environment detection", () => {
    it("should warn when --with-continue used without ~/.continue", () => {
      const result = runCli("agent init --with-continue", testHomeDir);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Continue.dev requested but not detected");
      expect(
        fs.existsSync(path.join(testHomeDir, ".continue", "config.json"))
      ).toBe(false);
    });
  });

  // ── 5d. Continue.dev corrupted JSON recovery ──────────────────────

  describe("Continue.dev corrupted JSON recovery", () => {
    it("should recover from corrupted config.json", () => {
      const continueDir = path.join(testHomeDir, ".continue");
      fs.mkdirSync(continueDir, { recursive: true });
      fs.writeFileSync(
        path.join(continueDir, "config.json"),
        "totally broken json{{"
      );

      const result = runCli("agent init --with-continue", testHomeDir);
      expect(result.exitCode).toBe(0);

      const config = JSON.parse(
        fs.readFileSync(path.join(continueDir, "config.json"), "utf-8")
      );
      expect(config.mcpServers).toBeDefined();
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

  // ── 6c. Aider environment detection ───────────────────────────────

  describe("Aider environment detection", () => {
    it("should warn when --with-aider used without ~/.aider.conf.yml", () => {
      // Do NOT create .aider.conf.yml
      const result = runCli("agent init --with-aider", testHomeDir);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Aider requested but not detected");
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

  // ── 8. --all flag ──────────────────────────────────────────────────

  describe("--all flag", () => {
    it("should install all detected platform configs", { timeout: 120_000 }, () => {
      // Pre-create all platform directories
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

      // --all also triggers gitleaks download, so allow extra time
      const result = runCli("agent init --all", testHomeDir, 90_000);
      expect(result.exitCode).toBe(0);

      // Gemini
      const geminiSettings = path.join(
        testHomeDir,
        ".gemini",
        "settings.json"
      );
      expect(fs.existsSync(geminiSettings)).toBe(true);
      const gemini = JSON.parse(fs.readFileSync(geminiSettings, "utf-8"));
      expect(gemini.mcpServers.rafter).toBeDefined();

      // Cursor
      const cursorMcp = path.join(testHomeDir, ".cursor", "mcp.json");
      expect(fs.existsSync(cursorMcp)).toBe(true);
      const cursor = JSON.parse(fs.readFileSync(cursorMcp, "utf-8"));
      expect(cursor.mcpServers.rafter).toBeDefined();

      // Windsurf
      const windsurfMcp = path.join(
        testHomeDir,
        ".codeium",
        "windsurf",
        "mcp_config.json"
      );
      expect(fs.existsSync(windsurfMcp)).toBe(true);
      const windsurf = JSON.parse(fs.readFileSync(windsurfMcp, "utf-8"));
      expect(windsurf.mcpServers.rafter).toBeDefined();

      // Continue.dev
      const continueConfig = path.join(
        testHomeDir,
        ".continue",
        "config.json"
      );
      expect(fs.existsSync(continueConfig)).toBe(true);
      const continueDev = JSON.parse(
        fs.readFileSync(continueConfig, "utf-8")
      );
      expect(continueDev.mcpServers).toBeDefined();

      // Aider — RAFTER.md + read: entry (rf-du2o; legacy mcp line removed)
      const aiderContent = fs.readFileSync(
        path.join(testHomeDir, ".aider.conf.yml"),
        "utf-8"
      );
      expect(aiderContent).not.toContain("rafter mcp serve");
      expect(aiderContent).toContain("RAFTER.md");
      expect(fs.existsSync(path.join(testHomeDir, "RAFTER.md"))).toBe(true);
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

  // ── 10. MCP entry structure validation ────────────────────────────

  describe("MCP entry structure validation", () => {
    it("all MCP adapters should produce identical rafter entry shape", () => {
      // Set up all MCP platforms
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".cursor"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".codeium", "windsurf"), {
        recursive: true,
      });

      runCli(
        "agent init --with-gemini --with-cursor --with-windsurf",
        testHomeDir
      );

      const expected = { command: "rafter", args: ["mcp", "serve"] };

      const gemini = JSON.parse(
        fs.readFileSync(
          path.join(testHomeDir, ".gemini", "settings.json"),
          "utf-8"
        )
      );
      expect(gemini.mcpServers.rafter).toEqual(expected);

      const cursor = JSON.parse(
        fs.readFileSync(
          path.join(testHomeDir, ".cursor", "mcp.json"),
          "utf-8"
        )
      );
      expect(cursor.mcpServers.rafter).toEqual(expected);

      const windsurf = JSON.parse(
        fs.readFileSync(
          path.join(
            testHomeDir,
            ".codeium",
            "windsurf",
            "mcp_config.json"
          ),
          "utf-8"
        )
      );
      expect(windsurf.mcpServers.rafter).toEqual(expected);
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
      const preCommands = settings.hooks.PreToolUse.flatMap(
        (e: any) => (e.hooks || []).map((h: any) => h.command)
      );
      expect(preCommands).toContain("rafter hook pretool");

      const postCommands = settings.hooks.PostToolUse.flatMap(
        (e: any) => (e.hooks || []).map((h: any) => h.command)
      );
      expect(postCommands).toContain("rafter hook posttool");

      // PostToolUse should have catch-all matcher
      const postMatchers = settings.hooks.PostToolUse.map((e: any) => e.matcher);
      expect(postMatchers).toContain(".*");
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

      // Should have exactly 2 PreToolUse entries (Bash + Write|Edit), not 4
      const rafterPreHooks = settings.hooks.PreToolUse.filter(
        (e: any) => (e.hooks || []).some((h: any) => h.command === "rafter hook pretool")
      );
      expect(rafterPreHooks).toHaveLength(2);

      // Exactly 1 PostToolUse entry
      const rafterPostHooks = settings.hooks.PostToolUse.filter(
        (e: any) => (e.hooks || []).some((h: any) => h.command === "rafter hook posttool")
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
    function runCliInCwd(args: string, cwd: string, homeDir: string) {
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

    it("writes .mcp.json at project root with rafter mcpServers entry", () => {
      const r = runCliInCwd("agent init --local --with-claude-code", testHomeDir, testHomeDir);
      expect(r.exitCode, `exit ${r.exitCode}; stderr: ${r.stderr}`).toBe(0);

      const mcpPath = path.join(testHomeDir, ".mcp.json");
      expect(fs.existsSync(mcpPath)).toBe(true);

      const config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
      expect(config.mcpServers).toBeDefined();
      expect(config.mcpServers.rafter).toBeDefined();
      expect(config.mcpServers.rafter.command).toBe("rafter");
      expect(config.mcpServers.rafter.args).toEqual(["mcp", "serve"]);
    });

    it("is idempotent on repeated installs", () => {
      runCliInCwd("agent init --local --with-claude-code", testHomeDir, testHomeDir);
      runCliInCwd("agent init --local --with-claude-code", testHomeDir, testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".mcp.json"), "utf-8")
      );
      expect(Object.keys(config.mcpServers)).toEqual(["rafter"]);
    });

    it("preserves existing non-rafter MCP servers", () => {
      fs.writeFileSync(
        path.join(testHomeDir, ".mcp.json"),
        JSON.stringify({ mcpServers: { other: { command: "other", args: [] } } }, null, 2)
      );

      runCliInCwd("agent init --local --with-claude-code", testHomeDir, testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".mcp.json"), "utf-8")
      );
      expect(config.mcpServers.other).toBeDefined();
      expect(config.mcpServers.rafter).toBeDefined();
    });

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

      // Codex has Bash matcher for PreToolUse
      const preMatchers = config.hooks.PreToolUse.map((e: any) => e.matcher);
      expect(preMatchers).toContain("Bash");

      // PostToolUse has catch-all
      const postMatchers = config.hooks.PostToolUse.map((e: any) => e.matcher);
      expect(postMatchers).toContain(".*");
    });

    it("should deduplicate hooks on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });

      runCli("agent init --with-codex", testHomeDir);
      runCli("agent init --with-codex", testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".codex", "hooks.json"), "utf-8")
      );
      const rafterPre = config.hooks.PreToolUse.filter(
        (e: any) => (e.hooks || []).some((h: any) => h.command?.startsWith("rafter hook pretool"))
      );
      expect(rafterPre).toHaveLength(1);
    });
  });

  // ── 13. Gemini hooks ──────────────────────────────────────────────

  describe("Gemini hooks (--with-gemini)", () => {
    it("should install BeforeTool/AfterTool hooks to settings.json", () => {
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });

      runCli("agent init --with-gemini", testHomeDir);

      const settings = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".gemini", "settings.json"), "utf-8")
      );

      // Should have both MCP and hooks
      expect(settings.mcpServers.rafter).toBeDefined();
      expect(settings.hooks).toBeDefined();
      expect(settings.hooks.BeforeTool).toBeDefined();
      expect(settings.hooks.AfterTool).toBeDefined();

      // BeforeTool matcher targets shell and write_file
      const beforeMatchers = settings.hooks.BeforeTool.map((e: any) => e.matcher);
      expect(beforeMatchers).toContain("shell|write_file");

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

      runCli("agent init --with-gemini", testHomeDir);
      runCli("agent init --with-gemini", testHomeDir);

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

      // ── OpenClaw: skill file ──
      const openclawSkill = path.join(testHomeDir, ".openclaw", "skills", "rafter-security.md");
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
