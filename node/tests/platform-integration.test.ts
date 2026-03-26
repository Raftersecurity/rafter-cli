import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { randomBytes } from "crypto";
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";

// These tests spawn real CLI processes via npx tsx — slow under parallel load
vi.setConfig({ testTimeout: 30_000 });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_ENTRY = path.join(PROJECT_ROOT, "src", "index.ts");

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
  timeout = 30_000
): { stdout: string; stderr: string; exitCode: number } {
  try {
    const stdout = execSync(`npx tsx ${CLI_ENTRY} ${args}`, {
      cwd: PROJECT_ROOT,
      encoding: "utf-8",
      timeout,
      env: {
        ...process.env,
        HOME: homeDir,
        // Prevent config manager from using real home
        XDG_CONFIG_HOME: path.join(homeDir, ".config"),
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (e: any) {
    return {
      stdout: e.stdout || "",
      stderr: e.stderr || "",
      exitCode: e.status ?? 1,
    };
  }
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

    it("should preserve existing Gemini settings", { timeout: 30_000 }, () => {
      const geminiDir = path.join(testHomeDir, ".gemini");
      fs.mkdirSync(geminiDir, { recursive: true });
      fs.writeFileSync(
        path.join(geminiDir, "settings.json"),
        JSON.stringify({ model: "gemini-2.0-flash", theme: "dark" }, null, 2)
      );

      const result = runCli("agent init --with-gemini", testHomeDir);
      expect(result.exitCode).toBe(0);

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

  // ── 5. Continue.dev MCP install ────────────────────────────────────

  describe("Continue.dev MCP install (--with-continue)", () => {
    it("should create config.json with mcpServers containing rafter", () => {
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

  // ── 6. Aider MCP install ───────────────────────────────────────────

  describe("Aider MCP install (--with-aider)", () => {
    it("should create .aider.conf.yml with rafter mcp serve", () => {
      // Aider detection checks for the file itself, not a directory
      fs.writeFileSync(
        path.join(testHomeDir, ".aider.conf.yml"),
        "# existing aider config\n"
      );

      const result = runCli("agent init --with-aider", testHomeDir);
      expect(result.exitCode).toBe(0);

      const configPath = path.join(testHomeDir, ".aider.conf.yml");
      expect(fs.existsSync(configPath)).toBe(true);

      const content = fs.readFileSync(configPath, "utf-8");
      expect(content).toContain("rafter mcp serve");
      expect(content).toContain("mcp-server-command: rafter mcp serve");
      // Should preserve existing content
      expect(content).toContain("# existing aider config");
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
      // Aider file existed before but should NOT have rafter appended
      const aiderContent = fs.readFileSync(
        path.join(testHomeDir, ".aider.conf.yml"),
        "utf-8"
      );
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

      // Aider
      const aiderContent = fs.readFileSync(
        path.join(testHomeDir, ".aider.conf.yml"),
        "utf-8"
      );
      expect(aiderContent).toContain("rafter mcp serve");
    });
  });
});
