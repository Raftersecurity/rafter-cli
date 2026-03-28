import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { randomBytes } from "crypto";
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";

// CLI integration tests spawn subprocesses — allow generous timeouts
vi.setConfig({ testTimeout: 30_000 });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_ENTRY = path.join(PROJECT_ROOT, "src", "index.ts");

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

describe("OpenClaw Integration", () => {
  let testHomeDir: string;

  beforeEach(() => {
    testHomeDir = createTempDir("rafter-openclaw-test");
  });

  afterEach(() => {
    cleanupDir(testHomeDir);
  });

  // ── 1. Skill installation ─────────────────────────────────────────

  describe("Skill installation (--with-openclaw)", () => {
    it("should create rafter-security.md in ~/.openclaw/skills/", () => {
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });

      const result = runCli("agent init --with-openclaw", testHomeDir);
      expect(result.exitCode).toBe(0);

      const skillPath = path.join(
        testHomeDir,
        ".openclaw",
        "skills",
        "rafter-security.md"
      );
      expect(fs.existsSync(skillPath)).toBe(true);
    });

    it("skill should contain valid YAML frontmatter", () => {
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });
      runCli("agent init --with-openclaw", testHomeDir);

      const skillContent = fs.readFileSync(
        path.join(
          testHomeDir,
          ".openclaw",
          "skills",
          "rafter-security.md"
        ),
        "utf-8"
      );
      expect(skillContent).toMatch(/^---\n/);
      // OpenClaw uses openclaw.skillKey instead of name:
      expect(skillContent).toContain("openclaw:");
      expect(skillContent).toContain("skillKey: rafter-security");
      expect(skillContent).toContain("version:");
      // Should end with proper content after frontmatter
      const parts = skillContent.split("---");
      expect(parts.length).toBeGreaterThanOrEqual(3); // before, frontmatter, content
    });

    it("skill should contain rafter CLI references", () => {
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });
      runCli("agent init --with-openclaw", testHomeDir);

      const skillContent = fs.readFileSync(
        path.join(
          testHomeDir,
          ".openclaw",
          "skills",
          "rafter-security.md"
        ),
        "utf-8"
      );
      expect(skillContent).toContain("rafter");
    });

    it("should create skills directory if it does not exist", () => {
      // Only create .openclaw, not .openclaw/skills
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });

      runCli("agent init --with-openclaw", testHomeDir);

      expect(
        fs.statSync(
          path.join(testHomeDir, ".openclaw", "skills")
        ).isDirectory()
      ).toBe(true);
    });
  });

  // ── 2. Environment detection ──────────────────────────────────────

  describe("OpenClaw environment detection", () => {
    it("should warn when --with-openclaw used without ~/.openclaw", () => {
      // Do NOT create .openclaw dir
      const result = runCli("agent init --with-openclaw", testHomeDir);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain(
        "OpenClaw requested but not detected"
      );
    });

    it("should NOT install skill when ~/.openclaw is absent", () => {
      runCli("agent init --with-openclaw", testHomeDir);

      expect(
        fs.existsSync(
          path.join(
            testHomeDir,
            ".openclaw",
            "skills",
            "rafter-security.md"
          )
        )
      ).toBe(false);
    });

    it("should detect .openclaw and install when requested", () => {
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });

      const result = runCli("agent init --with-openclaw", testHomeDir);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).not.toContain(
        "OpenClaw requested but not detected"
      );
      expect(result.stdout).toContain("Installed Rafter Security skill");
    });
  });

  // ── 3. Idempotency ────────────────────────────────────────────────

  describe("OpenClaw idempotency", () => {
    it("should not corrupt skill on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });

      runCli("agent init --with-openclaw", testHomeDir);
      const firstContent = fs.readFileSync(
        path.join(
          testHomeDir,
          ".openclaw",
          "skills",
          "rafter-security.md"
        ),
        "utf-8"
      );

      runCli("agent init --with-openclaw", testHomeDir);
      const secondContent = fs.readFileSync(
        path.join(
          testHomeDir,
          ".openclaw",
          "skills",
          "rafter-security.md"
        ),
        "utf-8"
      );

      // Content should be identical after re-install
      expect(secondContent).toBe(firstContent);
    });

    it("should succeed silently when skill already installed", () => {
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });

      const first = runCli("agent init --with-openclaw", testHomeDir);
      expect(first.exitCode).toBe(0);

      const second = runCli("agent init --with-openclaw", testHomeDir);
      expect(second.exitCode).toBe(0);
    });
  });

  // ── 4. Opt-in gating ─────────────────────────────────────────────

  describe("Opt-in gating", () => {
    it("plain 'agent init' should NOT install OpenClaw skill", () => {
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });

      const result = runCli("agent init", testHomeDir);
      expect(result.exitCode).toBe(0);

      expect(
        fs.existsSync(
          path.join(
            testHomeDir,
            ".openclaw",
            "skills",
            "rafter-security.md"
          )
        )
      ).toBe(false);
    });
  });

  // ── 5. Skill Manager unit tests ──────────────────────────────────

  describe("SkillManager", () => {
    it("parseSkillMetadata extracts name and version", async () => {
      const { SkillManager } = await import("../src/utils/skill-manager.js");
      const sm = new SkillManager();

      const content =
        '---\nname: rafter-security\nversion: 0.6.4\nrafter_cli_version: 0.6.4\nlast_updated: 2025-01-01\n---\n# Content\n';
      const metadata = sm.parseSkillMetadata(content);

      expect(metadata).not.toBeNull();
      expect(metadata!.name).toBe("rafter-security");
      expect(metadata!.version).toBe("0.6.4");
    });

    it("parseSkillMetadata returns null for missing frontmatter", async () => {
      const { SkillManager } = await import("../src/utils/skill-manager.js");
      const sm = new SkillManager();

      const metadata = sm.parseSkillMetadata("# Just markdown\nNo frontmatter");
      expect(metadata).toBeNull();
    });

    it("parseSkillMetadata returns null for incomplete frontmatter", async () => {
      const { SkillManager } = await import("../src/utils/skill-manager.js");
      const sm = new SkillManager();

      const metadata = sm.parseSkillMetadata("---\nname: rafter\n---\n");
      expect(metadata).toBeNull();
    });

    it("calculateContentHash ignores frontmatter", async () => {
      const { SkillManager } = await import("../src/utils/skill-manager.js");
      const sm = new SkillManager();

      const content1 =
        "---\nname: rafter\nversion: 1.0\n---\n# Same Content\n";
      const content2 =
        "---\nname: rafter\nversion: 2.0\n---\n# Same Content\n";

      expect(sm.calculateContentHash(content1)).toBe(
        sm.calculateContentHash(content2)
      );
    });

    it("calculateContentHash detects body changes", async () => {
      const { SkillManager } = await import("../src/utils/skill-manager.js");
      const sm = new SkillManager();

      const content1 =
        "---\nname: rafter\nversion: 1.0\n---\n# Original Content\n";
      const content2 =
        "---\nname: rafter\nversion: 1.0\n---\n# Modified Content\n";

      expect(sm.calculateContentHash(content1)).not.toBe(
        sm.calculateContentHash(content2)
      );
    });

    it("getOpenClawSkillsDir returns correct path", async () => {
      const { SkillManager } = await import("../src/utils/skill-manager.js");
      const sm = new SkillManager();

      const expected = path.join(os.homedir(), ".openclaw", "skills");
      expect(sm.getOpenClawSkillsDir()).toBe(expected);
    });

    it("getRafterSkillPath returns correct path", async () => {
      const { SkillManager } = await import("../src/utils/skill-manager.js");
      const sm = new SkillManager();

      const expected = path.join(
        os.homedir(),
        ".openclaw",
        "skills",
        "rafter-security.md"
      );
      expect(sm.getRafterSkillPath()).toBe(expected);
    });
  });

  // ── 6. Coexistence ────────────────────────────────────────────────

  describe("Coexistence with other adapters", () => {
    it("should install alongside Codex skills without conflict", () => {
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });

      const result = runCli(
        "agent init --with-openclaw --with-codex",
        testHomeDir
      );
      expect(result.exitCode).toBe(0);

      // OpenClaw skill
      expect(
        fs.existsSync(
          path.join(
            testHomeDir,
            ".openclaw",
            "skills",
            "rafter-security.md"
          )
        )
      ).toBe(true);

      // Codex skills
      expect(
        fs.existsSync(
          path.join(
            testHomeDir,
            ".agents",
            "skills",
            "rafter",
            "SKILL.md"
          )
        )
      ).toBe(true);
    });

    it("should install alongside MCP adapters without conflict", () => {
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".gemini"), { recursive: true });

      const result = runCli(
        "agent init --with-openclaw --with-gemini",
        testHomeDir
      );
      expect(result.exitCode).toBe(0);

      // OpenClaw skill
      expect(
        fs.existsSync(
          path.join(
            testHomeDir,
            ".openclaw",
            "skills",
            "rafter-security.md"
          )
        )
      ).toBe(true);

      // Gemini MCP
      expect(
        fs.existsSync(
          path.join(testHomeDir, ".gemini", "settings.json")
        )
      ).toBe(true);
    });
  });
});
