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

describe("OpenClaw Integration", () => {
  let testHomeDir: string;

  beforeEach(() => {
    testHomeDir = createTempDir("rafter-openclaw-test");
  });

  afterEach(() => {
    cleanupDir(testHomeDir);
  });

  // ── 1. Skill installation (rf-zgwj — ClawHub-shaped) ─────────────
  //
  // Per docs.openclaw.ai/tools/skills, OpenClaw auto-discovers skills from
  // <workspace>/skills/<name>/SKILL.md. Default workspace is
  // ~/.openclaw/workspace/. Earlier rafter versions wrote to
  // ~/.openclaw/skills/rafter-security.md (a path OpenClaw never read).
  // Migrated in rf-zgwj.

  const SKILL_DIR_REL = path.join(".openclaw", "workspace", "skills", "rafter-security");
  const SKILL_FILE_REL = path.join(SKILL_DIR_REL, "SKILL.md");
  const LEGACY_SKILL_REL = path.join(".openclaw", "skills", "rafter-security.md");

  describe("Skill installation (--with-openclaw)", () => {
    it("writes SKILL.md at the canonical workspace path", () => {
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });

      const result = runCli("agent init --with-openclaw", testHomeDir);
      expect(result.exitCode).toBe(0);

      const skillPath = path.join(testHomeDir, SKILL_FILE_REL);
      expect(fs.existsSync(skillPath)).toBe(true);
    });

    it("skill SKILL.md contains required ClawHub frontmatter", () => {
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });
      runCli("agent init --with-openclaw", testHomeDir);

      const skillContent = fs.readFileSync(
        path.join(testHomeDir, SKILL_FILE_REL),
        "utf-8",
      );
      expect(skillContent).toMatch(/^---\n/);
      // ClawHub-required top-level fields (rf-zgwj).
      expect(skillContent).toMatch(/^name:\s*rafter-security/m);
      expect(skillContent).toMatch(/^description:\s+/m);
      expect(skillContent).toMatch(/^version:\s+/m);
      // OpenClaw runtime metadata block (under metadata.openclaw or alias).
      expect(skillContent).toContain("openclaw:");
      expect(skillContent).toContain("skillKey: rafter-security");
      const parts = skillContent.split("---");
      expect(parts.length).toBeGreaterThanOrEqual(3);
    });

    it("skill should contain rafter CLI references", () => {
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });
      runCli("agent init --with-openclaw", testHomeDir);

      const skillContent = fs.readFileSync(
        path.join(testHomeDir, SKILL_FILE_REL),
        "utf-8",
      );
      expect(skillContent).toContain("rafter");
    });

    it("creates the workspace skills dir tree if absent", () => {
      // Only create .openclaw — not the workspace/skills/<name>/ tree.
      fs.mkdirSync(path.join(testHomeDir, ".openclaw"), { recursive: true });

      runCli("agent init --with-openclaw", testHomeDir);

      expect(
        fs.statSync(path.join(testHomeDir, SKILL_DIR_REL)).isDirectory(),
      ).toBe(true);
    });

    it("strips the rafter ≤ 0.7.7 legacy file on reinstall (rf-zgwj migration)", () => {
      // Pre-stage the legacy file as if from an old install.
      fs.mkdirSync(path.join(testHomeDir, ".openclaw", "skills"), { recursive: true });
      fs.writeFileSync(
        path.join(testHomeDir, LEGACY_SKILL_REL),
        "---\nname: rafter-security\nversion: 0.6.0\n---\n# Old content\n",
      );

      runCli("agent init --with-openclaw", testHomeDir);

      // New shape exists at the canonical path.
      expect(fs.existsSync(path.join(testHomeDir, SKILL_FILE_REL))).toBe(true);
      // Legacy file removed.
      expect(fs.existsSync(path.join(testHomeDir, LEGACY_SKILL_REL))).toBe(false);
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

      expect(fs.existsSync(path.join(testHomeDir, SKILL_FILE_REL))).toBe(false);
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
        path.join(testHomeDir, SKILL_FILE_REL),
        "utf-8",
      );

      runCli("agent init --with-openclaw", testHomeDir);
      const secondContent = fs.readFileSync(
        path.join(testHomeDir, SKILL_FILE_REL),
        "utf-8",
      );

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

      expect(fs.existsSync(path.join(testHomeDir, SKILL_FILE_REL))).toBe(false);
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

    it("getOpenClawSkillsDir returns the canonical workspace skills path (rf-zgwj)", async () => {
      const { SkillManager } = await import("../src/utils/skill-manager.js");
      const sm = new SkillManager();

      const expected = path.join(os.homedir(), ".openclaw", "workspace", "skills");
      expect(sm.getOpenClawSkillsDir()).toBe(expected);
    });

    it("getRafterSkillPath returns the SKILL.md inside the skill directory (rf-zgwj)", async () => {
      const { SkillManager } = await import("../src/utils/skill-manager.js");
      const sm = new SkillManager();

      const expected = path.join(
        os.homedir(),
        ".openclaw",
        "workspace",
        "skills",
        "rafter-security",
        "SKILL.md",
      );
      expect(sm.getRafterSkillPath()).toBe(expected);
    });

    it("getLegacyRafterSkillPath returns the rafter ≤ 0.7.7 path (rf-zgwj migration)", async () => {
      const { SkillManager } = await import("../src/utils/skill-manager.js");
      const sm = new SkillManager();

      const expected = path.join(os.homedir(), ".openclaw", "skills", "rafter-security.md");
      expect(sm.getLegacyRafterSkillPath()).toBe(expected);
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

      // OpenClaw skill at the canonical ClawHub path (rf-zgwj).
      expect(fs.existsSync(path.join(testHomeDir, SKILL_FILE_REL))).toBe(true);

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

      // OpenClaw skill at the canonical ClawHub path (rf-zgwj).
      expect(fs.existsSync(path.join(testHomeDir, SKILL_FILE_REL))).toBe(true);

      // Gemini MCP
      expect(
        fs.existsSync(
          path.join(testHomeDir, ".gemini", "settings.json")
        )
      ).toBe(true);
    });
  });
});
