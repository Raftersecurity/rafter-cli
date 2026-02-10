import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Test helper to create temporary directories
function createTempDir(prefix: string): string {
  const tmpDir = path.join(os.tmpdir(), `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`);
  fs.mkdirSync(tmpDir, { recursive: true });
  return tmpDir;
}

// Test helper to cleanup directory
function cleanupDir(dir: string) {
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// Mock implementation of installClaudeCodeSkills
async function installClaudeCodeSkills(homeDir: string, skillsSourceDir: string): Promise<void> {
  const claudeSkillsDir = path.join(homeDir, ".claude", "skills");

  // Ensure .claude/skills directory exists
  if (!fs.existsSync(claudeSkillsDir)) {
    fs.mkdirSync(claudeSkillsDir, { recursive: true });
  }

  // Install Backend Skill
  const backendSkillDir = path.join(claudeSkillsDir, "rafter");
  const backendSkillPath = path.join(backendSkillDir, "SKILL.md");
  const backendTemplatePath = path.join(skillsSourceDir, "rafter", "SKILL.md");

  if (!fs.existsSync(backendSkillDir)) {
    fs.mkdirSync(backendSkillDir, { recursive: true });
  }

  if (fs.existsSync(backendTemplatePath)) {
    fs.copyFileSync(backendTemplatePath, backendSkillPath);
  } else {
    throw new Error(`Backend skill template not found at ${backendTemplatePath}`);
  }

  // Install Agent Security Skill
  const agentSkillDir = path.join(claudeSkillsDir, "rafter-agent-security");
  const agentSkillPath = path.join(agentSkillDir, "SKILL.md");
  const agentTemplatePath = path.join(skillsSourceDir, "rafter-agent-security", "SKILL.md");

  if (!fs.existsSync(agentSkillDir)) {
    fs.mkdirSync(agentSkillDir, { recursive: true });
  }

  if (fs.existsSync(agentTemplatePath)) {
    fs.copyFileSync(agentTemplatePath, agentSkillPath);
  } else {
    throw new Error(`Agent Security skill template not found at ${agentTemplatePath}`);
  }
}

describe("Claude Code Integration", () => {
  let testHomeDir: string;
  let testSkillsSourceDir: string;

  beforeEach(() => {
    testHomeDir = createTempDir("rafter-home");
    testSkillsSourceDir = createTempDir("rafter-skills-source");

    // Create mock skill template files
    const backendSkillDir = path.join(testSkillsSourceDir, "rafter");
    fs.mkdirSync(backendSkillDir, { recursive: true });
    fs.writeFileSync(
      path.join(backendSkillDir, "SKILL.md"),
      `---
name: rafter
description: "Backend scanning skill"
version: 0.4.0
allowed-tools: [Bash]
---

# Rafter Backend Skill

Test content for backend skill.
`
    );

    const agentSkillDir = path.join(testSkillsSourceDir, "rafter-agent-security");
    fs.mkdirSync(agentSkillDir, { recursive: true });
    fs.writeFileSync(
      path.join(agentSkillDir, "SKILL.md"),
      `---
name: rafter-agent-security
description: "Agent security skill"
version: 0.4.0
disable-model-invocation: true
allowed-tools: [Bash, Read, Glob, Grep]
---

# Rafter Agent Security Skill

Test content for agent security skill.
`
    );
  });

  afterEach(() => {
    cleanupDir(testHomeDir);
    cleanupDir(testSkillsSourceDir);
  });

  describe("Claude Code Detection", () => {
    it("should detect Claude Code when .claude directory exists", () => {
      const claudeDir = path.join(testHomeDir, ".claude");
      fs.mkdirSync(claudeDir, { recursive: true });

      const hasClaudeCode = fs.existsSync(claudeDir);
      expect(hasClaudeCode).toBe(true);
    });

    it("should not detect Claude Code when .claude directory does not exist", () => {
      const claudeDir = path.join(testHomeDir, ".claude");
      const hasClaudeCode = fs.existsSync(claudeDir);

      expect(hasClaudeCode).toBe(false);
    });

    it("should create .claude/skills directory if it doesn't exist", async () => {
      const claudeSkillsDir = path.join(testHomeDir, ".claude", "skills");

      expect(fs.existsSync(claudeSkillsDir)).toBe(false);

      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      expect(fs.existsSync(claudeSkillsDir)).toBe(true);
    });
  });

  describe("Skill Installation", () => {
    it("should install backend skill to correct location", async () => {
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const backendSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter", "SKILL.md");
      expect(fs.existsSync(backendSkillPath)).toBe(true);

      const content = fs.readFileSync(backendSkillPath, "utf-8");
      expect(content).toContain("name: rafter");
      expect(content).toContain("Backend scanning skill");
      expect(content).toContain("Rafter Backend Skill");
    });

    it("should install agent security skill to correct location", async () => {
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const agentSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter-agent-security", "SKILL.md");
      expect(fs.existsSync(agentSkillPath)).toBe(true);

      const content = fs.readFileSync(agentSkillPath, "utf-8");
      expect(content).toContain("name: rafter-agent-security");
      expect(content).toContain("disable-model-invocation: true");
      expect(content).toContain("Rafter Agent Security Skill");
    });

    it("should install both skills in single invocation", async () => {
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const backendSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter", "SKILL.md");
      const agentSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter-agent-security", "SKILL.md");

      expect(fs.existsSync(backendSkillPath)).toBe(true);
      expect(fs.existsSync(agentSkillPath)).toBe(true);
    });

    it("should create skill directories if they don't exist", async () => {
      const backendSkillDir = path.join(testHomeDir, ".claude", "skills", "rafter");
      const agentSkillDir = path.join(testHomeDir, ".claude", "skills", "rafter-agent-security");

      expect(fs.existsSync(backendSkillDir)).toBe(false);
      expect(fs.existsSync(agentSkillDir)).toBe(false);

      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      expect(fs.existsSync(backendSkillDir)).toBe(true);
      expect(fs.existsSync(agentSkillDir)).toBe(true);
    });

    it("should overwrite existing skills on reinstall", async () => {
      // First installation
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const backendSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter", "SKILL.md");
      const originalContent = fs.readFileSync(backendSkillPath, "utf-8");

      // Modify the skill file
      fs.writeFileSync(backendSkillPath, "# Modified Content");
      expect(fs.readFileSync(backendSkillPath, "utf-8")).toBe("# Modified Content");

      // Reinstall
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      // Should be back to original content
      const newContent = fs.readFileSync(backendSkillPath, "utf-8");
      expect(newContent).toBe(originalContent);
      expect(newContent).not.toBe("# Modified Content");
    });
  });

  describe("Error Handling", () => {
    it("should throw error when backend skill template is missing", async () => {
      // Remove backend skill template
      const backendSkillPath = path.join(testSkillsSourceDir, "rafter", "SKILL.md");
      fs.unlinkSync(backendSkillPath);

      await expect(installClaudeCodeSkills(testHomeDir, testSkillsSourceDir)).rejects.toThrow(
        "Backend skill template not found"
      );
    });

    it("should throw error when agent security skill template is missing", async () => {
      // Remove agent security skill template
      const agentSkillPath = path.join(testSkillsSourceDir, "rafter-agent-security", "SKILL.md");
      fs.unlinkSync(agentSkillPath);

      await expect(installClaudeCodeSkills(testHomeDir, testSkillsSourceDir)).rejects.toThrow(
        "Agent Security skill template not found"
      );
    });

    it("should handle non-existent home directory gracefully", async () => {
      const nonExistentHome = path.join(os.tmpdir(), "nonexistent-home-" + Date.now());

      // Should not throw - mkdirSync with recursive: true handles this
      await expect(installClaudeCodeSkills(nonExistentHome, testSkillsSourceDir)).resolves.not.toThrow();

      // Verify skills were installed
      expect(fs.existsSync(path.join(nonExistentHome, ".claude", "skills", "rafter", "SKILL.md"))).toBe(true);

      // Cleanup
      cleanupDir(nonExistentHome);
    });
  });

  describe("Skill Content Validation", () => {
    it("backend skill should be auto-invocable (no disable-model-invocation)", async () => {
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const backendSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter", "SKILL.md");
      const content = fs.readFileSync(backendSkillPath, "utf-8");

      // Should NOT have disable-model-invocation
      expect(content).not.toContain("disable-model-invocation");
    });

    it("agent security skill should be user-only (has disable-model-invocation: true)", async () => {
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const agentSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter-agent-security", "SKILL.md");
      const content = fs.readFileSync(agentSkillPath, "utf-8");

      // Should have disable-model-invocation: true
      expect(content).toContain("disable-model-invocation: true");
    });

    it("backend skill should have correct allowed-tools", async () => {
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const backendSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter", "SKILL.md");
      const content = fs.readFileSync(backendSkillPath, "utf-8");

      expect(content).toContain("allowed-tools: [Bash]");
    });

    it("agent security skill should have correct allowed-tools", async () => {
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const agentSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter-agent-security", "SKILL.md");
      const content = fs.readFileSync(agentSkillPath, "utf-8");

      expect(content).toContain("allowed-tools: [Bash, Read, Glob, Grep]");
    });

    it("both skills should have version 0.4.0", async () => {
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const backendSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter", "SKILL.md");
      const agentSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter-agent-security", "SKILL.md");

      const backendContent = fs.readFileSync(backendSkillPath, "utf-8");
      const agentContent = fs.readFileSync(agentSkillPath, "utf-8");

      expect(backendContent).toContain("version: 0.4.0");
      expect(agentContent).toContain("version: 0.4.0");
    });
  });

  describe("File Permissions", () => {
    it("installed skills should be readable", async () => {
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const backendSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter", "SKILL.md");
      const agentSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter-agent-security", "SKILL.md");

      // Test by trying to read files
      expect(() => fs.readFileSync(backendSkillPath, "utf-8")).not.toThrow();
      expect(() => fs.readFileSync(agentSkillPath, "utf-8")).not.toThrow();
    });

    it("skill directories should be accessible", async () => {
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const backendSkillDir = path.join(testHomeDir, ".claude", "skills", "rafter");
      const agentSkillDir = path.join(testHomeDir, ".claude", "skills", "rafter-agent-security");

      // Test by trying to list directories
      expect(() => fs.readdirSync(backendSkillDir)).not.toThrow();
      expect(() => fs.readdirSync(agentSkillDir)).not.toThrow();
    });
  });

  describe("Integration Scenarios", () => {
    it("should handle sequential installs (update scenario)", async () => {
      // First install
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const backendSkillPath = path.join(testHomeDir, ".claude", "skills", "rafter", "SKILL.md");
      const firstInstallStat = fs.statSync(backendSkillPath);

      // Wait a bit to ensure different timestamp
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Second install (simulate update)
      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      const secondInstallStat = fs.statSync(backendSkillPath);

      // File should be updated (different mtime)
      expect(secondInstallStat.mtimeMs).toBeGreaterThan(firstInstallStat.mtimeMs);
    });

    it("should work with existing .claude directory", async () => {
      // Pre-create .claude directory
      const claudeDir = path.join(testHomeDir, ".claude");
      fs.mkdirSync(claudeDir, { recursive: true });
      fs.writeFileSync(path.join(claudeDir, "config.json"), '{"test": true}');

      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      // Original config should still exist
      expect(fs.existsSync(path.join(claudeDir, "config.json"))).toBe(true);

      // Skills should be installed
      expect(fs.existsSync(path.join(claudeDir, "skills", "rafter", "SKILL.md"))).toBe(true);
      expect(fs.existsSync(path.join(claudeDir, "skills", "rafter-agent-security", "SKILL.md"))).toBe(true);
    });

    it("should work with existing .claude/skills directory", async () => {
      // Pre-create .claude/skills directory with other skills
      const skillsDir = path.join(testHomeDir, ".claude", "skills");
      fs.mkdirSync(skillsDir, { recursive: true });

      const otherSkillDir = path.join(skillsDir, "other-skill");
      fs.mkdirSync(otherSkillDir, { recursive: true });
      fs.writeFileSync(path.join(otherSkillDir, "SKILL.md"), "# Other Skill");

      await installClaudeCodeSkills(testHomeDir, testSkillsSourceDir);

      // Other skill should still exist
      expect(fs.existsSync(path.join(skillsDir, "other-skill", "SKILL.md"))).toBe(true);

      // Rafter skills should be installed
      expect(fs.existsSync(path.join(skillsDir, "rafter", "SKILL.md"))).toBe(true);
      expect(fs.existsSync(path.join(skillsDir, "rafter-agent-security", "SKILL.md"))).toBe(true);
    });
  });
});
