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

describe("Codex CLI Integration", () => {
  let testHomeDir: string;

  beforeEach(() => {
    testHomeDir = createTempDir("rafter-codex-test");
  });

  afterEach(() => {
    cleanupDir(testHomeDir);
  });

  // ── 1. Skill installation ─────────────────────────────────────────

  describe("Skill installation (--with-codex)", () => {
    it("should create all AGENT_SKILLS files in ~/.agents/skills/", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });

      const result = runCli("agent init --with-codex", testHomeDir);
      expect(result.exitCode).toBe(0);

      // Must mirror AGENT_SKILLS in node/src/commands/agent/init.ts.
      const expected = [
        "rafter",
        "rafter-secure-design",
        "rafter-code-review",
      ];
      for (const name of expected) {
        const skillPath = path.join(
          testHomeDir,
          ".agents",
          "skills",
          name,
          "SKILL.md"
        );
        expect(fs.existsSync(skillPath), `${name} should be installed`).toBe(true);
      }
    });

    it("backend skill should contain valid frontmatter", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });
      runCli("agent init --with-codex", testHomeDir);

      const skillContent = fs.readFileSync(
        path.join(
          testHomeDir,
          ".agents",
          "skills",
          "rafter",
          "SKILL.md"
        ),
        "utf-8"
      );
      // Check frontmatter markers
      expect(skillContent).toMatch(/^---\n/);
      expect(skillContent).toContain("name: rafter");
      expect(skillContent).toContain("version:");
      expect(skillContent).toContain("allowed-tools:");
    });

    it("secure-design skill should contain valid frontmatter", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });
      runCli("agent init --with-codex", testHomeDir);

      const skillContent = fs.readFileSync(
        path.join(
          testHomeDir,
          ".agents",
          "skills",
          "rafter-secure-design",
          "SKILL.md"
        ),
        "utf-8"
      );
      expect(skillContent).toMatch(/^---\n/);
      expect(skillContent).toContain("name:");
      expect(skillContent).toContain("version:");
    });

    it("skill files should contain rafter CLI commands", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });
      runCli("agent init --with-codex", testHomeDir);

      const backendContent = fs.readFileSync(
        path.join(
          testHomeDir,
          ".agents",
          "skills",
          "rafter",
          "SKILL.md"
        ),
        "utf-8"
      );
      // Should reference rafter CLI usage
      expect(backendContent).toContain("rafter");
    });
  });

  // ── 2. Idempotency ────────────────────────────────────────────────

  describe("Codex idempotency", () => {
    it("should not corrupt skills on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });

      runCli("agent init --with-codex", testHomeDir);
      const firstContent = fs.readFileSync(
        path.join(
          testHomeDir,
          ".agents",
          "skills",
          "rafter",
          "SKILL.md"
        ),
        "utf-8"
      );

      runCli("agent init --with-codex", testHomeDir);
      const secondContent = fs.readFileSync(
        path.join(
          testHomeDir,
          ".agents",
          "skills",
          "rafter",
          "SKILL.md"
        ),
        "utf-8"
      );

      expect(secondContent).toBe(firstContent);
    });

    it("should overwrite stale skill content on re-install", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });
      const skillDir = path.join(
        testHomeDir,
        ".agents",
        "skills",
        "rafter"
      );
      fs.mkdirSync(skillDir, { recursive: true });
      fs.writeFileSync(
        path.join(skillDir, "SKILL.md"),
        "---\nname: rafter\nversion: 0.0.1\n---\nOld content\n"
      );

      runCli("agent init --with-codex", testHomeDir);

      const content = fs.readFileSync(
        path.join(skillDir, "SKILL.md"),
        "utf-8"
      );
      // Should be overwritten with the current template, not the old content
      expect(content).not.toContain("Old content");
      expect(content).not.toContain("version: 0.0.1");
    });
  });

  // ── 3. Environment detection ──────────────────────────────────────

  describe("Codex environment detection", () => {
    it("should warn when --with-codex used without ~/.codex", () => {
      // Do NOT create .codex dir
      const result = runCli("agent init --with-codex", testHomeDir);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Codex CLI requested but not detected");

      // Skills should NOT be installed
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
      ).toBe(false);
    });

    it("should detect .codex and install when requested", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });

      const result = runCli("agent init --with-codex", testHomeDir);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Codex CLI");
      // Should not contain the "not detected" warning
      expect(result.stdout).not.toContain(
        "Codex CLI requested but not detected"
      );
    });
  });

  // ── 4. Directory structure ────────────────────────────────────────

  describe("Codex directory structure", () => {
    it("should create ~/.agents/skills/ hierarchy", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });
      runCli("agent init --with-codex", testHomeDir);

      expect(
        fs.statSync(path.join(testHomeDir, ".agents", "skills")).isDirectory()
      ).toBe(true);
      expect(
        fs.statSync(
          path.join(testHomeDir, ".agents", "skills", "rafter")
        ).isDirectory()
      ).toBe(true);
      expect(
        fs.statSync(
          path.join(
            testHomeDir,
            ".agents",
            "skills",
            "rafter-secure-design"
          )
        ).isDirectory()
      ).toBe(true);
      expect(
        fs.statSync(
          path.join(
            testHomeDir,
            ".agents",
            "skills",
            "rafter-code-review"
          )
        ).isDirectory()
      ).toBe(true);
    });

    it("should not affect ~/.codex directory itself", () => {
      const codexDir = path.join(testHomeDir, ".codex");
      fs.mkdirSync(codexDir, { recursive: true });
      fs.writeFileSync(
        path.join(codexDir, "config.json"),
        '{"existing": true}'
      );

      runCli("agent init --with-codex", testHomeDir);

      // .codex/config.json should be untouched
      const config = JSON.parse(
        fs.readFileSync(path.join(codexDir, "config.json"), "utf-8")
      );
      expect(config.existing).toBe(true);
    });
  });

  // ── 5. Coexistence with Claude Code ───────────────────────────────

  describe("Coexistence with Claude Code", () => {
    it("should install both Codex and Claude Code skills independently", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });

      const result = runCli(
        "agent init --with-codex --with-claude-code",
        testHomeDir
      );
      expect(result.exitCode).toBe(0);

      // Codex skills in ~/.agents/skills/
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

      // Claude Code skills in ~/.claude/skills/
      expect(
        fs.existsSync(
          path.join(
            testHomeDir,
            ".claude",
            "skills",
            "rafter",
            "SKILL.md"
          )
        )
      ).toBe(true);

      // Claude Code hooks in settings.json
      const settings = JSON.parse(
        fs.readFileSync(
          path.join(testHomeDir, ".claude", "settings.json"),
          "utf-8"
        )
      );
      expect(settings.hooks).toBeDefined();
      expect(settings.hooks.PreToolUse).toBeDefined();
    });
  });

  // ── 6. Opt-in gating ─────────────────────────────────────────────

  describe("Opt-in gating", () => {
    it("plain 'agent init' should NOT install Codex skills", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });

      const result = runCli("agent init", testHomeDir);
      expect(result.exitCode).toBe(0);

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
      ).toBe(false);
    });
  });

  // ── 7. AGENTS.md instruction file ────────────────────────────────

  describe("Codex AGENTS.md instruction file", () => {
    it("writes ~/.codex/AGENTS.md with the rafter marker block at user scope", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });

      const result = runCli("agent init --with-codex", testHomeDir);
      expect(result.exitCode).toBe(0);

      const agentsPath = path.join(testHomeDir, ".codex", "AGENTS.md");
      expect(fs.existsSync(agentsPath)).toBe(true);

      const content = fs.readFileSync(agentsPath, "utf-8");
      expect(content).toContain("<!-- rafter:start -->");
      expect(content).toContain("<!-- rafter:end -->");
    });

    it("is idempotent on repeated installs", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });

      runCli("agent init --with-codex", testHomeDir);
      const first = fs.readFileSync(
        path.join(testHomeDir, ".codex", "AGENTS.md"),
        "utf-8"
      );

      runCli("agent init --with-codex", testHomeDir);
      const second = fs.readFileSync(
        path.join(testHomeDir, ".codex", "AGENTS.md"),
        "utf-8"
      );

      expect(second).toBe(first);
    });

    it("preserves existing user content outside the marker block", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });
      const agentsPath = path.join(testHomeDir, ".codex", "AGENTS.md");
      fs.writeFileSync(agentsPath, "# My personal instructions\n\nDo the thing.\n");

      runCli("agent init --with-codex", testHomeDir);

      const content = fs.readFileSync(agentsPath, "utf-8");
      expect(content).toContain("# My personal instructions");
      expect(content).toContain("Do the thing.");
      expect(content).toContain("<!-- rafter:start -->");
    });

    it("does NOT write AGENTS.md if --with-codex is not passed", () => {
      fs.mkdirSync(path.join(testHomeDir, ".codex"), { recursive: true });
      fs.mkdirSync(path.join(testHomeDir, ".claude"), { recursive: true });

      runCli("agent init --with-claude-code", testHomeDir);

      expect(
        fs.existsSync(path.join(testHomeDir, ".codex", "AGENTS.md"))
      ).toBe(false);
    });
  });
});
