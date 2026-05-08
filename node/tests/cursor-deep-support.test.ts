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

const SHIPPED_SKILLS = [
  "rafter",
  "rafter-secure-design",
  "rafter-code-review",
  "rafter-skill-review",
];

function createTempDir(prefix: string): string {
  const tmpDir = path.join(
    os.tmpdir(),
    `${prefix}-${Date.now()}-${randomBytes(6).toString("hex")}`,
  );
  fs.mkdirSync(tmpDir, { recursive: true });
  return tmpDir;
}

function cleanupDir(dir: string) {
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function runCli(args: string, homeDir: string) {
  return spawnSync(`node ${CLI_ENTRY} ${args}`, {
    cwd: PROJECT_ROOT,
    encoding: "utf-8",
    timeout: 15_000,
    shell: true,
    env: { ...process.env, HOME: homeDir, XDG_CONFIG_HOME: path.join(homeDir, ".config") },
    stdio: ["pipe", "pipe", "pipe"],
  });
}

describe("Cursor deep support — rf-cia (rf-svn3)", () => {
  let testHomeDir: string;

  beforeEach(() => {
    testHomeDir = createTempDir("rafter-cursor-deep");
    fs.mkdirSync(path.join(testHomeDir, ".cursor"), { recursive: true });
  });

  afterEach(() => {
    cleanupDir(testHomeDir);
  });

  // ── A. Hooks: extend coverage to preToolUse + postToolUse ───────────

  describe("Cursor hooks — preToolUse + postToolUse", () => {
    it("writes preToolUse, postToolUse, and beforeShellExecution entries", () => {
      const result = runCli("agent init --with-cursor", testHomeDir);
      expect(result.status).toBe(0);

      const hooksPath = path.join(testHomeDir, ".cursor", "hooks.json");
      const config = JSON.parse(fs.readFileSync(hooksPath, "utf-8"));
      expect(config.version).toBe(1);
      expect(Array.isArray(config.hooks.preToolUse)).toBe(true);
      expect(Array.isArray(config.hooks.postToolUse)).toBe(true);
      expect(Array.isArray(config.hooks.beforeShellExecution)).toBe(true);

      const pre = config.hooks.preToolUse.find((e: any) => e.command?.includes("rafter"));
      expect(pre).toBeDefined();
      expect(pre.command).toBe("rafter hook pretool --format cursor");
      expect(pre.type).toBe("command");

      const post = config.hooks.postToolUse.find((e: any) => e.command?.includes("rafter"));
      expect(post).toBeDefined();
      expect(post.command).toBe("rafter hook posttool --format cursor");
      expect(post.type).toBe("command");

      const shell = config.hooks.beforeShellExecution.find((e: any) =>
        e.command?.includes("rafter"),
      );
      expect(shell).toBeDefined();
      expect(shell.command).toBe("rafter hook pretool --format cursor");
    });

    it("is idempotent — repeated install yields exactly one rafter entry per event", () => {
      runCli("agent init --with-cursor", testHomeDir);
      runCli("agent init --with-cursor", testHomeDir);
      runCli("agent init --with-cursor", testHomeDir);

      const config = JSON.parse(
        fs.readFileSync(path.join(testHomeDir, ".cursor", "hooks.json"), "utf-8"),
      );
      for (const ev of ["preToolUse", "postToolUse", "beforeShellExecution"]) {
        const rafterHooks = config.hooks[ev].filter((e: any) =>
          e.command?.includes("rafter"),
        );
        expect(rafterHooks, `event ${ev}`).toHaveLength(1);
      }
    });

    it("preserves pre-existing non-rafter hook entries across all events", () => {
      const cursorDir = path.join(testHomeDir, ".cursor");
      const hooksPath = path.join(cursorDir, "hooks.json");
      fs.writeFileSync(
        hooksPath,
        JSON.stringify(
          {
            version: 1,
            hooks: {
              preToolUse: [{ command: "other pre", type: "command" }],
              postToolUse: [{ command: "other post", type: "command" }],
              beforeShellExecution: [{ command: "other shell", type: "command" }],
              afterFileEdit: [{ command: "other edit", type: "command" }],
            },
          },
          null,
          2,
        ),
      );

      runCli("agent init --with-cursor", testHomeDir);

      const config = JSON.parse(fs.readFileSync(hooksPath, "utf-8"));
      const flatten = (event: string) =>
        (config.hooks[event] || []).map((e: any) => e.command).filter(Boolean);
      expect(flatten("preToolUse")).toContain("other pre");
      expect(flatten("postToolUse")).toContain("other post");
      expect(flatten("beforeShellExecution")).toContain("other shell");
      // Untouched event stays.
      expect(flatten("afterFileEdit")).toEqual(["other edit"]);
    });
  });

  // ── B. Per-skill rules ──────────────────────────────────────────────

  describe("Cursor rules — per-skill .mdc files", () => {
    it("writes one .mdc per shipped skill under .cursor/rules/", () => {
      runCli("agent init --with-cursor", testHomeDir);
      const rulesDir = path.join(testHomeDir, ".cursor", "rules");
      for (const name of SHIPPED_SKILLS) {
        const p = path.join(rulesDir, `${name}.mdc`);
        expect(fs.existsSync(p), `missing ${p}`).toBe(true);
      }
    });

    it("each rule has frontmatter with description + alwaysApply: false", () => {
      runCli("agent init --with-cursor", testHomeDir);
      const rulesDir = path.join(testHomeDir, ".cursor", "rules");
      for (const name of SHIPPED_SKILLS) {
        const content = fs.readFileSync(path.join(rulesDir, `${name}.mdc`), "utf-8");
        expect(content.startsWith("---\n"), `${name}: must start with frontmatter`).toBe(true);
        const fmEnd = content.indexOf("\n---", 4);
        expect(fmEnd, `${name}: no closing frontmatter`).toBeGreaterThan(0);
        const frontmatter = content.slice(4, fmEnd);
        expect(frontmatter, `${name}: alwaysApply must be false`).toMatch(
          /alwaysApply:\s*false/,
        );
        expect(frontmatter, `${name}: description must be present`).toMatch(/description:\s*"/);
      }
    });

    it("each rule description is action-forcing (REQUIRED/Use/Invoke/Entry/etc.)", () => {
      runCli("agent init --with-cursor", testHomeDir);
      const rulesDir = path.join(testHomeDir, ".cursor", "rules");
      for (const name of SHIPPED_SKILLS) {
        const content = fs.readFileSync(path.join(rulesDir, `${name}.mdc`), "utf-8");
        const m = content.match(/description:\s*"([^"]+)"/);
        expect(m, `${name}: description regex match`).toBeTruthy();
        const desc = (m && m[1]) || "";
        expect(desc.length, `${name}: description nonempty`).toBeGreaterThan(20);
        // Trigger-first phrasing as per rf-4ei/rf-8po: starts with an
        // imperative or action-forcing token.
        expect(
          /^(REQUIRED|Use|Invoke|Entry|Run|Read|Stop)/.test(desc),
          `${name}: description must be action-forcing, got: ${desc.slice(0, 40)}`,
        ).toBe(true);
      }
    });

    it("does not write the legacy consolidated rafter-security.mdc", () => {
      runCli("agent init --with-cursor", testHomeDir);
      const legacy = path.join(testHomeDir, ".cursor", "rules", "rafter-security.mdc");
      expect(fs.existsSync(legacy)).toBe(false);
    });

    it("idempotent — repeated install does not duplicate or corrupt rules", () => {
      runCli("agent init --with-cursor", testHomeDir);
      const before: Record<string, string> = {};
      const rulesDir = path.join(testHomeDir, ".cursor", "rules");
      for (const name of SHIPPED_SKILLS) {
        before[name] = fs.readFileSync(path.join(rulesDir, `${name}.mdc`), "utf-8");
      }
      runCli("agent init --with-cursor", testHomeDir);
      for (const name of SHIPPED_SKILLS) {
        const after = fs.readFileSync(path.join(rulesDir, `${name}.mdc`), "utf-8");
        expect(after).toBe(before[name]);
      }
    });

    it("--local writes rules under <cwd>/.cursor/rules/", () => {
      // Use testHomeDir as the cwd for --local install.
      const result = spawnSync(`node ${CLI_ENTRY} agent init --local --with-cursor`, {
        cwd: testHomeDir,
        encoding: "utf-8",
        timeout: 15_000,
        shell: true,
        env: { ...process.env, HOME: testHomeDir },
        stdio: ["pipe", "pipe", "pipe"],
      });
      expect(result.status).toBe(0);
      for (const name of SHIPPED_SKILLS) {
        const p = path.join(testHomeDir, ".cursor", "rules", `${name}.mdc`);
        expect(fs.existsSync(p), `local: missing ${p}`).toBe(true);
      }
    });
  });

  // ── C. Sub-agent: .cursor/agents/rafter.md ──────────────────────────

  describe("Cursor sub-agent — .cursor/agents/rafter.md", () => {
    it("writes the rafter sub-agent to .cursor/agents/rafter.md", () => {
      runCli("agent init --with-cursor", testHomeDir);
      const agentPath = path.join(testHomeDir, ".cursor", "agents", "rafter.md");
      expect(fs.existsSync(agentPath)).toBe(true);
    });

    it("frontmatter has name + description but no `tools:` field", () => {
      runCli("agent init --with-cursor", testHomeDir);
      const agentPath = path.join(testHomeDir, ".cursor", "agents", "rafter.md");
      const content = fs.readFileSync(agentPath, "utf-8");
      expect(content.startsWith("---\n")).toBe(true);
      const fmEnd = content.indexOf("\n---", 4);
      const frontmatter = content.slice(4, fmEnd);
      expect(frontmatter).toMatch(/name:\s*rafter/);
      expect(frontmatter).toMatch(/description:\s*\S/);
      // Cursor frontmatter has no tools: field — strip it from the source if present.
      expect(frontmatter).not.toMatch(/^tools:/m);
    });

    it("body references rafter run / rafter run --mode plus / rafter secrets", () => {
      runCli("agent init --with-cursor", testHomeDir);
      const content = fs.readFileSync(
        path.join(testHomeDir, ".cursor", "agents", "rafter.md"),
        "utf-8",
      );
      expect(content).toContain("rafter run");
      expect(content).toContain("--mode plus");
      expect(content).toContain("rafter secrets");
    });

    it("idempotent — repeated install yields identical file", () => {
      runCli("agent init --with-cursor", testHomeDir);
      const agentPath = path.join(testHomeDir, ".cursor", "agents", "rafter.md");
      const before = fs.readFileSync(agentPath, "utf-8");
      runCli("agent init --with-cursor", testHomeDir);
      const after = fs.readFileSync(agentPath, "utf-8");
      expect(after).toBe(before);
    });
  });
});
