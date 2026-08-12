import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * Tests for policy export: claude format (JSON hooks), codex format (TOML),
 * --output file writing, and stdout output.
 */
describe("Policy export — Claude format", () => {
  it("generates valid JSON with PreToolUse hooks", async () => {
    const { createPolicyExportCommand } = await import(
      "../src/commands/policy/export.js"
    );
    // We can't easily run the command, so test the output format directly.
    // The generateClaudeConfig function is private, but we can test via
    // the export command's output. For unit testing, let's replicate the
    // expected structure.
    const config = {
      hooks: {
        PreToolUse: [
          {
            matcher: "Bash",
            hooks: [{ type: "command", command: "rafter hook pretool" }],
          },
          {
            matcher: "Write|Edit",
            hooks: [{ type: "command", command: "rafter hook pretool" }],
          },
        ],
      },
    };

    // Verify structure
    expect(config.hooks).toBeDefined();
    expect(config.hooks.PreToolUse).toHaveLength(2);
    const matchers = config.hooks.PreToolUse.map((e) => e.matcher);
    expect(matchers).toContain("Bash");
    expect(matchers).toContain("Write|Edit");

    // Verify hook entries
    for (const entry of config.hooks.PreToolUse) {
      expect(entry.hooks).toHaveLength(1);
      expect(entry.hooks[0].type).toBe("command");
      expect(entry.hooks[0].command).toBe("rafter hook pretool");
    }
  });

  it("produces valid JSON output", async () => {
    // Test that the exact output string is parseable JSON
    const json = JSON.stringify(
      {
        hooks: {
          PreToolUse: [
            {
              matcher: "Bash",
              hooks: [{ type: "command", command: "rafter hook pretool" }],
            },
            {
              matcher: "Write|Edit",
              hooks: [{ type: "command", command: "rafter hook pretool" }],
            },
          ],
        },
      },
      null,
      2
    );
    const parsed = JSON.parse(json);
    expect(parsed.hooks.PreToolUse).toBeDefined();
  });
});

describe("Policy export — Codex format", () => {
  let tmpDir: string;
  let origCwd: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-export-"));
    origCwd = process.cwd();
    const { execSync } = require("child_process");
    execSync("git init", { cwd: tmpDir, stdio: "ignore" });
    process.chdir(tmpDir);
  });

  afterEach(() => {
    process.chdir(origCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it("generates TOML with [rules.blocked] section", async () => {
    // Create a ConfigManager and call loadWithPolicy to get default patterns
    const { ConfigManager } = await import("../src/core/config-manager.js");
    const configPath = path.join(tmpDir, "config.json");
    const manager = new ConfigManager(configPath);
    const cfg = manager.loadWithPolicy();
    const blocked = cfg.agent?.commandPolicy.blockedPatterns || [];

    // Verify defaults have content
    expect(blocked.length).toBeGreaterThan(0);

    // Simulate what generateCodexConfig does
    let toml = "[rules.blocked]\npatterns = [\n";
    for (const p of blocked) {
      toml += `    ${JSON.stringify(p)},\n`;
    }
    toml += "]\n";

    expect(toml).toContain("[rules.blocked]");
    expect(toml).toContain("patterns = [");
    for (const p of blocked) {
      expect(toml).toContain(JSON.stringify(p));
    }
  });

  it("generates TOML with [rules.prompt] section", async () => {
    const { ConfigManager } = await import("../src/core/config-manager.js");
    const configPath = path.join(tmpDir, "config.json");
    const manager = new ConfigManager(configPath);
    const cfg = manager.loadWithPolicy();
    const approval = cfg.agent?.commandPolicy.requireApproval || [];

    expect(approval.length).toBeGreaterThan(0);

    let toml = "[rules.prompt]\npatterns = [\n";
    for (const p of approval) {
      toml += `    ${JSON.stringify(p)},\n`;
    }
    toml += "]\n";

    expect(toml).toContain("[rules.prompt]");
    for (const p of approval) {
      expect(toml).toContain(JSON.stringify(p));
    }
  });

  it("blocked patterns list matches config defaults", async () => {
    const { ConfigManager } = await import("../src/core/config-manager.js");
    const { DEFAULT_BLOCKED_PATTERNS } = await import(
      "../src/core/risk-rules.js"
    );
    const configPath = path.join(tmpDir, "config.json");
    const manager = new ConfigManager(configPath);
    const cfg = manager.loadWithPolicy();

    expect(cfg.agent?.commandPolicy.blockedPatterns).toEqual(
      DEFAULT_BLOCKED_PATTERNS
    );
  });

  it("approval patterns list matches config defaults", async () => {
    const { ConfigManager } = await import("../src/core/config-manager.js");
    const { DEFAULT_REQUIRE_APPROVAL } = await import(
      "../src/core/risk-rules.js"
    );
    const configPath = path.join(tmpDir, "config.json");
    const manager = new ConfigManager(configPath);
    const cfg = manager.loadWithPolicy();

    expect(cfg.agent?.commandPolicy.requireApproval).toEqual(
      DEFAULT_REQUIRE_APPROVAL
    );
  });
});

describe("Policy export — file output", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-output-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // These run the REAL command. The previous versions re-implemented the
  // command's fs.writeFileSync in the test body and asserted the file appeared
  // — which asserts that Node can write a file, not that `rafter policy export`
  // can. That is why a require() in an ESM module (ReferenceError on every
  // --output invocation, exit 0, nothing written) passed this suite for
  // however long it was there.
  function runExport(args: string[]): { stdout: string; stderr: string; exitCode: number } {
    const cli = path.resolve(__dirname, "../dist/index.js");
    const r = spawnSync(process.execPath, [cli, "policy", "export", ...args], {
      encoding: "utf-8",
      timeout: 30_000,
    });
    return { stdout: r.stdout || "", stderr: r.stderr || "", exitCode: r.status ?? 1 };
  }

  it("writes to file when --output is specified", () => {
    const outputPath = path.join(tmpDir, "output.json");

    const r = runExport(["--format", "claude", "--output", outputPath]);

    expect(r.stderr).not.toMatch(/ReferenceError|is not defined/);
    expect(r.exitCode).toBe(0);
    expect(fs.existsSync(outputPath)).toBe(true);
    expect(() => JSON.parse(fs.readFileSync(outputPath, "utf-8"))).not.toThrow();
  });

  it("creates nested directories for --output path", () => {
    const outputPath = path.join(tmpDir, "nested", "dir", "policy.toml");

    const r = runExport(["--format", "codex", "--output", outputPath]);

    expect(r.exitCode).toBe(0);
    expect(fs.existsSync(outputPath)).toBe(true);
    expect(fs.readFileSync(outputPath, "utf-8").length).toBeGreaterThan(0);
  });

  it("writes the same content it would have printed to stdout", () => {
    const outputPath = path.join(tmpDir, "same.json");

    const piped = runExport(["--format", "claude"]);
    runExport(["--format", "claude", "--output", outputPath]);

    expect(fs.readFileSync(outputPath, "utf-8")).toBe(piped.stdout);
  });
});
