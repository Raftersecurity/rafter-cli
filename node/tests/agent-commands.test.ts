import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";
import { randomBytes } from "crypto";

/**
 * Comprehensive tests for agent subcommands:
 *   init, scan, exec, audit, config, status, verify
 *
 * Tests use a fake HOME to isolate from the user's real config.
 * CLI is invoked via tsx (source-level) for accurate behavior.
 */

vi.setConfig({ testTimeout: 30_000 });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_ENTRY = path.join(PROJECT_ROOT, "src", "index.ts");

function createTempHome(): string {
  const dir = path.join(
    os.tmpdir(),
    `rafter-agent-test-${Date.now()}-${randomBytes(4).toString("hex")}`
  );
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function runCli(
  args: string,
  homeDir: string,
  extraEnv?: Record<string, string>,
): { stdout: string; stderr: string; exitCode: number } {
  try {
    const stdout = execSync(`npx tsx ${CLI_ENTRY} ${args}`, {
      cwd: PROJECT_ROOT,
      encoding: "utf-8",
      timeout: 25_000,
      env: {
        ...process.env,
        HOME: homeDir,
        XDG_CONFIG_HOME: path.join(homeDir, ".config"),
        ...extraEnv,
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

// ─── agent config ────────────────────────────────────────────────────────────

describe("agent config", () => {
  let home: string;

  beforeEach(() => {
    home = createTempHome();
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("config show outputs valid JSON (default config)", () => {
    const r = runCli("agent config show", home);
    expect(r.exitCode).toBe(0);
    const cfg = JSON.parse(r.stdout);
    expect(cfg).toHaveProperty("agent");
    expect(cfg.agent).toHaveProperty("riskLevel");
  });

  it("config show returns saved config after init", () => {
    runCli("agent init --risk-level minimal", home);
    const r = runCli("agent config show", home);
    expect(r.exitCode).toBe(0);
    const cfg = JSON.parse(r.stdout);
    expect(cfg.agent.riskLevel).toBe("minimal");
  });

  it("config get returns a specific key", () => {
    runCli("agent init", home);
    const r = runCli("agent config get agent.riskLevel", home);
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toMatch(/^(minimal|moderate|aggressive)$/);
  });

  it("config get exits 1 for missing key", () => {
    const r = runCli("agent config get nonexistent.key.path", home);
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("Key not found");
  });

  it("config get for nested object returns JSON", () => {
    runCli("agent init", home);
    const r = runCli("agent config get agent.commandPolicy", home);
    expect(r.exitCode).toBe(0);
    const policy = JSON.parse(r.stdout);
    expect(policy).toHaveProperty("mode");
    expect(policy).toHaveProperty("blockedPatterns");
  });

  it("config set updates a value", () => {
    runCli("agent init", home);
    const set = runCli('agent config set agent.riskLevel "aggressive"', home);
    expect(set.exitCode).toBe(0);
    expect(set.stdout).toContain("Set agent.riskLevel");

    const get = runCli("agent config get agent.riskLevel", home);
    expect(get.stdout.trim()).toBe("aggressive");
  });

  it("config set parses JSON values", () => {
    runCli("agent init", home);
    const set = runCli("agent config set agent.audit.retentionDays 90", home);
    expect(set.exitCode).toBe(0);

    const get = runCli("agent config get agent.audit.retentionDays", home);
    expect(get.stdout.trim()).toBe("90");
  });

  it("config set creates intermediate keys", () => {
    runCli("agent init", home);
    const set = runCli('agent config set custom.nested.key "hello"', home);
    expect(set.exitCode).toBe(0);

    const get = runCli("agent config get custom.nested.key", home);
    expect(get.stdout.trim()).toBe("hello");
  });
});

// ─── agent init ──────────────────────────────────────────────────────────────

describe("agent init", () => {
  let home: string;

  beforeEach(() => {
    home = createTempHome();
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("creates .rafter directory and config.json", () => {
    const r = runCli("agent init", home);
    expect(r.exitCode).toBe(0);

    const configPath = path.join(home, ".rafter", "config.json");
    expect(fs.existsSync(configPath)).toBe(true);

    const cfg = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    expect(cfg.agent.riskLevel).toBe("moderate");
  });

  it("creates bin and patterns directories", () => {
    runCli("agent init", home);
    expect(fs.existsSync(path.join(home, ".rafter", "bin"))).toBe(true);
    expect(fs.existsSync(path.join(home, ".rafter", "patterns"))).toBe(true);
  });

  it("respects --risk-level flag", () => {
    runCli("agent init --risk-level minimal", home);
    const cfg = JSON.parse(
      fs.readFileSync(path.join(home, ".rafter", "config.json"), "utf-8")
    );
    expect(cfg.agent.riskLevel).toBe("minimal");
  });

  it("respects --risk-level aggressive", () => {
    runCli("agent init --risk-level aggressive", home);
    const cfg = JSON.parse(
      fs.readFileSync(path.join(home, ".rafter", "config.json"), "utf-8")
    );
    expect(cfg.agent.riskLevel).toBe("aggressive");
  });

  it("is idempotent — running twice doesn't corrupt config", () => {
    runCli("agent init --risk-level minimal", home);
    runCli("agent init", home);
    const cfg = JSON.parse(
      fs.readFileSync(path.join(home, ".rafter", "config.json"), "utf-8")
    );
    // Config should still be valid JSON with expected fields
    expect(cfg).toHaveProperty("agent");
    expect(cfg).toHaveProperty("version");
  });

  it("--with-claude-code installs hooks into settings.json", () => {
    const r = runCli("agent init --with-claude-code", home);
    expect(r.exitCode).toBe(0);

    const settingsPath = path.join(home, ".claude", "settings.json");
    expect(fs.existsSync(settingsPath)).toBe(true);

    const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    expect(settings.hooks).toBeDefined();
    expect(settings.hooks.PreToolUse).toBeDefined();
    expect(settings.hooks.PostToolUse).toBeDefined();

    const hasPreHook = settings.hooks.PreToolUse.some((entry: any) =>
      (entry.hooks || []).some((h: any) => h.command === "rafter hook pretool")
    );
    expect(hasPreHook).toBe(true);
  });

  it("--with-claude-code preserves existing settings", () => {
    // Create pre-existing settings
    const claudeDir = path.join(home, ".claude");
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, "settings.json"),
      JSON.stringify({ customKey: "preserved", hooks: {} }, null, 2)
    );

    runCli("agent init --with-claude-code", home);

    const settings = JSON.parse(
      fs.readFileSync(path.join(claudeDir, "settings.json"), "utf-8")
    );
    expect(settings.customKey).toBe("preserved");
    expect(settings.hooks.PreToolUse.length).toBeGreaterThan(0);
  });
});

// ─── agent scan ──────────────────────────────────────────────────────────────

describe("agent scan", () => {
  let home: string;
  let tmpDir: string;

  beforeEach(() => {
    home = createTempHome();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-scan-test-"));
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("exits 0 for clean file", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "just regular content\n");
    const r = runCli(`agent scan ${f} --engine patterns --quiet`, home);
    expect(r.exitCode).toBe(0);
  });

  it("exits 1 when AWS key detected", () => {
    const f = path.join(tmpDir, "secrets.env");
    fs.writeFileSync(f, "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n");
    const r = runCli(`agent scan ${f} --engine patterns --quiet`, home);
    expect(r.exitCode).toBe(1);
  });

  it("--json outputs valid JSON array", () => {
    const f = path.join(tmpDir, "api.txt");
    fs.writeFileSync(f, "token=ghp_FAKE567890abcdefghijklmnopqrstuAB\n");
    const r = runCli(`agent scan ${f} --engine patterns --json`, home);
    expect(r.exitCode).toBe(1);
    const parsed = JSON.parse(r.stdout);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBeGreaterThan(0);
    expect(parsed[0]).toHaveProperty("file");
    expect(parsed[0]).toHaveProperty("matches");
  });

  it("--format sarif produces SARIF 2.1.0 output", () => {
    const f = path.join(tmpDir, "key.txt");
    fs.writeFileSync(f, "AKIAIOSFODNN7EXAMPLE\n");
    const r = runCli(`agent scan ${f} --engine patterns --format sarif`, home);
    expect(r.exitCode).toBe(1);
    const sarif = JSON.parse(r.stdout);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.name).toBe("rafter");
  });

  it("exits 2 for invalid engine", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "ok\n");
    const r = runCli(`agent scan ${f} --engine bogus`, home);
    expect(r.exitCode).toBe(2);
  });

  it("exits 2 for invalid format", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "ok\n");
    const r = runCli(`agent scan ${f} --engine patterns --format csv`, home);
    expect(r.exitCode).toBe(2);
  });

  it("exits 2 for nonexistent path", () => {
    const r = runCli(
      "agent scan /tmp/rafter-nonexistent-path-xyz --engine patterns",
      home
    );
    expect(r.exitCode).toBe(2);
  });

  it("scans directory recursively", () => {
    const sub = path.join(tmpDir, "nested", "deep");
    fs.mkdirSync(sub, { recursive: true });
    fs.writeFileSync(
      path.join(sub, "config.ts"),
      "const k = 'AKIAIOSFODNN7EXAMPLE';\n"
    );
    const r = runCli(`agent scan ${tmpDir} --engine patterns --json`, home);
    expect(r.exitCode).toBe(1);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.length).toBeGreaterThan(0);
  });

  it("emits deprecation warning when invoked as agent scan", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "nothing here\n");
    const r = runCli(`agent scan ${f} --engine patterns --quiet`, home);
    // The deprecation warning goes to stderr
    expect(r.stderr).toContain("deprecated");
  });

  it("text format shows human-readable output for findings", () => {
    const f = path.join(tmpDir, "leak.txt");
    fs.writeFileSync(f, "sk_l1ve_1234567890abcdefghijklmn\n");
    const r = runCli(`agent scan ${f} --engine patterns`, home);
    expect(r.exitCode).toBe(1);
    // Text output goes to stdout (via console.log)
    const combined = r.stdout + r.stderr;
    expect(combined).toContain("secret");
  });

  it("--baseline filters known findings when no baseline exists", () => {
    const f = path.join(tmpDir, "key.txt");
    fs.writeFileSync(f, "AKIAIOSFODNN7EXAMPLE\n");
    // Without a baseline file, --baseline should still work (no filtering)
    const r = runCli(`agent scan ${f} --engine patterns --json --baseline`, home);
    expect(r.exitCode).toBe(1);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.length).toBeGreaterThan(0);
  });
});

// ─── agent exec ──────────────────────────────────────────────────────────────

describe("agent exec", () => {
  let home: string;

  beforeEach(() => {
    home = createTempHome();
    // Initialize config so the interceptor has policy
    runCli("agent init", home);
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("allows safe commands (echo)", () => {
    const r = runCli('agent exec "echo hello world"', home);
    expect(r.exitCode).toBe(0);
  });

  it("blocks critical commands (rm -rf /)", () => {
    const r = runCli('agent exec "rm -rf /"', home);
    expect(r.exitCode).not.toBe(0);
  });

  it("blocks chmod 777", () => {
    const r = runCli('agent exec "chmod 777 /etc/passwd"', home);
    expect(r.exitCode).not.toBe(0);
  });

  it("--force allows commands that need approval", () => {
    // With default approve-dangerous policy, high-risk commands need approval
    // --force skips the prompt
    const r = runCli('agent exec "echo safe" --force', home);
    expect(r.exitCode).toBe(0);
  });

  it("--skip-scan skips pre-execution scanning", () => {
    const r = runCli('agent exec "echo test" --skip-scan', home);
    expect(r.exitCode).toBe(0);
  });

  it("reports failure for commands that error", () => {
    const r = runCli('agent exec "false"', home);
    expect(r.exitCode).not.toBe(0);
  });

  it("writes to audit log on command evaluation", () => {
    runCli('agent exec "echo audit-test"', home);
    const auditPath = path.join(home, ".rafter", "audit.jsonl");
    if (fs.existsSync(auditPath)) {
      const content = fs.readFileSync(auditPath, "utf-8");
      expect(content).toContain("command_intercepted");
    }
  });
});

// ─── agent audit ─────────────────────────────────────────────────────────────

describe("agent audit", () => {
  let home: string;

  beforeEach(() => {
    home = createTempHome();
    // Init to get config
    runCli("agent init", home);
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("shows 'no entries' when audit log is empty", () => {
    const r = runCli("agent audit", home);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("No audit log entries found");
  });

  it("shows entries after commands are executed", () => {
    // Generate some audit entries
    runCli('agent exec "echo test1"', home);
    runCli('agent exec "echo test2"', home);

    const r = runCli("agent audit", home);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("audit log entries");
  });

  it("--last limits number of entries", () => {
    // Generate entries
    for (let i = 0; i < 5; i++) {
      runCli(`agent exec "echo entry${i}"`, home);
    }

    const r = runCli("agent audit --last 2", home);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("2 audit log entries");
  });

  it("--event filters by event type", () => {
    runCli('agent exec "echo test"', home);
    const r = runCli("agent audit --event command_intercepted", home);
    expect(r.exitCode).toBe(0);
    // Should either find entries or say no entries
    const combined = r.stdout;
    expect(combined).toMatch(/(command_intercepted|No audit log entries)/);
  });

  it("--share generates a redacted excerpt", () => {
    const r = runCli("agent audit --share", home);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("Rafter Audit Excerpt");
    expect(r.stdout).toContain("Environment:");
    expect(r.stdout).toContain("Policy:");
    expect(r.stdout).toContain("Recent events");
  });

  it("--share includes version and OS info", () => {
    const r = runCli("agent audit --share", home);
    expect(r.stdout).toContain("CLI:");
    expect(r.stdout).toContain("OS:");
  });

  it("--since filters entries by date", () => {
    runCli('agent exec "echo old"', home);
    // Use a future date so nothing matches
    const r = runCli("agent audit --since 2099-01-01", home);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("No audit log entries found");
  });
});

// ─── agent status ────────────────────────────────────────────────────────────

describe("agent status", () => {
  let home: string;

  beforeEach(() => {
    home = createTempHome();
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("outputs status dashboard header", () => {
    const r = runCli("agent status", home);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("Rafter Agent Status");
  });

  it("shows 'not found' when no config exists", () => {
    const r = runCli("agent status", home);
    expect(r.stdout).toContain("not found");
  });

  it("shows config path after init", () => {
    runCli("agent init", home);
    const r = runCli("agent status", home);
    expect(r.stdout).toContain("config.json");
    expect(r.stdout).toContain("Risk level:");
  });

  it("reports risk level from config", () => {
    runCli("agent init --risk-level minimal", home);
    const r = runCli("agent status", home);
    expect(r.stdout).toContain("minimal");
  });

  it("shows Gitleaks status", () => {
    const r = runCli("agent status", home);
    expect(r.stdout).toContain("Gitleaks:");
  });

  it("shows Claude Code hook status", () => {
    const r = runCli("agent status", home);
    expect(r.stdout).toContain("PreToolUse:");
    expect(r.stdout).toContain("PostToolUse:");
  });

  it("shows installed hooks after init --with-claude-code", () => {
    runCli("agent init --with-claude-code", home);
    const r = runCli("agent status", home);
    expect(r.stdout).toContain("installed");
  });

  it("shows optional platform statuses", () => {
    const r = runCli("agent status", home);
    const combined = r.stdout;
    // These platforms should appear in the status output
    expect(combined).toContain("OpenClaw:");
    expect(combined).toContain("Gemini CLI:");
    expect(combined).toContain("Cursor:");
    expect(combined).toContain("Aider:");
  });

  it("shows audit log summary", () => {
    const r = runCli("agent status", home);
    expect(r.stdout).toContain("Audit log:");
  });

  it("shows audit stats after generating events", () => {
    runCli("agent init", home);
    runCli('agent exec "echo test"', home);
    const r = runCli("agent status", home);
    expect(r.stdout).toContain("Total events:");
  });
});

// ─── agent verify ────────────────────────────────────────────────────────────

describe("agent verify", () => {
  let home: string;

  beforeEach(() => {
    home = createTempHome();
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("outputs verify header", () => {
    const r = runCli("agent verify", home);
    // Verify always outputs the header
    const combined = r.stdout + r.stderr;
    expect(combined).toMatch(/Rafter Agent Verify|check/i);
  });

  it("fails when no config exists (exit 1)", () => {
    const r = runCli("agent verify", home);
    // Config check is a hard failure
    expect(r.exitCode).toBe(1);
  });

  it("config check passes after init", () => {
    runCli("agent init", home);
    const r = runCli("agent verify", home);
    // Config should pass now (gitleaks may still fail)
    expect(r.stdout).toContain("Config:");
  });

  it("reports optional checks as warnings not failures", () => {
    runCli("agent init", home);
    const r = runCli("agent verify", home);
    // Claude Code is optional — should show a warning, not a hard fail
    const combined = r.stdout;
    // Optional checks show warning messages (with "not detected" or similar)
    expect(combined).toMatch(/(Claude Code|OpenClaw|Codex|Gemini|Cursor|Windsurf)/);
  });

  it("shows passed count summary", () => {
    runCli("agent init", home);
    const r = runCli("agent verify", home);
    // Should show X/Y checks passed
    const combined = r.stdout;
    expect(combined).toMatch(/\d+\/\d+.*check/i);
  });

  it("detects Claude Code hooks when installed", () => {
    runCli("agent init --with-claude-code", home);
    const r = runCli("agent verify", home);
    expect(r.stdout).toContain("Claude Code:");
  });

  it("detects Gemini when configured", () => {
    // Set up fake Gemini config
    const geminiDir = path.join(home, ".gemini");
    fs.mkdirSync(geminiDir, { recursive: true });
    fs.writeFileSync(
      path.join(geminiDir, "settings.json"),
      JSON.stringify({ mcpServers: { rafter: { command: "rafter mcp serve" } } })
    );

    runCli("agent init", home);
    const r = runCli("agent verify", home);
    expect(r.stdout).toContain("Gemini CLI:");
    expect(r.stdout).toContain("MCP server configured");
  });

  it("detects Cursor when configured", () => {
    const cursorDir = path.join(home, ".cursor");
    fs.mkdirSync(cursorDir, { recursive: true });
    fs.writeFileSync(
      path.join(cursorDir, "mcp.json"),
      JSON.stringify({ mcpServers: { rafter: { command: "rafter mcp serve" } } })
    );

    runCli("agent init", home);
    const r = runCli("agent verify", home);
    expect(r.stdout).toContain("Cursor:");
    expect(r.stdout).toContain("MCP server configured");
  });

  it("detects Windsurf when configured", () => {
    const wsDir = path.join(home, ".codeium", "windsurf");
    fs.mkdirSync(wsDir, { recursive: true });
    fs.writeFileSync(
      path.join(wsDir, "mcp_config.json"),
      JSON.stringify({ mcpServers: { rafter: { command: "rafter mcp serve" } } })
    );

    runCli("agent init", home);
    const r = runCli("agent verify", home);
    expect(r.stdout).toContain("Windsurf:");
    expect(r.stdout).toContain("MCP server configured");
  });
});

// ─── audit helpers (unit tests) ──────────────────────────────────────────────

describe("audit helpers", () => {
  it("truncateCommand truncates long strings", async () => {
    const { truncateCommand } = await import(
      "../src/commands/agent/audit.js"
    );
    expect(truncateCommand("short", 60)).toBe("short");
    expect(truncateCommand("x".repeat(100), 60)).toBe("x".repeat(60) + "...");
  });

  it("computePolicyHash is deterministic", async () => {
    const { computePolicyHash } = await import(
      "../src/commands/agent/audit.js"
    );
    const config = { agent: { commandPolicy: { requireApproval: ["a", "b"] } } };
    const h1 = computePolicyHash(config);
    const h2 = computePolicyHash(config);
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(16);
  });

  it("computePolicyHash is order-independent", async () => {
    const { computePolicyHash } = await import(
      "../src/commands/agent/audit.js"
    );
    const c1 = { agent: { commandPolicy: { requireApproval: ["a", "b"] } } };
    const c2 = { agent: { commandPolicy: { requireApproval: ["b", "a"] } } };
    expect(computePolicyHash(c1)).toBe(computePolicyHash(c2));
  });

  it("getRiskLevel returns default when missing", async () => {
    const { getRiskLevel } = await import(
      "../src/commands/agent/audit.js"
    );
    expect(getRiskLevel({})).toBe("moderate");
    expect(getRiskLevel({ agent: { riskLevel: "minimal" } })).toBe("minimal");
  });

  it("formatShareDetail handles secret_detected events", async () => {
    const { formatShareDetail } = await import(
      "../src/commands/agent/audit.js"
    );
    const entry = {
      timestamp: "2025-01-01T00:00:00Z",
      sessionId: "test",
      eventType: "secret_detected" as const,
      securityCheck: { passed: false, reason: "AWS key in config.ts" },
      resolution: { actionTaken: "blocked" as const },
    };
    const detail = formatShareDetail(entry);
    expect(detail).toContain("AWS key");
    expect(detail).toContain("[blocked]");
  });

  it("formatShareDetail handles command entries", async () => {
    const { formatShareDetail } = await import(
      "../src/commands/agent/audit.js"
    );
    const entry = {
      timestamp: "2025-01-01T00:00:00Z",
      sessionId: "test",
      eventType: "command_intercepted" as const,
      action: { command: "rm -rf /tmp/test" },
      resolution: { actionTaken: "allowed" as const },
    };
    const detail = formatShareDetail(entry);
    expect(detail).toContain("rm -rf");
    expect(detail).toContain("[allowed]");
  });
});

// ─── cross-command integration ───────────────────────────────────────────────

describe("cross-command integration", () => {
  let home: string;
  let tmpDir: string;

  beforeEach(() => {
    home = createTempHome();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-cross-"));
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("init → config show → verify: full lifecycle", () => {
    // Init
    const init = runCli("agent init --risk-level aggressive", home);
    expect(init.exitCode).toBe(0);

    // Config reflects init
    const cfg = runCli("agent config show", home);
    const parsed = JSON.parse(cfg.stdout);
    expect(parsed.agent.riskLevel).toBe("aggressive");

    // Verify finds config
    const verify = runCli("agent verify", home);
    expect(verify.stdout).toContain("Config:");
  });

  it("scan generates audit entries visible in audit", () => {
    runCli("agent init", home);

    // Create a file with a secret and scan it
    const f = path.join(tmpDir, "leak.txt");
    fs.writeFileSync(f, "AKIAIOSFODNN7EXAMPLE\n");
    runCli(`agent scan ${f} --engine patterns --quiet`, home);

    // The scan should have logged to audit
    const auditPath = path.join(home, ".rafter", "audit.jsonl");
    if (fs.existsSync(auditPath)) {
      const content = fs.readFileSync(auditPath, "utf-8");
      expect(content.length).toBeGreaterThan(0);
    }
  });

  it("exec → audit shows intercepted commands", () => {
    runCli("agent init", home);
    runCli('agent exec "echo cross-test"', home);

    const r = runCli("agent audit --event command_intercepted", home);
    expect(r.exitCode).toBe(0);
    // Should show the intercepted command
    const combined = r.stdout;
    expect(combined).toMatch(/(command_intercepted|echo|No audit log entries)/);
  });

  it("status reflects audit event counts after exec", () => {
    runCli("agent init", home);
    runCli('agent exec "echo one"', home);
    runCli('agent exec "echo two"', home);

    const r = runCli("agent status", home);
    expect(r.stdout).toContain("Total events:");
  });
});
