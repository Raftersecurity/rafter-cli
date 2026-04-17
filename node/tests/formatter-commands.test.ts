import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * Tests that the -a (--agent) flag produces correct plain-text output
 * across all commands, and that default (human) mode uses styled output.
 *
 * These are integration tests that invoke the actual CLI binary.
 */

const CLI = path.resolve(__dirname, "../dist/index.js");

// Strip ANSI escape sequences
const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

// Emoji regex covering common ranges
const emojiRe = /[\u2600-\u27BF\u{1F300}-\u{1F9FF}\u{1FA00}-\u{1FAFF}]/u;

function rafter(
  args: string | string[],
  opts?: { cwd?: string; env?: Record<string, string> },
): { stdout: string; stderr: string; exitCode: number } {
  const argList = Array.isArray(args) ? args : args.split(/\s+/);
  try {
    const result = execFileSync("node", [CLI, ...argList], {
      encoding: "utf-8",
      cwd: opts?.cwd,
      env: { ...process.env, ...opts?.env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { stdout: result, stderr: "", exitCode: 0 };
  } catch (e: any) {
    return {
      stdout: e.stdout || "",
      stderr: e.stderr || "",
      exitCode: e.status ?? 1,
    };
  }
}

// ── scan local: agent vs human mode ──────────────────────────────────

describe("scan local — agent mode vs human mode", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-fmt-scan-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("agent mode: clean scan uses [OK] prefix, no ANSI", () => {
    fs.writeFileSync(path.join(tmpDir, "safe.txt"), "nothing secret here\n");
    const r = rafter(["-a", "scan", "local", tmpDir]);
    const combined = r.stdout + r.stderr;
    expect(combined).toContain("[OK]");
    expect(combined).toBe(stripAnsi(combined));
  });

  it("human mode: clean scan uses ✓ check mark", () => {
    fs.writeFileSync(path.join(tmpDir, "safe.txt"), "nothing secret here\n");
    const r = rafter(["scan", "local", tmpDir]);
    const combined = r.stdout + r.stderr;
    const raw = stripAnsi(combined);
    expect(raw).toContain("✓");
  });

  it("agent mode: findings use [WARN] prefix, no ANSI", () => {
    fs.writeFileSync(
      path.join(tmpDir, "leak.py"),
      'AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    );
    const r = rafter(["-a", "scan", "local", tmpDir]);
    const combined = r.stdout + r.stderr;
    expect(combined).toContain("[WARN]");
    expect(combined).toBe(stripAnsi(combined));
    expect(r.exitCode).toBe(1);
  });

  it("agent mode: severity levels use bracket notation", () => {
    fs.writeFileSync(
      path.join(tmpDir, "leak.py"),
      'AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    );
    const r = rafter(["-a", "scan", "local", tmpDir]);
    const combined = r.stdout + r.stderr;
    // Severity should be [CRITICAL], [HIGH], [MEDIUM], or [LOW]
    expect(combined).toMatch(/\[(CRITICAL|HIGH|MEDIUM|LOW)\]/);
  });

  it("human mode: findings use ⚠ warning indicator", () => {
    fs.writeFileSync(
      path.join(tmpDir, "leak.py"),
      'AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    );
    const r = rafter(["scan", "local", tmpDir]);
    const combined = r.stdout + r.stderr;
    const raw = stripAnsi(combined);
    expect(raw).toContain("⚠");
    expect(r.exitCode).toBe(1);
  });

  it("agent mode: no emoji in findings output", () => {
    fs.writeFileSync(
      path.join(tmpDir, "leak.py"),
      'AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    );
    const r = rafter(["-a", "scan", "local", tmpDir]);
    const combined = r.stdout + r.stderr;
    expect(combined).not.toMatch(emojiRe);
  });
});

// ── agent verify: agent vs human mode ──────��─────────────────────────

describe("agent verify — agent mode vs human mode", () => {
  it("agent mode: uses === header delimiters", () => {
    const r = rafter(["-a", "agent", "verify"]);
    const combined = r.stdout + r.stderr;
    expect(combined).toContain("=== Rafter Agent Verify ===");
  });

  it("agent mode: uses --- divider", () => {
    const r = rafter(["-a", "agent", "verify"]);
    const combined = r.stdout + r.stderr;
    expect(combined).toContain("---");
  });

  it("agent mode: check results use [OK], [WARN], or [ERROR]", () => {
    const r = rafter(["-a", "agent", "verify"]);
    const combined = r.stdout + r.stderr;
    // At least one of these should appear in the output
    const hasAgentIndicator =
      combined.includes("[OK]") ||
      combined.includes("[WARN]") ||
      combined.includes("[ERROR]");
    expect(hasAgentIndicator).toBe(true);
  });

  it("agent mode: output is ANSI-free", () => {
    const r = rafter(["-a", "agent", "verify"]);
    const combined = r.stdout + r.stderr;
    expect(combined).toBe(stripAnsi(combined));
  });

  it("agent mode: no emoji in verify output", () => {
    const r = rafter(["-a", "agent", "verify"]);
    const combined = r.stdout + r.stderr;
    expect(combined).not.toMatch(emojiRe);
  });

  it("human mode: uses box-drawing header", () => {
    const r = rafter(["agent", "verify"]);
    const combined = r.stdout + r.stderr;
    const raw = stripAnsi(combined);
    expect(raw).toContain("┌");
    expect(raw).toContain("Rafter Agent Verify");
  });

  it("human mode: uses styled divider", () => {
    const r = rafter(["agent", "verify"]);
    const combined = r.stdout + r.stderr;
    const raw = stripAnsi(combined);
    expect(raw).toContain("═");
  });

  it("human mode: check results use ✓, ⚠, or ✗", () => {
    const r = rafter(["agent", "verify"]);
    const combined = r.stdout + r.stderr;
    const raw = stripAnsi(combined);
    const hasHumanIndicator =
      raw.includes("✓") || raw.includes("⚠") || raw.includes("✗");
    expect(hasHumanIndicator).toBe(true);
  });
});

// ── agent exec: agent vs human mode ──────��───────────────────────────

describe("agent exec — agent mode formatting", () => {
  it("agent mode: blocked command uses [ERROR], no ANSI", () => {
    // Use a command that should be blocked (critical risk)
    const r = rafter(["-a", "agent", "exec", "rm -rf /"]);
    const combined = r.stdout + r.stderr;
    expect(combined).toContain("[ERROR]");
    expect(combined).toBe(stripAnsi(combined));
    expect(r.exitCode).toBe(1);
  });

  it("human mode: blocked command uses ✗ mark", () => {
    const r = rafter(["agent", "exec", "rm -rf /"]);
    const combined = r.stdout + r.stderr;
    const raw = stripAnsi(combined);
    expect(raw).toContain("✗");
    expect(r.exitCode).toBe(1);
  });

  it("agent mode: blocked output has no emoji", () => {
    const r = rafter(["-a", "agent", "exec", "rm -rf /"]);
    const combined = r.stdout + r.stderr;
    expect(combined).not.toMatch(emojiRe);
  });
});

// ── agent audit: event indicators ────────────────────────────────────

describe("agent audit — event indicators", () => {
  let tmpDir: string;
  let auditPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-fmt-audit-"));
    auditPath = path.join(tmpDir, "audit.jsonl");

    // Write sample audit entries
    const entries = [
      {
        timestamp: new Date().toISOString(),
        eventType: "command_intercepted",
        agentType: "claude-code",
        resolution: { actionTaken: "blocked" },
        context: { command: "rm -rf /", riskLevel: "critical" },
      },
      {
        timestamp: new Date().toISOString(),
        eventType: "secret_detected",
        agentType: "claude-code",
        context: { file: "test.py", pattern: "AWS Key" },
      },
      {
        timestamp: new Date().toISOString(),
        eventType: "scan_executed",
        agentType: "claude-code",
        context: { engine: "regex" },
      },
    ];
    fs.writeFileSync(
      auditPath,
      entries.map((e) => JSON.stringify(e)).join("\n") + "\n",
    );
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("agent mode: uses bracket indicators [INTERCEPT], [SECRET], [SCAN]", () => {
    const r = rafter(["-a", "agent", "audit", "--last", "10"], {
      env: { RAFTER_AUDIT_LOG: auditPath },
    });
    const combined = r.stdout + r.stderr;
    // Agent mode bracket indicators
    const hasBracketIndicators =
      combined.includes("[INTERCEPT]") ||
      combined.includes("[SECRET]") ||
      combined.includes("[SCAN]");
    expect(hasBracketIndicators).toBe(true);
  });

  it("agent mode: no emoji in audit output", () => {
    const r = rafter(["-a", "agent", "audit", "--last", "10"], {
      env: { RAFTER_AUDIT_LOG: auditPath },
    });
    const combined = r.stdout + r.stderr;
    expect(combined).not.toMatch(emojiRe);
  });

  it("agent mode: output is ANSI-free", () => {
    const r = rafter(["-a", "agent", "audit", "--last", "10"], {
      env: { RAFTER_AUDIT_LOG: auditPath },
    });
    const combined = r.stdout + r.stderr;
    expect(combined).toBe(stripAnsi(combined));
  });

  it("human mode: uses emoji indicators (🛡️, 🔑, 🔍)", () => {
    const r = rafter(["agent", "audit", "--last", "10"], {
      env: { RAFTER_AUDIT_LOG: auditPath },
    });
    const combined = r.stdout + r.stderr;
    const raw = stripAnsi(combined);
    // Should contain at least one emoji indicator
    const hasEmoji =
      raw.includes("🛡") ||
      raw.includes("🔑") ||
      raw.includes("🔍") ||
      raw.includes("🧹") ||
      raw.includes("⚙");
    expect(hasEmoji).toBe(true);
  });
});

// ── ci init: agent vs human mode ────────��────────────────────────────

describe("ci init — agent mode vs human mode", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-fmt-ci-"));
    // Create .github dir so platform auto-detects
    fs.mkdirSync(path.join(tmpDir, ".github"), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("agent mode: success message uses [OK], no ANSI", () => {
    const r = rafter(["-a", "ci", "init", "--platform", "github"], {
      cwd: tmpDir,
    });
    const combined = r.stdout + r.stderr;
    expect(combined).toContain("[OK]");
    expect(combined).toBe(stripAnsi(combined));
  });

  it("human mode: success message uses ✓", () => {
    const r = rafter(["ci", "init", "--platform", "github"], { cwd: tmpDir });
    const combined = r.stdout + r.stderr;
    const raw = stripAnsi(combined);
    expect(raw).toContain("✓");
  });

  it("agent mode: unknown platform error uses [ERROR], no ANSI", () => {
    const r = rafter(["-a", "ci", "init", "--platform", "nonexistent"], {
      cwd: tmpDir,
    });
    const combined = r.stdout + r.stderr;
    expect(combined).toContain("[ERROR]");
    expect(combined).toBe(stripAnsi(combined));
  });
});

// ── --agent flag positioning ───────────────────────────��─────────────

describe("--agent flag positioning", () => {
  it("-a before subcommand works", () => {
    const r = rafter(["-a", "agent", "verify"]);
    const combined = r.stdout + r.stderr;
    expect(combined).toContain("===");
    expect(combined).toBe(stripAnsi(combined));
  });

  it("--agent long form before subcommand works", () => {
    const r = rafter(["--agent", "agent", "verify"]);
    const combined = r.stdout + r.stderr;
    expect(combined).toContain("===");
    expect(combined).toBe(stripAnsi(combined));
  });
});
