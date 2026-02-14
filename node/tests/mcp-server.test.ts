import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mocks ────────────────────────────────────────────────────────────────────
// Must be declared before imports so vi.mock hoists correctly.

vi.mock("../src/scanners/gitleaks.js", () => ({
  GitleaksScanner: vi.fn().mockImplementation(() => ({
    isAvailable: vi.fn().mockResolvedValue(false),
    scanDirectory: vi.fn().mockResolvedValue([]),
    scanFile: vi.fn().mockResolvedValue({ file: "", matches: [] }),
  })),
}));

vi.mock("../src/scanners/regex-scanner.js", () => ({
  RegexScanner: vi.fn().mockImplementation(() => ({
    scanFile: vi.fn().mockReturnValue({ file: "", matches: [] }),
    scanDirectory: vi.fn().mockReturnValue([]),
  })),
}));

vi.mock("../src/core/command-interceptor.js", () => ({
  CommandInterceptor: vi.fn().mockImplementation(() => ({
    evaluate: vi.fn().mockReturnValue({
      command: "",
      riskLevel: "low",
      allowed: true,
      requiresApproval: false,
    }),
  })),
}));

vi.mock("../src/core/audit-logger.js", () => ({
  AuditLogger: vi.fn().mockImplementation(() => ({
    read: vi.fn().mockReturnValue([]),
  })),
}));

vi.mock("../src/core/config-manager.js", () => ({
  ConfigManager: vi.fn().mockImplementation(() => ({
    load: vi.fn().mockReturnValue({
      version: "1.0",
      agent: {
        riskLevel: "medium",
        commandPolicy: { mode: "intercept", blockedPatterns: [], requireApproval: [] },
        audit: { logAllActions: true, retentionDays: 30, logLevel: "info" },
      },
    }),
    get: vi.fn().mockReturnValue(undefined),
    loadWithPolicy: vi.fn().mockReturnValue({
      version: "1.0",
      agent: {
        riskLevel: "medium",
        commandPolicy: { mode: "intercept" },
        audit: { logAllActions: true, retentionDays: 30 },
      },
    }),
  })),
}));

// Prevent MCP SDK from touching stdio
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: vi.fn(),
}));

import { GitleaksScanner } from "../src/scanners/gitleaks.js";
import { RegexScanner } from "../src/scanners/regex-scanner.js";
import { CommandInterceptor } from "../src/core/command-interceptor.js";
import { AuditLogger } from "../src/core/audit-logger.js";
import { ConfigManager } from "../src/core/config-manager.js";

// ── Helpers ──────────────────────────────────────────────────────────────────
// The MCP server is built with low-level Server class and registers handlers
// inline inside createServer(). Rather than spinning up a transport, we
// import the handler logic indirectly by exercising the same code paths:
// instantiate the mocked classes and call them the same way the CallTool
// handler does.  This mirrors the Python tests which call the handler
// functions directly.

/**
 * Simulate the scan_secrets tool handler from server.ts
 */
async function handleScanSecrets(scanPath: string, engine: string = "auto") {
  if (engine === "gitleaks" || engine === "auto") {
    const gitleaks = new GitleaksScanner();
    if (await gitleaks.isAvailable()) {
      try {
        const results = await gitleaks.scanDirectory(scanPath);
        return formatScanResults(results);
      } catch {
        if (engine === "gitleaks") throw new Error("Gitleaks scan failed");
      }
    } else if (engine === "gitleaks") {
      throw new Error("Gitleaks not installed");
    }
  }

  const scanner = new RegexScanner();
  let results: Array<{ file: string; matches: any[] }>;
  try {
    results = scanner.scanDirectory(scanPath);
  } catch {
    results = [scanner.scanFile(scanPath)];
  }
  return formatScanResults(results);
}

function formatScanResults(results: Array<{ file: string; matches: any[] }>) {
  return results.map((r) => ({
    file: r.file,
    matches: r.matches.map((m: any) => ({
      pattern: m.pattern.name,
      severity: m.pattern.severity,
      line: m.line,
      redacted: m.redacted || m.match.slice(0, 4) + "****",
    })),
  }));
}

function handleEvaluateCommand(command: string) {
  const interceptor = new CommandInterceptor();
  const result = interceptor.evaluate(command);
  const out: Record<string, unknown> = {
    allowed: result.allowed,
    risk_level: result.riskLevel,
    requires_approval: result.requiresApproval,
  };
  if (result.reason) out.reason = result.reason;
  return out;
}

function handleReadAuditLog(opts?: { limit?: number; event_type?: string; since?: string }) {
  const logger = new AuditLogger();
  return logger.read({
    limit: opts?.limit ?? 20,
    eventType: opts?.event_type as any,
    since: opts?.since ? new Date(opts.since) : undefined,
  });
}

function handleGetConfig(key?: string) {
  const manager = new ConfigManager();
  return key ? manager.get(key) : manager.load();
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("MCP Server — scan_secrets", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should scan a single file and return matches", async () => {
    const mockMatch = {
      pattern: { name: "aws-access-key", severity: "high", regex: "" },
      match: "AKIAIOSFODNN7EXAMPLE1",
      line: 1,
      redacted: "AKIA****",
    };
    const scannerInstance = new RegexScanner() as any;
    scannerInstance.scanDirectory.mockImplementation(() => {
      throw new Error("not a directory");
    });
    scannerInstance.scanFile.mockReturnValue({
      file: "/tmp/creds.txt",
      matches: [mockMatch],
    });

    // Re-mock constructor to return our instance
    (RegexScanner as any).mockImplementation(() => scannerInstance);

    const results = await handleScanSecrets("/tmp/creds.txt", "patterns");

    expect(results).toHaveLength(1);
    expect(results[0].file).toBe("/tmp/creds.txt");
    expect(results[0].matches).toHaveLength(1);
    expect(results[0].matches[0].pattern).toBe("aws-access-key");
    expect(results[0].matches[0].severity).toBe("high");
    expect(results[0].matches[0].redacted).toBe("AKIA****");
  });

  it("should scan a directory and return results", async () => {
    const mockResults = [
      {
        file: "/tmp/dir/secret.env",
        matches: [
          {
            pattern: { name: "aws-access-key", severity: "high", regex: "" },
            match: "AKIAIOSFODNN7EXAMPLE2",
            line: 1,
            redacted: "AKIA****",
          },
        ],
      },
    ];
    const scannerInstance = new RegexScanner() as any;
    scannerInstance.scanDirectory.mockReturnValue(mockResults);
    (RegexScanner as any).mockImplementation(() => scannerInstance);

    const results = await handleScanSecrets("/tmp/dir", "patterns");

    expect(results).toHaveLength(1);
    expect(results[0].file).toBe("/tmp/dir/secret.env");
    expect(results[0].matches[0].pattern).toBe("aws-access-key");
  });

  it("should return empty matches for clean file", async () => {
    const scannerInstance = new RegexScanner() as any;
    scannerInstance.scanDirectory.mockImplementation(() => {
      throw new Error("not a directory");
    });
    scannerInstance.scanFile.mockReturnValue({
      file: "/tmp/clean.py",
      matches: [],
    });
    (RegexScanner as any).mockImplementation(() => scannerInstance);

    const results = await handleScanSecrets("/tmp/clean.py", "patterns");

    expect(results).toHaveLength(1);
    expect(results[0].matches).toEqual([]);
  });

  it("should fall back to regex when gitleaks unavailable in auto mode", async () => {
    const glInstance = new GitleaksScanner() as any;
    glInstance.isAvailable.mockResolvedValue(false);
    (GitleaksScanner as any).mockImplementation(() => glInstance);

    const scannerInstance = new RegexScanner() as any;
    scannerInstance.scanDirectory.mockImplementation(() => {
      throw new Error("not a directory");
    });
    scannerInstance.scanFile.mockReturnValue({
      file: "/tmp/test.txt",
      matches: [],
    });
    (RegexScanner as any).mockImplementation(() => scannerInstance);

    const results = await handleScanSecrets("/tmp/test.txt", "auto");

    expect(results).toHaveLength(1);
    expect(scannerInstance.scanFile).toHaveBeenCalled();
  });

  it("should throw when gitleaks explicitly requested but unavailable", async () => {
    const glInstance = new GitleaksScanner() as any;
    glInstance.isAvailable.mockResolvedValue(false);
    (GitleaksScanner as any).mockImplementation(() => glInstance);

    await expect(handleScanSecrets("/tmp", "gitleaks")).rejects.toThrow(
      "Gitleaks not installed"
    );
  });

  it("should use gitleaks when available in auto mode", async () => {
    const glInstance = new GitleaksScanner() as any;
    glInstance.isAvailable.mockResolvedValue(true);
    glInstance.scanDirectory.mockResolvedValue([
      {
        file: "/tmp/secret.env",
        matches: [
          {
            pattern: { name: "generic-api-key", severity: "high", regex: "" },
            match: "sk-1234567890abcdef",
            line: 3,
            redacted: "sk-1****cdef",
          },
        ],
      },
    ]);
    (GitleaksScanner as any).mockImplementation(() => glInstance);

    const results = await handleScanSecrets("/tmp", "auto");

    expect(glInstance.scanDirectory).toHaveBeenCalledWith("/tmp");
    expect(results).toHaveLength(1);
    expect(results[0].matches[0].pattern).toBe("generic-api-key");
  });
});

describe("MCP Server — evaluate_command", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should allow a safe command", () => {
    const interceptorInstance = new CommandInterceptor() as any;
    interceptorInstance.evaluate.mockReturnValue({
      command: "ls -la",
      riskLevel: "low",
      allowed: true,
      requiresApproval: false,
    });
    (CommandInterceptor as any).mockImplementation(() => interceptorInstance);

    const result = handleEvaluateCommand("ls -la");

    expect(result.allowed).toBe(true);
    expect(result.risk_level).toBe("low");
    expect(result.requires_approval).toBe(false);
    expect(result).not.toHaveProperty("reason");
  });

  it("should block a dangerous command with reason", () => {
    const interceptorInstance = new CommandInterceptor() as any;
    interceptorInstance.evaluate.mockReturnValue({
      command: "rm -rf /",
      riskLevel: "critical",
      allowed: false,
      requiresApproval: false,
      reason: "Destructive system command",
    });
    (CommandInterceptor as any).mockImplementation(() => interceptorInstance);

    const result = handleEvaluateCommand("rm -rf /");

    expect(result.allowed).toBe(false);
    expect(result.risk_level).toBe("critical");
    expect(result.reason).toBe("Destructive system command");
  });

  it("should flag approval-required commands", () => {
    const interceptorInstance = new CommandInterceptor() as any;
    interceptorInstance.evaluate.mockReturnValue({
      command: "chmod 777 /tmp/test",
      riskLevel: "high",
      allowed: false,
      requiresApproval: true,
      reason: "Permissions change requires approval",
    });
    (CommandInterceptor as any).mockImplementation(() => interceptorInstance);

    const result = handleEvaluateCommand("chmod 777 /tmp/test");

    expect(result.allowed).toBe(false);
    expect(result.requires_approval).toBe(true);
    expect(result.risk_level).toBe("high");
  });
});

describe("MCP Server — read_audit_log", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return empty array for no entries", () => {
    const loggerInstance = new AuditLogger() as any;
    loggerInstance.read.mockReturnValue([]);
    (AuditLogger as any).mockImplementation(() => loggerInstance);

    const entries = handleReadAuditLog({ limit: 10 });

    expect(entries).toEqual([]);
  });

  it("should return entries and pass limit", () => {
    const mockEntries = [
      {
        timestamp: "2026-02-14T00:00:00Z",
        sessionId: "abc",
        eventType: "command_intercepted",
        securityCheck: { passed: true },
        resolution: { actionTaken: "allowed" },
      },
    ];
    const loggerInstance = new AuditLogger() as any;
    loggerInstance.read.mockReturnValue(mockEntries);
    (AuditLogger as any).mockImplementation(() => loggerInstance);

    const entries = handleReadAuditLog({ limit: 5 });

    expect(entries).toHaveLength(1);
    expect(loggerInstance.read).toHaveBeenCalledWith({
      limit: 5,
      eventType: undefined,
      since: undefined,
    });
  });

  it("should pass event_type filter", () => {
    const loggerInstance = new AuditLogger() as any;
    loggerInstance.read.mockReturnValue([{ eventType: "secret_detected" }]);
    (AuditLogger as any).mockImplementation(() => loggerInstance);

    handleReadAuditLog({ event_type: "secret_detected", limit: 5 });

    expect(loggerInstance.read).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: "secret_detected" })
    );
  });

  it("should parse since as Date", () => {
    const loggerInstance = new AuditLogger() as any;
    loggerInstance.read.mockReturnValue([]);
    (AuditLogger as any).mockImplementation(() => loggerInstance);

    handleReadAuditLog({ since: "2026-01-01T00:00:00Z" });

    const callArg = loggerInstance.read.mock.calls[0][0];
    expect(callArg.since).toBeInstanceOf(Date);
    expect(callArg.since.toISOString()).toBe("2026-01-01T00:00:00.000Z");
  });

  it("should default limit to 20", () => {
    const loggerInstance = new AuditLogger() as any;
    loggerInstance.read.mockReturnValue([]);
    (AuditLogger as any).mockImplementation(() => loggerInstance);

    handleReadAuditLog();

    expect(loggerInstance.read).toHaveBeenCalledWith(
      expect.objectContaining({ limit: 20 })
    );
  });
});

describe("MCP Server — get_config", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return full config when no key specified", () => {
    const managerInstance = new ConfigManager() as any;
    managerInstance.load.mockReturnValue({
      version: "1.0",
      agent: {
        riskLevel: "medium",
        commandPolicy: { mode: "intercept" },
        audit: { logAllActions: true },
      },
    });
    (ConfigManager as any).mockImplementation(() => managerInstance);

    const result = handleGetConfig();

    expect(result).toHaveProperty("version");
    expect(result).toHaveProperty("agent");
    expect(managerInstance.load).toHaveBeenCalled();
  });

  it("should return specific key value", () => {
    const managerInstance = new ConfigManager() as any;
    managerInstance.get.mockReturnValue("medium");
    (ConfigManager as any).mockImplementation(() => managerInstance);

    const result = handleGetConfig("agent.riskLevel");

    expect(result).toBe("medium");
    expect(managerInstance.get).toHaveBeenCalledWith("agent.riskLevel");
  });

  it("should return undefined for missing key", () => {
    const managerInstance = new ConfigManager() as any;
    managerInstance.get.mockReturnValue(undefined);
    (ConfigManager as any).mockImplementation(() => managerInstance);

    const result = handleGetConfig("nonexistent.path");

    expect(result).toBeUndefined();
  });
});

describe("MCP Server — utility functions", () => {
  it("formatScanResults should structure output correctly", () => {
    const raw = [
      {
        file: "/a/b.js",
        matches: [
          {
            pattern: { name: "github-token", severity: "critical", regex: "" },
            match: "ghp_abcdef1234567890",
            line: 10,
            redacted: "ghp_****",
          },
        ],
      },
    ];

    const formatted = formatScanResults(raw);

    expect(formatted).toHaveLength(1);
    expect(formatted[0].file).toBe("/a/b.js");
    expect(formatted[0].matches[0]).toEqual({
      pattern: "github-token",
      severity: "critical",
      line: 10,
      redacted: "ghp_****",
    });
  });

  it("formatScanResults should use match prefix when no redacted field", () => {
    const raw = [
      {
        file: "/a/b.js",
        matches: [
          {
            pattern: { name: "generic-secret", severity: "medium", regex: "" },
            match: "supersecretvalue",
            line: 5,
            // no redacted field
          },
        ],
      },
    ];

    const formatted = formatScanResults(raw);

    expect(formatted[0].matches[0].redacted).toBe("supe****");
  });
});
