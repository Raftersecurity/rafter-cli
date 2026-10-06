import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mocks ────────────────────────────────────────────────────────────────────
// Must be declared before imports so vi.mock hoists correctly.

vi.mock("../src/scanners/betterleaks.js", () => ({
  BetterleaksScanner: vi.fn().mockImplementation(function () {
    return {
      isAvailable: vi.fn().mockResolvedValue(false),
      scanDirectory: vi.fn().mockResolvedValue([]),
      scanFile: vi.fn().mockResolvedValue({ file: "", matches: [] }),
    };
  }),
}));

vi.mock("../src/scanners/regex-scanner.js", () => ({
  RegexScanner: vi.fn().mockImplementation(function () {
    return {
      scanFile: vi.fn().mockReturnValue({ file: "", matches: [] }),
      scanDirectory: vi.fn().mockReturnValue([]),
    };
  }),
}));

vi.mock("../src/core/command-interceptor.js", () => ({
  CommandInterceptor: vi.fn().mockImplementation(function () {
    return {
      evaluate: vi.fn().mockReturnValue({
        command: "",
        riskLevel: "low",
        allowed: true,
        requiresApproval: false,
      }),
    };
  }),
}));

vi.mock("../src/core/audit-logger.js", () => ({
  AuditLogger: vi.fn().mockImplementation(function () {
    return { read: vi.fn().mockReturnValue([]) };
  }),
}));

vi.mock("../src/core/config-manager.js", () => ({
  ConfigManager: vi.fn().mockImplementation(function () {
    return {
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
    };
  }),
}));

// Prevent MCP SDK from touching stdio
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: vi.fn(),
}));

import { BetterleaksScanner } from "../src/scanners/betterleaks.js";
import { RegexScanner } from "../src/scanners/regex-scanner.js";
import { unionScanResults } from "../src/scanners/union.js";
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
  const runPatterns = (): Array<{ file: string; matches: any[] }> => {
    const scanner = new RegexScanner();
    try {
      return scanner.scanDirectory(scanPath) as any;
    } catch {
      return [scanner.scanFile(scanPath)];
    }
  };

  if (engine === "betterleaks") {
    const bl = new BetterleaksScanner();
    if (!(await bl.isAvailable())) throw new Error("Betterleaks not installed");
    try {
      return formatScanResults(await bl.scanDirectory(scanPath));
    } catch {
      throw new Error("Betterleaks scan failed");
    }
  }

  if (engine === "auto") {
    // sable-j85 — auto runs BOTH engines and unions; degrade to patterns-only
    // when betterleaks is unavailable or errors.
    const bl = new BetterleaksScanner();
    if (await bl.isAvailable()) {
      try {
        const blResults = await bl.scanDirectory(scanPath);
        return formatScanResults(unionScanResults(blResults as any, runPatterns() as any));
      } catch {
        // fall through to patterns-only
      }
    }
    return formatScanResults(runPatterns());
  }

  return formatScanResults(runPatterns());
}

function formatScanResults(results: Array<{ file: string; matches: any[] }>) {
  return results.map((r) => ({
    file: r.file,
    matches: r.matches.map((m: any) => ({
      pattern: m.pattern.name,
      severity: m.pattern.severity,
      line: m.line,
      redacted: m.redacted || m.match.slice(0, 4) + "****",
      ...(m.engines ? { engines: m.engines } : {}),
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

  it("should fall back to regex when betterleaks unavailable in auto mode", async () => {
    const blInstance = new BetterleaksScanner() as any;
    blInstance.isAvailable.mockResolvedValue(false);
    (BetterleaksScanner as any).mockImplementation(function () { return blInstance; });

    const scannerInstance = new RegexScanner() as any;
    scannerInstance.scanDirectory.mockImplementation(() => {
      throw new Error("not a directory");
    });
    scannerInstance.scanFile.mockReturnValue({
      file: "/tmp/test.txt",
      matches: [],
    });
    (RegexScanner as any).mockImplementation(function () { return scannerInstance; });

    const results = await handleScanSecrets("/tmp/test.txt", "auto");

    expect(results).toHaveLength(1);
    expect(scannerInstance.scanFile).toHaveBeenCalled();
  });

  it("should throw when betterleaks explicitly requested but unavailable", async () => {
    const blInstance = new BetterleaksScanner() as any;
    blInstance.isAvailable.mockResolvedValue(false);
    (BetterleaksScanner as any).mockImplementation(function () { return blInstance; });

    await expect(handleScanSecrets("/tmp", "betterleaks")).rejects.toThrow(
      "Betterleaks not installed"
    );
  });

  it("should run BOTH engines and union findings in auto mode (sable-j85)", async () => {
    // betterleaks finds a generic key AND a private key on the same file.
    const blInstance = new BetterleaksScanner() as any;
    blInstance.isAvailable.mockResolvedValue(true);
    blInstance.scanDirectory.mockResolvedValue([
      {
        file: "/tmp/secret.env",
        matches: [
          {
            pattern: { name: "generic-api-key", severity: "high", regex: "" },
            match: "sk-1234567890abcdef",
            line: 3,
            redacted: "sk-1****cdef",
          },
          {
            pattern: { name: "private-key", severity: "critical", regex: "" },
            match: "-----BEGIN PRIVATE KEY-----",
            line: 9,
            redacted: "----****----",
          },
        ],
      },
    ]);
    (BetterleaksScanner as any).mockImplementation(function () { return blInstance; });

    // patterns re-finds the private key (same file+line+text → dedup) and
    // ALSO catches an AWS key betterleaks misses (sable-h2y) on a second file.
    const scannerInstance = new RegexScanner() as any;
    scannerInstance.scanDirectory.mockReturnValue([
      {
        file: "/tmp/secret.env",
        matches: [
          {
            pattern: { name: "Private Key", severity: "critical", regex: "" },
            match: "-----BEGIN PRIVATE KEY-----",
            line: 9,
            redacted: "----****----",
          },
        ],
      },
      {
        file: "/tmp/creds.txt",
        matches: [
          {
            pattern: { name: "AWS Access Key ID", severity: "high", regex: "" },
            match: "AKIAIOSFODNN7EXAMPLE1",
            line: 1,
            redacted: "AKIA****PLE1",
          },
        ],
      },
    ]);
    (RegexScanner as any).mockImplementation(function () { return scannerInstance; });

    const results = await handleScanSecrets("/tmp", "auto");

    // Both engines were consulted.
    expect(blInstance.scanDirectory).toHaveBeenCalledWith("/tmp");
    expect(scannerInstance.scanDirectory).toHaveBeenCalled();

    // Two files surfaced: secret.env (betterleaks first) then creds.txt.
    expect(results).toHaveLength(2);
    const env = results.find((r) => r.file === "/tmp/secret.env")!;
    const creds = results.find((r) => r.file === "/tmp/creds.txt")!;

    // secret.env: generic-api-key (betterleaks-only) + private key (deduped).
    expect(env.matches).toHaveLength(2);
    const generic = env.matches.find((m) => m.pattern === "generic-api-key")!;
    expect(generic.engines).toEqual(["betterleaks"]);

    // The private key fired in both engines → deduped, betterleaks rule-id
    // kept, both engines recorded.
    const priv = env.matches.find((m) => m.pattern === "private-key")!;
    expect(priv).toBeDefined();
    expect(priv.engines).toEqual(["betterleaks", "patterns"]);

    // The AWS key betterleaks missed is still reported, attributed to patterns.
    expect(creds.matches).toHaveLength(1);
    expect(creds.matches[0].pattern).toBe("AWS Access Key ID");
    expect(creds.matches[0].engines).toEqual(["patterns"]);
  });

  it("should degrade to patterns-only when betterleaks errors in auto mode", async () => {
    const blInstance = new BetterleaksScanner() as any;
    blInstance.isAvailable.mockResolvedValue(true);
    blInstance.scanDirectory.mockRejectedValue(new Error("betterleaks boom"));
    (BetterleaksScanner as any).mockImplementation(function () { return blInstance; });

    const scannerInstance = new RegexScanner() as any;
    scannerInstance.scanDirectory.mockReturnValue([
      {
        file: "/tmp/creds.txt",
        matches: [
          {
            pattern: { name: "AWS Access Key ID", severity: "high", regex: "" },
            match: "AKIAIOSFODNN7EXAMPLE1",
            line: 1,
            redacted: "AKIA****PLE1",
          },
        ],
      },
    ]);
    (RegexScanner as any).mockImplementation(function () { return scannerInstance; });

    const results = await handleScanSecrets("/tmp", "auto");

    expect(results).toHaveLength(1);
    expect(results[0].matches[0].pattern).toBe("AWS Access Key ID");
    // Single-engine fallback path → no engine attribution.
    expect(results[0].matches[0].engines).toBeUndefined();
  });
});

describe("MCP Server — evaluate_command", () => {
  beforeEach(() => {
    vi.clearAllMocks();
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
    (CommandInterceptor as any).mockImplementation(function () { return interceptorInstance; });

    const result = handleEvaluateCommand("chmod 777 /tmp/test");

    expect(result.allowed).toBe(false);
    expect(result.requires_approval).toBe(true);
    expect(result.risk_level).toBe("high");
  });
});

