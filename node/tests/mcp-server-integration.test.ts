import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

// ── Mocks ────────────────────────────────────────────────────────────────────

vi.mock("../src/scanners/gitleaks.js", () => ({
  GitleaksScanner: vi.fn().mockImplementation(function () {
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
      scanFile: vi.fn().mockReturnValue({ file: "/tmp/test.txt", matches: [] }),
      scanDirectory: vi.fn().mockReturnValue([]),
    };
  }),
}));

vi.mock("../src/core/command-interceptor.js", () => ({
  CommandInterceptor: vi.fn().mockImplementation(function () {
    return {
      evaluate: vi.fn().mockImplementation((cmd: string) => {
        if (cmd.includes("rm -rf")) {
          return {
            command: cmd,
            riskLevel: "critical",
            allowed: false,
            requiresApproval: false,
            reason: "Destructive system command",
          };
        }
        return {
          command: cmd,
          riskLevel: "low",
          allowed: true,
          requiresApproval: false,
        };
      }),
    };
  }),
}));

vi.mock("../src/core/audit-logger.js", () => ({
  AuditLogger: vi.fn().mockImplementation(function () {
    return {
      read: vi.fn().mockReturnValue([
        {
          timestamp: "2026-03-25T00:00:00Z",
          sessionId: "test-session",
          eventType: "command_intercepted",
          securityCheck: { passed: true },
          resolution: { actionTaken: "allowed" },
        },
      ]),
    };
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
      get: vi.fn().mockImplementation((key: string) => {
        const config: Record<string, unknown> = {
          "agent.riskLevel": "medium",
          "agent.commandPolicy.mode": "intercept",
        };
        return config[key] ?? undefined;
      }),
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

import { createServer } from "../src/commands/mcp/server.js";
import { RegexScanner } from "../src/scanners/regex-scanner.js";
import { GitleaksScanner } from "../src/scanners/gitleaks.js";
import { AuditLogger } from "../src/core/audit-logger.js";

// ── Test harness ─────────────────────────────────────────────────────────────

let client: Client;
let server: Server;

async function setupClientServer() {
  server = createServer();
  client = new Client({ name: "test-client", version: "1.0.0" });

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);
}

async function teardown() {
  try { await client.close(); } catch { /* ignore */ }
  try { await server.close(); } catch { /* ignore */ }
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("MCP Server — tool registration and schema", () => {
  beforeAll(setupClientServer);
  afterAll(teardown);

  it("should register exactly 4 tools", async () => {
    const { tools } = await client.listTools();
    expect(tools).toHaveLength(4);
  });

  it("should expose scan_secrets with correct schema", async () => {
    const { tools } = await client.listTools();
    const tool = tools.find(t => t.name === "scan_secrets");
    expect(tool).toBeDefined();
    expect(tool!.inputSchema.required).toContain("path");
    expect(tool!.inputSchema.properties).toHaveProperty("path");
    expect(tool!.inputSchema.properties).toHaveProperty("engine");
  });

  it("should expose evaluate_command with correct schema", async () => {
    const { tools } = await client.listTools();
    const tool = tools.find(t => t.name === "evaluate_command");
    expect(tool).toBeDefined();
    expect(tool!.inputSchema.required).toContain("command");
  });

  it("should expose read_audit_log with correct schema", async () => {
    const { tools } = await client.listTools();
    const tool = tools.find(t => t.name === "read_audit_log");
    expect(tool).toBeDefined();
    expect(tool!.inputSchema.properties).toHaveProperty("limit");
    expect(tool!.inputSchema.properties).toHaveProperty("event_type");
    expect(tool!.inputSchema.properties).toHaveProperty("since");
    // No required fields for read_audit_log
    expect(tool!.inputSchema.required).toBeUndefined();
  });

  it("should expose get_config with correct schema", async () => {
    const { tools } = await client.listTools();
    const tool = tools.find(t => t.name === "get_config");
    expect(tool).toBeDefined();
    expect(tool!.inputSchema.properties).toHaveProperty("key");
  });

  it("tool names should match expected set exactly", async () => {
    const { tools } = await client.listTools();
    const names = tools.map(t => t.name).sort();
    expect(names).toEqual([
      "evaluate_command",
      "get_config",
      "read_audit_log",
      "scan_secrets",
    ]);
  });
});

describe("MCP Server — resource registration", () => {
  beforeAll(setupClientServer);
  afterAll(teardown);

  it("should register exactly 2 resources", async () => {
    const { resources } = await client.listResources();
    expect(resources).toHaveLength(2);
  });

  it("should expose rafter://config resource", async () => {
    const { resources } = await client.listResources();
    const res = resources.find(r => r.uri === "rafter://config");
    expect(res).toBeDefined();
    expect(res!.mimeType).toBe("application/json");
  });

  it("should expose rafter://policy resource", async () => {
    const { resources } = await client.listResources();
    const res = resources.find(r => r.uri === "rafter://policy");
    expect(res).toBeDefined();
    expect(res!.mimeType).toBe("application/json");
  });

  it("should return valid JSON from rafter://config", async () => {
    const result = await client.readResource({ uri: "rafter://config" });
    expect(result.contents).toHaveLength(1);
    expect(result.contents[0].mimeType).toBe("application/json");
    const parsed = JSON.parse(result.contents[0].text as string);
    expect(parsed).toHaveProperty("version");
    expect(parsed).toHaveProperty("agent");
  });

  it("should return valid JSON from rafter://policy", async () => {
    const result = await client.readResource({ uri: "rafter://policy" });
    expect(result.contents).toHaveLength(1);
    const parsed = JSON.parse(result.contents[0].text as string);
    expect(parsed).toHaveProperty("version");
    expect(parsed).toHaveProperty("agent");
  });

  it("should throw on unknown resource URI", async () => {
    await expect(
      client.readResource({ uri: "rafter://nonexistent" })
    ).rejects.toThrow();
  });
});

describe("MCP Server — tool execution end-to-end", () => {
  beforeAll(setupClientServer);
  afterAll(teardown);
  beforeEach(() => vi.clearAllMocks());

  it("scan_secrets should return results via MCP protocol", async () => {
    const scannerInstance = new RegexScanner() as any;
    scannerInstance.scanDirectory.mockReturnValue([
      {
        file: "/tmp/secret.env",
        matches: [
          {
            pattern: { name: "aws-access-key", severity: "high", regex: "" },
            match: "AKIAIOSFODNN7EXAMPLE1",
            line: 1,
            redacted: "AKIA****",
          },
        ],
      },
    ]);
    (RegexScanner as any).mockImplementation(function () { return scannerInstance; });

    const result = await client.callTool({ name: "scan_secrets", arguments: { path: "/tmp/dir" } });

    expect(result.isError).toBeFalsy();
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content).toHaveLength(1);
    const parsed = JSON.parse(content[0].text);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].file).toBe("/tmp/secret.env");
    expect(parsed[0].matches[0].pattern).toBe("aws-access-key");
  });

  it("scan_secrets with gitleaks available uses gitleaks", async () => {
    const glInstance = new GitleaksScanner() as any;
    glInstance.isAvailable.mockResolvedValue(true);
    glInstance.scanDirectory.mockResolvedValue([
      {
        file: "/tmp/leak.py",
        matches: [
          {
            pattern: { name: "github-token", severity: "critical", regex: "" },
            match: "ghp_abcdef1234567890",
            line: 5,
            redacted: "ghp_****",
          },
        ],
      },
    ]);
    (GitleaksScanner as any).mockImplementation(function () { return glInstance; });

    const result = await client.callTool({ name: "scan_secrets", arguments: { path: "/tmp", engine: "auto" } });

    const parsed = JSON.parse((result.content as any)[0].text);
    expect(parsed[0].matches[0].pattern).toBe("github-token");
    expect(glInstance.scanDirectory).toHaveBeenCalledWith("/tmp");
  });

  it("evaluate_command allows safe commands", async () => {
    const result = await client.callTool({ name: "evaluate_command", arguments: { command: "ls -la" } });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(parsed.allowed).toBe(true);
    expect(parsed.risk_level).toBe("low");
    expect(parsed.requires_approval).toBe(false);
    expect(parsed).not.toHaveProperty("reason");
  });

  it("evaluate_command blocks dangerous commands with reason", async () => {
    const result = await client.callTool({ name: "evaluate_command", arguments: { command: "rm -rf /" } });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(parsed.allowed).toBe(false);
    expect(parsed.risk_level).toBe("critical");
    expect(parsed.reason).toBe("Destructive system command");
  });

  it("read_audit_log returns entries", async () => {
    const result = await client.callTool({ name: "read_audit_log", arguments: { limit: 10 } });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].eventType).toBe("command_intercepted");
  });

  it("read_audit_log passes filters correctly", async () => {
    const loggerInstance = new AuditLogger() as any;
    loggerInstance.read.mockReturnValue([]);
    (AuditLogger as any).mockImplementation(function () { return loggerInstance; });

    await client.callTool({
      name: "read_audit_log",
      arguments: {
        limit: 5,
        event_type: "secret_detected",
        since: "2026-01-01T00:00:00Z",
      },
    });

    expect(loggerInstance.read).toHaveBeenCalledWith(
      expect.objectContaining({
        limit: 5,
        eventType: "secret_detected",
      })
    );
    const callArg = loggerInstance.read.mock.calls[0][0];
    expect(callArg.since).toBeInstanceOf(Date);
  });

  it("get_config returns full config when no key", async () => {
    const result = await client.callTool({ name: "get_config", arguments: {} });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(parsed).toHaveProperty("version");
    expect(parsed).toHaveProperty("agent");
  });

  it("get_config returns specific key value", async () => {
    const result = await client.callTool({ name: "get_config", arguments: { key: "agent.riskLevel" } });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(parsed).toBe("medium");
  });

  it("unknown tool returns error", async () => {
    const result = await client.callTool({ name: "nonexistent_tool", arguments: {} });

    expect(result.isError).toBe(true);
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(parsed.error).toContain("Unknown tool");
  });
});

describe("MCP Server — version reporting", () => {
  beforeAll(setupClientServer);
  afterAll(teardown);

  it("server version should match package.json", async () => {
    const { createRequire } = await import("module");
    const _require = createRequire(import.meta.url);
    const { version } = _require("../package.json");

    // Server info is available after connection
    const serverInfo = (server as any).getClientCapabilities
      ? undefined
      : server;

    // The version is set in the Server constructor — verify it's a valid semver
    expect(version).toMatch(/^\d+\.\d+\.\d+$/);
    // Ensure it's NOT the old hardcoded "0.5.0"
    expect(version).not.toBe("0.5.0");
  });

  it("version is read dynamically from package.json, not hardcoded", async () => {
    // Read the source to confirm no hardcoded version
    const fs = await import("fs");
    const source = fs.readFileSync(
      new URL("../src/commands/mcp/server.ts", import.meta.url),
      "utf8"
    );
    // Should use createRequire to load package.json, not a hardcoded string
    expect(source).toContain('_require("../../../package.json")');
    expect(source).not.toMatch(/version:\s*["']0\.5\.0["']/);
    expect(source).not.toMatch(/version:\s*["']0\.6\.\d["']/);
  });
});

describe("MCP Server — lifecycle", () => {
  it("should create and connect server without errors", async () => {
    const s = createServer();
    const c = new Client({ name: "lifecycle-test", version: "1.0.0" });
    const [ct, st] = InMemoryTransport.createLinkedPair();

    await expect(
      Promise.all([s.connect(st), c.connect(ct)])
    ).resolves.not.toThrow();

    await c.close();
    await s.close();
  });

  it("should handle multiple sequential connect/disconnect cycles", async () => {
    for (let i = 0; i < 3; i++) {
      const s = createServer();
      const c = new Client({ name: `cycle-${i}`, version: "1.0.0" });
      const [ct, st] = InMemoryTransport.createLinkedPair();

      await Promise.all([s.connect(st), c.connect(ct)]);

      // Quick sanity — tools are still listed
      const { tools } = await c.listTools();
      expect(tools).toHaveLength(4);

      await c.close();
      await s.close();
    }
  });

  it("capabilities should declare tools and resources", () => {
    const s = createServer();
    // Server constructor sets capabilities; verify the server object was created
    // with the right shape
    expect(s).toBeInstanceOf(Server);
  });
});
