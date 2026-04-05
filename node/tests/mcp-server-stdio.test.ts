/**
 * Real stdio transport tests for the MCP server.
 *
 * These tests spawn `node dist/index.js mcp serve` as a child process and
 * communicate with it via stdin/stdout using the MCP SDK's StdioClientTransport.
 * No mocking — the full server stack runs end-to-end over real pipes.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// ── Helpers ──────────────────────────────────────────────────────────────────

const NODE_ENTRY = path.resolve(import.meta.dirname, "../dist/index.js");

function createStdioTransport(): StdioClientTransport {
  return new StdioClientTransport({
    command: "node",
    args: [NODE_ENTRY, "mcp", "serve"],
    stderr: "pipe",
  });
}

async function createConnectedClient(): Promise<{ client: Client; transport: StdioClientTransport }> {
  const transport = createStdioTransport();
  const client = new Client({ name: "stdio-test-client", version: "1.0.0" });
  await client.connect(transport);
  return { client, transport };
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("MCP Server — real stdio transport: tool listing", () => {
  let client: Client;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    ({ client, transport } = await createConnectedClient());
  });

  afterAll(async () => {
    await client.close();
  });

  it("should register exactly 4 tools over stdio", async () => {
    const { tools } = await client.listTools();
    expect(tools).toHaveLength(4);
  });

  it("tool names match expected set", async () => {
    const { tools } = await client.listTools();
    const names = tools.map(t => t.name).sort();
    expect(names).toEqual([
      "evaluate_command",
      "get_config",
      "read_audit_log",
      "scan_secrets",
    ]);
  });

  it("scan_secrets has required path parameter", async () => {
    const { tools } = await client.listTools();
    const tool = tools.find(t => t.name === "scan_secrets")!;
    expect(tool.inputSchema.required).toContain("path");
    expect(tool.inputSchema.properties).toHaveProperty("path");
    expect(tool.inputSchema.properties).toHaveProperty("engine");
  });

  it("evaluate_command has required command parameter", async () => {
    const { tools } = await client.listTools();
    const tool = tools.find(t => t.name === "evaluate_command")!;
    expect(tool.inputSchema.required).toContain("command");
  });

  it("read_audit_log has optional limit, event_type, since", async () => {
    const { tools } = await client.listTools();
    const tool = tools.find(t => t.name === "read_audit_log")!;
    expect(tool.inputSchema.properties).toHaveProperty("limit");
    expect(tool.inputSchema.properties).toHaveProperty("event_type");
    expect(tool.inputSchema.properties).toHaveProperty("since");
  });

  it("get_config has optional key parameter", async () => {
    const { tools } = await client.listTools();
    const tool = tools.find(t => t.name === "get_config")!;
    expect(tool.inputSchema.properties).toHaveProperty("key");
  });
});

describe("MCP Server — real stdio transport: resource listing", () => {
  let client: Client;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    ({ client, transport } = await createConnectedClient());
  });

  afterAll(async () => {
    await client.close();
  });

  it("should register exactly 2 resources", async () => {
    const { resources } = await client.listResources();
    expect(resources).toHaveLength(2);
  });

  it("should expose rafter://config with JSON mime type", async () => {
    const { resources } = await client.listResources();
    const res = resources.find(r => r.uri === "rafter://config");
    expect(res).toBeDefined();
    expect(res!.mimeType).toBe("application/json");
  });

  it("should expose rafter://policy with JSON mime type", async () => {
    const { resources } = await client.listResources();
    const res = resources.find(r => r.uri === "rafter://policy");
    expect(res).toBeDefined();
    expect(res!.mimeType).toBe("application/json");
  });
});

describe("MCP Server — real stdio transport: scan_secrets", () => {
  let client: Client;
  let transport: StdioClientTransport;
  let tmpDir: string;

  beforeAll(async () => {
    ({ client, transport } = await createConnectedClient());
  });

  afterAll(async () => {
    await client.close();
  });

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-stdio-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should detect a planted AWS key in a directory", async () => {
    fs.writeFileSync(path.join(tmpDir, "creds.env"), "AWS_KEY=AKIAIOSFODNN7EXAMPLE1\n");

    const result = await client.callTool({
      name: "scan_secrets",
      arguments: { path: tmpDir, engine: "patterns" },
    });

    expect(result.isError).toBeFalsy();
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content).toHaveLength(1);
    const parsed = JSON.parse(content[0].text);
    expect(parsed.length).toBeGreaterThanOrEqual(1);
    const withMatches = parsed.filter((r: any) => r.matches.length > 0);
    expect(withMatches.length).toBeGreaterThanOrEqual(1);
    expect(withMatches[0].matches[0]).toHaveProperty("pattern");
    expect(withMatches[0].matches[0]).toHaveProperty("severity");
    expect(withMatches[0].matches[0]).toHaveProperty("redacted");
  });

  it("should scan a directory and find secrets", async () => {
    fs.writeFileSync(path.join(tmpDir, "clean.txt"), "nothing here\n");
    fs.writeFileSync(path.join(tmpDir, "secret.env"), "GITHUB_TOKEN=ghp_FAKEEFabcdef1234567890abcdef1234567\n");

    const result = await client.callTool({
      name: "scan_secrets",
      arguments: { path: tmpDir, engine: "patterns" },
    });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse((result.content as any)[0].text);
    const withMatches = parsed.filter((r: any) => r.matches.length > 0);
    expect(withMatches.length).toBeGreaterThanOrEqual(1);
  });

  it("should return no findings for a clean directory", async () => {
    fs.writeFileSync(path.join(tmpDir, "clean.py"), "x = 1 + 2\nprint(x)\n");
    fs.writeFileSync(path.join(tmpDir, "readme.txt"), "This is a clean project\n");

    const result = await client.callTool({
      name: "scan_secrets",
      arguments: { path: tmpDir, engine: "patterns" },
    });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse((result.content as any)[0].text);
    // scanFiles only returns entries with matches, so clean dir → empty array
    expect(parsed).toHaveLength(0);
  });
});

describe("MCP Server — real stdio transport: evaluate_command", () => {
  let client: Client;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    ({ client, transport } = await createConnectedClient());
  });

  afterAll(async () => {
    await client.close();
  });

  it("should allow a safe command", async () => {
    const result = await client.callTool({
      name: "evaluate_command",
      arguments: { command: "ls -la" },
    });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(parsed.allowed).toBe(true);
    expect(parsed.risk_level).toBe("low");
    expect(parsed.requires_approval).toBe(false);
  });

  it("should block a destructive command with reason", async () => {
    const result = await client.callTool({
      name: "evaluate_command",
      arguments: { command: "rm -rf /" },
    });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(parsed.allowed).toBe(false);
    expect(parsed.risk_level).toBe("critical");
    expect(parsed.reason).toBeTruthy();
  });
});

describe("MCP Server — real stdio transport: read_audit_log", () => {
  let client: Client;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    ({ client, transport } = await createConnectedClient());
  });

  afterAll(async () => {
    await client.close();
  });

  it("should return an array (possibly empty)", async () => {
    const result = await client.callTool({
      name: "read_audit_log",
      arguments: { limit: 5 },
    });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(Array.isArray(parsed)).toBe(true);
  });

  it("should accept filter parameters without error", async () => {
    const result = await client.callTool({
      name: "read_audit_log",
      arguments: {
        limit: 3,
        event_type: "command_intercepted",
        since: "2026-01-01T00:00:00Z",
      },
    });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(Array.isArray(parsed)).toBe(true);
  });
});

describe("MCP Server — real stdio transport: get_config", () => {
  let client: Client;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    ({ client, transport } = await createConnectedClient());
  });

  afterAll(async () => {
    await client.close();
  });

  it("should return full config when no key provided", async () => {
    const result = await client.callTool({
      name: "get_config",
      arguments: {},
    });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(parsed).toHaveProperty("version");
    expect(parsed).toHaveProperty("agent");
  });

  it("should return specific key value", async () => {
    const result = await client.callTool({
      name: "get_config",
      arguments: { key: "agent.riskLevel" },
    });

    expect(result.isError).toBeFalsy();
    // Should not error — value can be the key value or undefined
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(parsed).toBeDefined();
  });
});

describe("MCP Server — real stdio transport: resources", () => {
  let client: Client;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    ({ client, transport } = await createConnectedClient());
  });

  afterAll(async () => {
    await client.close();
  });

  it("rafter://config returns valid JSON with version and agent", async () => {
    const result = await client.readResource({ uri: "rafter://config" });
    expect(result.contents).toHaveLength(1);
    expect(result.contents[0].mimeType).toBe("application/json");
    const parsed = JSON.parse(result.contents[0].text as string);
    expect(parsed).toHaveProperty("version");
    expect(parsed).toHaveProperty("agent");
  });

  it("rafter://policy returns valid JSON with version and agent", async () => {
    const result = await client.readResource({ uri: "rafter://policy" });
    expect(result.contents).toHaveLength(1);
    const parsed = JSON.parse(result.contents[0].text as string);
    expect(parsed).toHaveProperty("version");
    expect(parsed).toHaveProperty("agent");
  });

  it("unknown resource URI throws", async () => {
    await expect(
      client.readResource({ uri: "rafter://nonexistent" })
    ).rejects.toThrow();
  });
});

describe("MCP Server — real stdio transport: error handling", () => {
  let client: Client;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    ({ client, transport } = await createConnectedClient());
  });

  afterAll(async () => {
    await client.close();
  });

  it("unknown tool returns error", async () => {
    const result = await client.callTool({
      name: "nonexistent_tool",
      arguments: {},
    });

    expect(result.isError).toBe(true);
    const parsed = JSON.parse((result.content as any)[0].text);
    expect(parsed.error).toContain("Unknown tool");
  });
});

describe("MCP Server — real stdio transport: lifecycle", () => {
  it("should connect and disconnect cleanly", async () => {
    const { client } = await createConnectedClient();
    // Verify we can list tools (connection works)
    const { tools } = await client.listTools();
    expect(tools).toHaveLength(4);
    await client.close();
  });

  it("should handle sequential connect/disconnect cycles", async () => {
    for (let i = 0; i < 3; i++) {
      const { client } = await createConnectedClient();
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(4);
      await client.close();
    }
  });
});
