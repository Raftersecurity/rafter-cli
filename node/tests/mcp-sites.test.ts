import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";

/**
 * Tests for the sites_* MCP tools (sites_create, sites_scan, sites_list,
 * sites_get) exposed by createServer(). Drives the real request handlers
 * through an in-memory MCP client/server pair, with axios mocked.
 */

vi.mock("axios");

vi.mock("../src/core/config-manager.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/core/config-manager.js")>()),
  ConfigManager: vi.fn().mockImplementation(function () {
    return {
      load: vi.fn().mockReturnValue({ version: "1.0" }),
      get: vi.fn().mockReturnValue(undefined),
      loadWithPolicy: vi.fn().mockReturnValue({ version: "1.0" }),
    };
  }),
}));

vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: vi.fn(),
}));

import axios from "axios";
import { createServer } from "../src/commands/mcp/server.js";

const mockedAxios = vi.mocked(axios, true);

let client: Client;
let server: Server;

async function setupClientServer() {
  server = createServer();
  client = new Client({ name: "test-client", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
}

async function teardown() {
  try { await client.close(); } catch { /* ignore */ }
  try { await server.close(); } catch { /* ignore */ }
}

function parseResult(result: any) {
  return JSON.parse(result.content[0].text);
}

describe("MCP sites_* tools", () => {
  beforeAll(async () => {
    process.env.RAFTER_API_KEY = "test-key";
    await setupClientServer();
  });
  afterAll(async () => {
    delete process.env.RAFTER_API_KEY;
    await teardown();
  });

  it("sites_create success", async () => {
    mockedAxios.post.mockResolvedValueOnce({
      data: { site: { id: "p1" }, run: { id: "r1" }, created: true },
    });
    const result = await client.callTool({ name: "sites_create", arguments: { url: "https://example.com" } });
    expect(result.isError).toBeFalsy();
    expect(parseResult(result)).toEqual({ site: { id: "p1" }, run: { id: "r1" }, created: true });
    expect(mockedAxios.post).toHaveBeenCalledWith(
      "https://rafter.so/api/static/sites",
      { url: "https://example.com" },
      { headers: { "x-api-key": "test-key" } }
    );
  });

  it("sites_create 401", async () => {
    mockedAxios.post.mockRejectedValueOnce({ response: { status: 401, data: { error: "invalid key" } } });
    const result = await client.callTool({ name: "sites_create", arguments: { url: "https://example.com" } });
    expect(result.isError).toBe(true);
    expect(parseResult(result).error).toBe("Unauthorized — invalid key");
  });

  it("sites_create 403 wrong scope", async () => {
    mockedAxios.post.mockRejectedValueOnce({ response: { status: 403, data: { error: "insufficient scope" } } });
    const result = await client.callTool({ name: "sites_create", arguments: { url: "https://example.com" } });
    expect(result.isError).toBe(true);
    expect(parseResult(result).error).toContain("insufficient scope");
  });

  it("sites_scan by projectId", async () => {
    mockedAxios.post.mockResolvedValueOnce({ data: { run: { id: "r1" } } });
    const result = await client.callTool({ name: "sites_scan", arguments: { projectId: "proj-1" } });
    expect(result.isError).toBeFalsy();
    expect(mockedAxios.post).toHaveBeenCalledWith(
      "https://rafter.so/api/static/sites/scan",
      { projectId: "proj-1" },
      expect.anything()
    );
  });

  it("sites_scan requires projectId or url", async () => {
    const result = await client.callTool({ name: "sites_scan", arguments: {} });
    expect(result.isError).toBe(true);
    expect(parseResult(result).error).toBe("Provide exactly one of projectId or url");
  });

  it("sites_scan rejects when both projectId and url are provided", async () => {
    const callsBefore = mockedAxios.post.mock.calls.length;
    const result = await client.callTool({
      name: "sites_scan",
      arguments: { projectId: "proj-1", url: "https://example.com" },
    });
    expect(result.isError).toBe(true);
    expect(parseResult(result).error).toBe("Provide exactly one of projectId or url, not both");
    expect(mockedAxios.post.mock.calls.length).toBe(callsBefore);
  });

  it("sites_scan 404 (not owned)", async () => {
    mockedAxios.post.mockRejectedValueOnce({ response: { status: 404, data: { error: "not found" } } });
    const result = await client.callTool({ name: "sites_scan", arguments: { projectId: "proj-1" } });
    expect(result.isError).toBe(true);
    expect(parseResult(result).error).toBe("Not found — not found");
  });

  it("sites_list success with params", async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { sites: [], limit: 5, offset: 0, has_more: false } });
    const result = await client.callTool({ name: "sites_list", arguments: { limit: 5, include_archived: true } });
    expect(result.isError).toBeFalsy();
    expect(mockedAxios.get).toHaveBeenCalledWith(
      "https://rafter.so/api/static/sites",
      { params: { limit: "5", include_archived: "true" }, headers: { "x-api-key": "test-key" } }
    );
  });

  it("sites_list 429", async () => {
    mockedAxios.get.mockRejectedValueOnce({ response: { status: 429, data: { error: "Rate limit exceeded" } } });
    const result = await client.callTool({ name: "sites_list", arguments: {} });
    expect(result.isError).toBe(true);
    expect(parseResult(result).error).toBe("Rate limited — Rate limit exceeded");
  });

  it("sites_get success", async () => {
    mockedAxios.get.mockResolvedValueOnce({
      data: { site: { id: "p1" }, latest_run: null, security: { critical: 0, warn: 0, info: 0, total: 0 } },
    });
    const result = await client.callTool({ name: "sites_get", arguments: { id: "p1" } });
    expect(result.isError).toBeFalsy();
    expect(mockedAxios.get).toHaveBeenCalledWith(
      "https://rafter.so/api/static/sites/p1",
      { headers: { "x-api-key": "test-key" } }
    );
  });

  it("sites_get 404", async () => {
    mockedAxios.get.mockRejectedValueOnce({ response: { status: 404, data: { error: "not found" } } });
    const result = await client.callTool({ name: "sites_get", arguments: { id: "nonexistent" } });
    expect(result.isError).toBe(true);
    expect(parseResult(result).error).toBe("Not found — not found");
  });

  it("sites_get requires id", async () => {
    const result = await client.callTool({ name: "sites_get", arguments: {} });
    expect(result.isError).toBe(true);
  });
});

describe("MCP sites_* tools — missing API key", () => {
  it("returns a helpful error instead of crashing the server", async () => {
    delete process.env.RAFTER_API_KEY;
    const s = createServer();
    const c = new Client({ name: "no-key-client", version: "1.0.0" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await Promise.all([s.connect(st), c.connect(ct)]);

    const result = await c.callTool({ name: "sites_get", arguments: { id: "p1" } });
    expect(result.isError).toBe(true);
    expect(parseResult(result).error).toContain("No API key configured");

    await c.close();
    await s.close();
  });
});
