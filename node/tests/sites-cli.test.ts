import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Tests for `rafter sites` — CLI commands for Rafter Sites (live-application
 * security monitoring). All tests mock axios so no network calls are made.
 */

vi.mock("axios");

import axios from "axios";
import { runSitesCreate } from "../src/commands/sites/create.js";
import { runSitesScan } from "../src/commands/sites/scan.js";
import { runSitesList } from "../src/commands/sites/list.js";
import { runSitesGet } from "../src/commands/sites/get.js";
import { EXIT_SUCCESS, EXIT_GENERAL_ERROR, EXIT_INSUFFICIENT_SCOPE, EXIT_SCAN_NOT_FOUND, EXIT_QUOTA_EXHAUSTED } from "../src/utils/api.js";

const mockedAxios = vi.mocked(axios, true);
const opts = { apiKey: "test-key", format: "json", quiet: true };

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(process.stdout, "write").mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("sites create", () => {
  it("returns EXIT_SUCCESS and posts the url on success", async () => {
    mockedAxios.post.mockResolvedValueOnce({
      data: { site: { id: "p1" }, run: { id: "r1" }, created: true },
    });

    const code = await runSitesCreate("https://example.com", opts);

    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.post).toHaveBeenCalledWith(
      expect.stringContaining("/static/sites"),
      { url: "https://example.com" },
      { headers: { "x-api-key": "test-key" } }
    );
  });

  it("returns EXIT_GENERAL_ERROR for 401", async () => {
    mockedAxios.post.mockRejectedValueOnce({ response: { status: 401, data: { error: "bad key" } } });
    const code = await runSitesCreate("https://example.com", opts);
    expect(code).toBe(EXIT_GENERAL_ERROR);
  });

  it("returns EXIT_INSUFFICIENT_SCOPE for 403 wrong scope", async () => {
    mockedAxios.post.mockRejectedValueOnce({ response: { status: 403, data: { error: "insufficient scope: requires read-and-scan" } } });
    const code = await runSitesCreate("https://example.com", opts);
    expect(code).toBe(EXIT_INSUFFICIENT_SCOPE);
  });

  it("returns EXIT_QUOTA_EXHAUSTED for 429", async () => {
    mockedAxios.post.mockRejectedValueOnce({ response: { status: 429, data: { error: "Rate limit exceeded" } } });
    const code = await runSitesCreate("https://example.com", opts);
    expect(code).toBe(EXIT_QUOTA_EXHAUSTED);
  });
});

describe("sites scan", () => {
  it("sends { projectId } when given a bare id", async () => {
    mockedAxios.post.mockResolvedValueOnce({ data: { run: { id: "r1" } } });
    const code = await runSitesScan("proj-123", opts);
    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.post).toHaveBeenCalledWith(
      expect.stringContaining("/static/sites/scan"),
      { projectId: "proj-123" },
      expect.anything()
    );
  });

  it("sends { url } when given a URL", async () => {
    mockedAxios.post.mockResolvedValueOnce({ data: { run: { id: "r1" } } });
    const code = await runSitesScan("https://example.com", opts);
    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.post).toHaveBeenCalledWith(
      expect.stringContaining("/static/sites/scan"),
      { url: "https://example.com" },
      expect.anything()
    );
  });

  it("includes sections when provided", async () => {
    mockedAxios.post.mockResolvedValueOnce({ data: { run: { id: "r1" } } });
    await runSitesScan("proj-123", { ...opts, sections: "security, dns" });
    expect(mockedAxios.post).toHaveBeenCalledWith(
      expect.stringContaining("/static/sites/scan"),
      { projectId: "proj-123", sections: ["security", "dns"] },
      expect.anything()
    );
  });

  it("rejects an invalid section without calling the API", async () => {
    const code = await runSitesScan("proj-123", { ...opts, sections: "bogus" });
    expect(code).toBe(1);
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });

  it("returns EXIT_SCAN_NOT_FOUND for 404 (not owned)", async () => {
    mockedAxios.post.mockRejectedValueOnce({ response: { status: 404, data: { error: "not found" } } });
    const code = await runSitesScan("proj-123", opts);
    expect(code).toBe(EXIT_SCAN_NOT_FOUND);
  });

  it("returns EXIT_INSUFFICIENT_SCOPE for 403 run-limit reached", async () => {
    mockedAxios.post.mockRejectedValueOnce({ response: { status: 403, data: { error: "run limit reached" } } });
    const code = await runSitesScan("proj-123", opts);
    expect(code).toBe(EXIT_INSUFFICIENT_SCOPE);
  });
});

describe("sites list", () => {
  it("passes limit/offset/include_archived as query params", async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { sites: [], limit: 10, offset: 5, has_more: false } });
    const code = await runSitesList({ ...opts, limit: 10, offset: 5, includeArchived: true });
    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.get).toHaveBeenCalledWith(
      expect.stringContaining("/static/sites"),
      { params: { limit: "10", offset: "5", include_archived: "true" }, headers: { "x-api-key": "test-key" } }
    );
  });

  it("returns EXIT_GENERAL_ERROR for 401", async () => {
    mockedAxios.get.mockRejectedValueOnce({ response: { status: 401 } });
    const code = await runSitesList(opts);
    expect(code).toBe(EXIT_GENERAL_ERROR);
  });
});

describe("sites get", () => {
  it("returns EXIT_SUCCESS on success", async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { site: { id: "p1" }, latest_run: null, security: { critical: 0, warn: 0, info: 0, total: 0 } } });
    const code = await runSitesGet("p1", opts);
    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.get).toHaveBeenCalledWith(
      expect.stringContaining("/static/sites/p1"),
      { headers: { "x-api-key": "test-key" } }
    );
  });

  it("returns EXIT_SCAN_NOT_FOUND for 404 (not owned/not found)", async () => {
    mockedAxios.get.mockRejectedValueOnce({ response: { status: 404, data: { error: "not found" } } });
    const code = await runSitesGet("nonexistent", opts);
    expect(code).toBe(EXIT_SCAN_NOT_FOUND);
  });

  it("returns EXIT_QUOTA_EXHAUSTED for 429", async () => {
    mockedAxios.get.mockRejectedValueOnce({ response: { status: 429, data: { error: "Rate limit exceeded", retryAfter: 30 } } });
    const code = await runSitesGet("p1", opts);
    expect(code).toBe(EXIT_QUOTA_EXHAUSTED);
  });
});
