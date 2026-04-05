import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Tests for rafter scan remote / rafter run — the remote backend scan flow.
 *
 * Covers:
 * - runRemoteScan: success, error handling, skip-interactive, quiet mode
 * - handleScanStatus: immediate completion, polling, 404, failure
 *
 * All tests mock axios so no network calls are made.
 */

// ── Mocks ──────────────────────────────────────────────────────────────

vi.mock("axios");
vi.mock("ora", () => ({
  default: () => ({
    start: vi.fn().mockReturnThis(),
    succeed: vi.fn().mockReturnThis(),
    fail: vi.fn().mockReturnThis(),
    stop: vi.fn().mockReturnThis(),
  }),
}));

import axios from "axios";
import { handleScanStatus } from "../src/commands/backend/scan-status.js";
import { EXIT_SUCCESS, EXIT_GENERAL_ERROR, EXIT_SCAN_NOT_FOUND } from "../src/utils/api.js";

const mockedAxios = vi.mocked(axios, true);

// ── handleScanStatus ───────────────────────────────────────────────────

describe("handleScanStatus", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const headers = { "x-api-key": "test-key" };

  it("returns success when scan is already completed", async () => {
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "completed", markdown: "# Clean", scan_id: "s1" },
    });

    const code = await handleScanStatus("s1", headers, "md");
    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.get).toHaveBeenCalledTimes(1);
  });

  it("outputs markdown payload for completed scan", async () => {
    const stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "completed", markdown: "# Results\nNo issues found" },
    });

    await handleScanStatus("s1", headers, "md");
    expect(stdoutSpy).toHaveBeenCalledWith("# Results\nNo issues found");
  });

  it("outputs JSON payload when format is json", async () => {
    const stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const responseData = { status: "completed", findings: [] };
    mockedAxios.get.mockResolvedValueOnce({ data: responseData });

    await handleScanStatus("s1", headers, "json");
    const output = stdoutSpy.mock.calls[0][0] as string;
    expect(JSON.parse(output)).toEqual(responseData);
  });

  it("returns EXIT_SCAN_NOT_FOUND for 404", async () => {
    mockedAxios.get.mockRejectedValueOnce({
      response: { status: 404 },
    });

    const code = await handleScanStatus("nonexistent", headers, "md");
    expect(code).toBe(EXIT_SCAN_NOT_FOUND);
  });

  it("returns EXIT_GENERAL_ERROR for failed scan", async () => {
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "failed", scan_id: "s1" },
    });

    const code = await handleScanStatus("s1", headers, "md");
    expect(code).toBe(EXIT_GENERAL_ERROR);
  });

  it("returns EXIT_GENERAL_ERROR for non-404 network error", async () => {
    mockedAxios.get.mockRejectedValueOnce({
      response: { status: 500, data: "Internal server error" },
      message: "Request failed",
    });

    const code = await handleScanStatus("s1", headers, "md");
    expect(code).toBe(EXIT_GENERAL_ERROR);
  });

  it("polls when status is queued, then returns on completed", async () => {
    // First call: queued, second call: completed
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "queued" } })
      .mockResolvedValueOnce({
        data: { status: "completed", markdown: "# Done" },
      });

    // Speed up polling by mocking setTimeout
    vi.useFakeTimers();
    const promise = handleScanStatus("s1", headers, "md");
    await vi.advanceTimersByTimeAsync(10000);
    const code = await promise;
    vi.useRealTimers();

    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.get).toHaveBeenCalledTimes(2);
  });

  it("polls when status is processing, then returns on failed", async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockResolvedValueOnce({ data: { status: "failed" } });

    vi.useFakeTimers();
    const promise = handleScanStatus("s1", headers, "md");
    await vi.advanceTimersByTimeAsync(10000);
    const code = await promise;
    vi.useRealTimers();

    expect(code).toBe(EXIT_GENERAL_ERROR);
  });

  it("polls when status is pending", async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "pending" } })
      .mockResolvedValueOnce({
        data: { status: "completed", markdown: "ok" },
      });

    vi.useFakeTimers();
    const promise = handleScanStatus("s1", headers, "md");
    await vi.advanceTimersByTimeAsync(10000);
    const code = await promise;
    vi.useRealTimers();

    expect(code).toBe(EXIT_SUCCESS);
  });

  it("suppresses spinner in quiet mode", async () => {
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "completed", markdown: "# Done" },
    });

    const stderrSpy = vi.spyOn(console, "error");
    await handleScanStatus("s1", headers, "md", true);

    // In quiet mode, "Scan completed" should not be printed
    const stderrCalls = stderrSpy.mock.calls.map((c) => c[0]);
    expect(stderrCalls).not.toContain("Scan completed");
  });

  it("passes format param to API", async () => {
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "completed", findings: [] },
    });

    await handleScanStatus("s1", headers, "json");
    expect(mockedAxios.get).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        params: { scan_id: "s1", format: "json" },
      })
    );
  });
});

// ── runRemoteScan (mocked) ─────────────────────────────────────────────

describe("runRemoteScan", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
      throw new Error("process.exit");
    }) as any);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // We need to import dynamically to apply mocks on detectRepo
  it("posts to /static/scan with correct body", async () => {
    // Mock detectRepo
    vi.doMock("../../src/utils/git.js", () => ({
      detectRepo: () => ({ repo: "owner/repo", branch: "main" }),
    }));

    mockedAxios.post.mockResolvedValueOnce({
      data: { scan_id: "scan-abc" },
    });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await runRemoteScan({
      apiKey: "test-key",
      repo: "owner/repo",
      branch: "main",
      mode: "fast",
      skipInteractive: true,
      quiet: true,
    });

    expect(mockedAxios.post).toHaveBeenCalledWith(
      expect.stringContaining("/static/scan"),
      expect.objectContaining({
        repository_name: "owner/repo",
        branch_name: "main",
        scan_mode: "fast",
      }),
      expect.objectContaining({
        headers: { "x-api-key": "test-key" },
      })
    );
  });

  it("includes github_token in body when provided", async () => {
    mockedAxios.post.mockResolvedValueOnce({
      data: { scan_id: "scan-abc" },
    });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await runRemoteScan({
      apiKey: "test-key",
      repo: "owner/repo",
      branch: "main",
      skipInteractive: true,
      quiet: true,
      githubToken: "ghp_test123",
    });

    expect(mockedAxios.post).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        github_token: "ghp_test123",
      }),
      expect.any(Object)
    );
  });

  it("defaults scan_mode to fast", async () => {
    mockedAxios.post.mockResolvedValueOnce({
      data: { scan_id: "scan-abc" },
    });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await runRemoteScan({
      apiKey: "test-key",
      repo: "owner/repo",
      branch: "main",
      skipInteractive: true,
      quiet: true,
    });

    expect(mockedAxios.post).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ scan_mode: "fast" }),
      expect.any(Object)
    );
  });

  it("uses plus scan_mode when specified", async () => {
    mockedAxios.post.mockResolvedValueOnce({
      data: { scan_id: "scan-abc" },
    });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await runRemoteScan({
      apiKey: "test-key",
      repo: "owner/repo",
      branch: "main",
      mode: "plus",
      skipInteractive: true,
      quiet: true,
    });

    expect(mockedAxios.post).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ scan_mode: "plus" }),
      expect.any(Object)
    );
  });

  it("returns early when skipInteractive is true", async () => {
    mockedAxios.post.mockResolvedValueOnce({
      data: { scan_id: "scan-abc" },
    });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await runRemoteScan({
      apiKey: "test-key",
      repo: "owner/repo",
      branch: "main",
      skipInteractive: true,
      quiet: true,
    });

    // Should NOT call get (no polling)
    expect(mockedAxios.get).not.toHaveBeenCalled();
  });

  it("exits with EXIT_QUOTA_EXHAUSTED on 429", async () => {
    mockedAxios.post.mockRejectedValueOnce({
      response: { status: 429, data: "quota exhausted" },
    });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await expect(
      runRemoteScan({
        apiKey: "test-key",
        repo: "owner/repo",
        branch: "main",
        skipInteractive: true,
        quiet: true,
      })
    ).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(3); // EXIT_QUOTA_EXHAUSTED
  });

  it("exits with EXIT_INSUFFICIENT_SCOPE on 403 with scope keyword", async () => {
    mockedAxios.post.mockRejectedValueOnce({
      response: {
        status: 403,
        data: { error: "Required scope: read-and-scan." },
      },
    });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await expect(
      runRemoteScan({
        apiKey: "test-key",
        repo: "owner/repo",
        branch: "main",
        skipInteractive: true,
        quiet: true,
      })
    ).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(4); // EXIT_INSUFFICIENT_SCOPE
  });

  it("exits with EXIT_QUOTA_EXHAUSTED on 403 with scan_mode body", async () => {
    mockedAxios.post.mockRejectedValueOnce({
      response: {
        status: 403,
        data: { scan_mode: "plus", limit: 5, used: 5 },
      },
    });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await expect(
      runRemoteScan({
        apiKey: "test-key",
        repo: "owner/repo",
        branch: "main",
        skipInteractive: true,
        quiet: true,
      })
    ).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(3); // EXIT_QUOTA_EXHAUSTED
  });

  it("exits with EXIT_GENERAL_ERROR on non-403/429 error", async () => {
    mockedAxios.post.mockRejectedValueOnce({
      response: { status: 500, data: "internal error" },
    });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await expect(
      runRemoteScan({
        apiKey: "test-key",
        repo: "owner/repo",
        branch: "main",
        skipInteractive: true,
        quiet: true,
      })
    ).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(1); // EXIT_GENERAL_ERROR
  });

  it("exits with EXIT_GENERAL_ERROR when detectRepo fails", async () => {
    // Force detectRepo to throw
    vi.doMock("../../src/utils/git.js", () => ({
      detectRepo: () => {
        throw new Error("Could not auto-detect Git repository.");
      },
    }));

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await expect(
      runRemoteScan({
        apiKey: "test-key",
        skipInteractive: true,
        quiet: true,
      })
    ).rejects.toThrow("process.exit");

    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});

// ── Live API integration tests ──────────────────────────────────────────

const API_KEY = process.env.RAFTER_API_KEY;
const describeWithKey = API_KEY ? describe : describe.skip;

describeWithKey("scan remote — live API integration", () => {
  it("triggers a scan and polls for status", async () => {
    mockedAxios.post.mockRestore?.();
    mockedAxios.get.mockRestore?.();

    // Use real axios for live tests
    const realAxios = await vi.importActual<typeof import("axios")>("axios");
    const { default: ax } = realAxios;

    const { data } = await ax.post(
      "https://rafter.so/api/static/scan",
      {
        repository_name: "raftersecurity/rafter-cli",
        branch_name: "main",
        scan_mode: "fast",
      },
      { headers: { "x-api-key": API_KEY! } }
    );

    expect(data.scan_id).toBeDefined();
    expect(typeof data.scan_id).toBe("string");

    // Check status (don't wait for completion)
    const status = await ax.get("https://rafter.so/api/static/scan", {
      params: { scan_id: data.scan_id, format: "json" },
      headers: { "x-api-key": API_KEY! },
    });

    expect(["queued", "pending", "processing", "completed", "failed"]).toContain(
      status.data.status
    );
  }, 30000);
});
