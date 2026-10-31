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

vi.mock("axios", () => {
  // sable-2s6p — the code calls `apiClient`, an axios instance created with
  // maxRedirects: 0. `create` must return something, and it returns the same
  // object as the default export so `mockedAxios.get` still refers to the
  // function under test.
  const instance: any = {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    patch: vi.fn(),
    defaults: { maxRedirects: 0 },
    interceptors: { response: { use: vi.fn() }, request: { use: vi.fn() } },
  };
    // The default export gets its OWN mocks, distinct from the instance's. If
  // production code regresses to bare `axios.get`, the assertions below — which
  // watch the instance — stop seeing calls, and the test fails. A shim where
  // both are the same object would silently accept that regression.
  const bare: any = {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    patch: vi.fn(),
    interceptors: { response: { use: vi.fn() }, request: { use: vi.fn() } },
    create: () => instance,
  };
  return { default: bare };
});
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
import { EXIT_SUCCESS, EXIT_GENERAL_ERROR } from "../src/utils/api.js";

// The code calls `apiClient` — the instance `create()` returns.
const mockedAxios = vi.mocked((axios as any).create(), true);

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

  it("returns EXIT_GENERAL_ERROR for failed scan", async () => {
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "failed", scan_id: "s1" },
    });

    const code = await handleScanStatus("s1", headers, "md");
    expect(code).toBe(EXIT_GENERAL_ERROR);
  });

  // sable-l10k changed this: a 500 on the first poll is now RETRIED, because
  // the give-up message tells the user to run `rafter get <id>`, which
  // re-enters here. A non-transient status is what still fails immediately.
  // The retry/exhaustion paths are covered in scan-poll-transient-500.test.ts.
  it("returns EXIT_GENERAL_ERROR for a non-transient error", async () => {
    mockedAxios.get.mockRejectedValueOnce({
      response: { status: 403, data: "Forbidden" },
      message: "Request failed",
    });

    const code = await handleScanStatus("s1", headers, "md");
    expect(code).toBe(EXIT_GENERAL_ERROR);
    expect(mockedAxios.get).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["queued", { status: "completed", markdown: "# Done" }, EXIT_SUCCESS],
    ["processing", { status: "failed" }, EXIT_GENERAL_ERROR],
    ["pending", { status: "completed", markdown: "ok" }, EXIT_SUCCESS],
  ] as const)(
    "polls when status is %s, then returns on the terminal state",
    async (inProgressStatus, terminalData, expectedCode) => {
      mockedAxios.get
        .mockResolvedValueOnce({ data: { status: inProgressStatus } })
        .mockResolvedValueOnce({ data: terminalData });

      vi.useFakeTimers();
      const promise = handleScanStatus("s1", headers, "md");
      await vi.advanceTimersByTimeAsync(10000);
      const code = await promise;
      vi.useRealTimers();

      expect(code).toBe(expectedCode);
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
    }
  );

  it("says why a scan failed and hands the payload to JSON consumers", async () => {
    const failed = {
      status: "failed",
      error_code: "SCAN_STALLED",
      error: "The scan stopped sending progress updates. Please re-run the scan.",
      retryable: true,
    };
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockResolvedValueOnce({ data: failed });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const outSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    vi.useFakeTimers();
    const promise = handleScanStatus("s1", headers, "json");
    await vi.advanceTimersByTimeAsync(10000);
    const code = await promise;
    vi.useRealTimers();

    expect(code).toBe(EXIT_GENERAL_ERROR);
    const stderr = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(stderr).toContain("SCAN_STALLED");
    expect(stderr).toContain("stopped sending progress updates");
    expect(stderr).toContain("rafter run");
    expect(JSON.parse(String(outSpy.mock.calls[0][0])).error_code).toBe("SCAN_STALLED");
  });

  it("warns that a completed scan is partial, even with --quiet", async () => {
    const partial = {
      status: "completed", partial: true, warning_code: "SCAN_PARTIAL",
      missing_scanners: ["opengrep_rafter"], vulnerabilities: [],
    };
    mockedAxios.get.mockResolvedValueOnce({ data: partial });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const outSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    const code = await handleScanStatus("s1", headers, "json", true);

    expect(code).toBe(EXIT_SUCCESS);
    const stderr = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(stderr).toContain("SCAN_PARTIAL");
    expect(stderr).toContain("opengrep_rafter");
    expect(JSON.parse(String(outSpy.mock.calls[0][0])).partial).toBe(true);
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

  it("still exits with EXIT_QUOTA_EXHAUSTED on a 429 that carries Retry-After", async () => {
    // sable-96ex — the poll loop now retries a 429 when the server says when to
    // come back. SUBMIT deliberately does not: a 429 here means the account is
    // out of credits, and no amount of waiting changes that. The asymmetry is
    // the point, so it is pinned rather than left to be "made consistent".
    mockedAxios.post.mockRejectedValueOnce({
      response: {
        status: 429,
        data: "quota exhausted",
        headers: { "retry-after": "30" },
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
    expect(mockedAxios.get).not.toHaveBeenCalled(); // no polling, no retry
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

  // ── provider / repo_url (multi-provider, additive + backward-compatible) ──

  async function postedBody(): Promise<Record<string, unknown>> {
    // The 2nd positional arg of the last axios.post call is the request body.
    const call = mockedAxios.post.mock.calls[mockedAxios.post.mock.calls.length - 1];
    return call[1] as Record<string, unknown>;
  }

  it("a github remote produces a body with NO provider/repo_url (byte-identical to today)", async () => {
    mockedAxios.post.mockResolvedValueOnce({ data: { scan_id: "scan-abc" } });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await runRemoteScan({
      apiKey: "test-key",
      repo: "owner/repo",
      branch: "main",
      mode: "fast",
      skipInteractive: true,
      quiet: true,
    });

    const body = await postedBody();
    // Byte-identical shape: exactly these keys, nothing more.
    expect(body).toEqual({
      repository_name: "owner/repo",
      branch_name: "main",
      scan_mode: "fast",
    });
    expect(body).not.toHaveProperty("provider");
    expect(body).not.toHaveProperty("repo_url");

    const call = mockedAxios.post.mock.calls[mockedAxios.post.mock.calls.length - 1];
    expect(call[0]).toContain("/static/scan");
    expect(call[2]).toMatchObject({ headers: { "x-api-key": "test-key" } });
  });

  it("an explicit --provider github still omits provider/repo_url", async () => {
    mockedAxios.post.mockResolvedValueOnce({ data: { scan_id: "scan-abc" } });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await runRemoteScan({
      apiKey: "test-key",
      repo: "owner/repo",
      branch: "main",
      mode: "fast",
      skipInteractive: true,
      quiet: true,
      provider: "github",
      repoUrl: "https://github.com/owner/repo",
    });

    const body = await postedBody();
    expect(body).not.toHaveProperty("provider");
    expect(body).not.toHaveProperty("repo_url");
  });

  it.each([
    {
      provider: "gitlab",
      repo: "group/project",
      repoUrl: "https://gitlab.com/group/project",
      mode: "fast" as const,
    },
    {
      provider: "bitbucket",
      repo: "team/repo",
      repoUrl: "https://bitbucket.org/team/repo",
      mode: undefined,
    },
  ])(
    "sends $provider provider + repo_url when flags are supplied",
    async ({ provider, repo, repoUrl, mode }) => {
      mockedAxios.post.mockResolvedValueOnce({ data: { scan_id: "scan-abc" } });

      const { runRemoteScan } = await import("../src/commands/backend/run.js");
      await runRemoteScan({
        apiKey: "test-key",
        repo,
        branch: "main",
        ...(mode ? { mode } : {}),
        skipInteractive: true,
        quiet: true,
        provider,
        repoUrl,
      });

      const body = await postedBody();
      expect(body.provider).toBe(provider);
      expect(body.repo_url).toBe(repoUrl);
      if (mode) {
        expect(body).toMatchObject({
          repository_name: repo,
          branch_name: "main",
          scan_mode: mode,
        });
      }
    }
  );

  it("omits provider/repo_url when a provider is given without a repo_url", async () => {
    mockedAxios.post.mockResolvedValueOnce({ data: { scan_id: "scan-abc" } });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await runRemoteScan({
      apiKey: "test-key",
      repo: "group/project",
      branch: "main",
      skipInteractive: true,
      quiet: true,
      provider: "gitlab",
      // no repoUrl → cannot send the pair; stay backward-compatible
    });

    const body = await postedBody();
    expect(body).not.toHaveProperty("provider");
    expect(body).not.toHaveProperty("repo_url");
  });
});

// ── detectRepo-inferred provider flows into the body ────────────────────

describe("runRemoteScan — inferred provider from detectRepo", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    vi.spyOn(process, "exit").mockImplementation((() => {
      throw new Error("process.exit");
    }) as any);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock("../src/utils/git.js");
    vi.resetModules();
  });

  it("includes an inferred gitlab provider + repo_url with no explicit flags", async () => {
    vi.resetModules();
    vi.doMock("../src/utils/git.js", () => ({
      detectRepo: () => ({
        repo: "group/project",
        branch: "main",
        provider: "gitlab",
        repo_url: "https://gitlab.com/group/project",
      }),
    }));

    mockedAxios.post.mockResolvedValueOnce({ data: { scan_id: "scan-abc" } });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await runRemoteScan({
      apiKey: "test-key",
      mode: "fast",
      skipInteractive: true,
      quiet: true,
    });

    const call = mockedAxios.post.mock.calls[mockedAxios.post.mock.calls.length - 1];
    const body = call[1] as Record<string, unknown>;
    expect(body).toMatchObject({
      repository_name: "group/project",
      branch_name: "main",
      provider: "gitlab",
      repo_url: "https://gitlab.com/group/project",
    });
  });

  it("omits provider/repo_url when detectRepo infers github", async () => {
    vi.resetModules();
    vi.doMock("../src/utils/git.js", () => ({
      detectRepo: () => ({
        repo: "owner/repo",
        branch: "main",
        provider: "github",
        repo_url: "https://github.com/owner/repo",
      }),
    }));

    mockedAxios.post.mockResolvedValueOnce({ data: { scan_id: "scan-abc" } });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await runRemoteScan({
      apiKey: "test-key",
      mode: "fast",
      skipInteractive: true,
      quiet: true,
    });

    const call = mockedAxios.post.mock.calls[mockedAxios.post.mock.calls.length - 1];
    const body = call[1] as Record<string, unknown>;
    expect(body).not.toHaveProperty("provider");
    expect(body).not.toHaveProperty("repo_url");
  });

  it("an explicit --provider flag overrides the inferred provider", async () => {
    vi.resetModules();
    vi.doMock("../src/utils/git.js", () => ({
      detectRepo: () => ({
        repo: "group/project",
        branch: "main",
        provider: "gitlab",
        repo_url: "https://gitlab.com/group/project",
      }),
    }));

    mockedAxios.post.mockResolvedValueOnce({ data: { scan_id: "scan-abc" } });

    const { runRemoteScan } = await import("../src/commands/backend/run.js");
    await runRemoteScan({
      apiKey: "test-key",
      skipInteractive: true,
      quiet: true,
      provider: "bitbucket",
      repoUrl: "https://bitbucket.org/group/project",
    });

    const call = mockedAxios.post.mock.calls[mockedAxios.post.mock.calls.length - 1];
    const body = call[1] as Record<string, unknown>;
    expect(body.provider).toBe("bitbucket");
    expect(body.repo_url).toBe("https://bitbucket.org/group/project");
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
