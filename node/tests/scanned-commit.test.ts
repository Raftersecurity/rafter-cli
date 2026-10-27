import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Tests for the "Scanned commit" info/warning line printed when a remote
 * scan finishes with a completed status (`rafter run`, `rafter get`, and
 * `rafter get --interactive`).
 *
 * Mocks axios (API) and ../src/utils/git.js (the HEAD lookup) so no network
 * calls or real git subprocess are needed — the module stub must stand in
 * for a real checkout, not just suppress the dependency.
 */

vi.mock("axios", () => {
  const instance: any = {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    patch: vi.fn(),
    defaults: { maxRedirects: 0 },
    interceptors: { response: { use: vi.fn() }, request: { use: vi.fn() } },
  };
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

const gitMock = vi.fn();
vi.mock("../src/utils/git.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/utils/git.js")>()),
  git: (cmd: string) => gitMock(cmd),
}));

import axios from "axios";
import { handleScanStatus } from "../src/commands/backend/scan-status.js";
import { createGetCommand } from "../src/commands/backend/get.js";
import { EXIT_SUCCESS } from "../src/utils/api.js";

const mockedAxios = vi.mocked((axios as any).create(), true);

// Fake 40-char SHAs, distinct from whatever this checkout's real HEAD is —
// if the git.js mock above were not actually intercepted, production code
// would call the real `git rev-parse HEAD` and these would not line up,
// turning the "matches HEAD" case red instead of green.
const LOCAL_HEAD = "a".repeat(40);
const SCANNED = "b".repeat(40);

describe("Scanned commit reporting", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const headers = { "x-api-key": "test-key" };

  it("prints the short scanned commit when it matches local HEAD, no warning", async () => {
    gitMock.mockReturnValue(LOCAL_HEAD);
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "completed", markdown: "# ok", scanned_commit: LOCAL_HEAD },
    });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const code = await handleScanStatus("s1", headers, "md");

    expect(code).toBe(EXIT_SUCCESS);
    const stderr = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(stderr).toContain(`Scanned commit: ${LOCAL_HEAD.slice(0, 12)}`);
    expect(stderr).not.toContain("Warning: the scan covers commit");
  });

  it("warns when the scanned commit differs from local HEAD", async () => {
    gitMock.mockReturnValue(LOCAL_HEAD);
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "completed", markdown: "# ok", scanned_commit: SCANNED },
    });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await handleScanStatus("s1", headers, "md");

    const stderr = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(stderr).toContain(`Scanned commit: ${SCANNED.slice(0, 12)}`);
    expect(stderr).toContain(
      `Warning: the scan covers commit ${SCANNED.slice(0, 12)}, but your checkout is at ${LOCAL_HEAD.slice(0, 12)}.`
    );
  });

  it("does not compare against a checkout of a different repository", async () => {
    gitMock.mockImplementation((cmd: string) =>
      cmd.startsWith("remote") ? "https://github.com/acme/other.git" : LOCAL_HEAD);
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "completed", markdown: "# ok", scanned_commit: SCANNED, repository_name: "acme/app" },
    });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await handleScanStatus("s1", headers, "md");

    const stderr = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(stderr).toContain(`Scanned commit: ${SCANNED.slice(0, 12)}`);
    expect(stderr).not.toContain("Warning:");
  });

  it('prints "not recorded" and skips the git lookup when scanned_commit is null', async () => {
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "completed", markdown: "# ok", scanned_commit: null },
    });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await handleScanStatus("s1", headers, "md");

    const stderr = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(stderr).toContain("Scanned commit: not recorded");
    expect(gitMock).not.toHaveBeenCalled();
  });

  it("--quiet hides the info line but still prints the mismatch warning", async () => {
    gitMock.mockReturnValue(LOCAL_HEAD);
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "completed", markdown: "# ok", scanned_commit: SCANNED },
    });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await handleScanStatus("s1", headers, "md", true);

    const stderr = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(stderr).not.toContain("Scanned commit:");
    expect(stderr).toContain(
      `Warning: the scan covers commit ${SCANNED.slice(0, 12)}, but your checkout is at ${LOCAL_HEAD.slice(0, 12)}.`
    );
  });

  it("stays silent about a mismatch when there is no checkout (git fails)", async () => {
    gitMock.mockImplementation(() => {
      throw new Error("not a git repository");
    });
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "completed", markdown: "# ok", scanned_commit: SCANNED },
    });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await handleScanStatus("s1", headers, "md");

    const stderr = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(stderr).toContain(`Scanned commit: ${SCANNED.slice(0, 12)}`);
    expect(stderr).not.toContain("Warning:");
  });

  // ── rafter get (plain, non-interactive) — the second call site ────────

  it("get (plain) prints the scanned-commit line for a completed scan", async () => {
    gitMock.mockReturnValue(LOCAL_HEAD);
    mockedAxios.get.mockResolvedValueOnce({
      data: { status: "completed", markdown: "# ok", scanned_commit: LOCAL_HEAD },
    });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    // A no-op mock (not a throw): the real action calls process.exit() as its
    // last statement in the try block, and a throwing mock would be caught by
    // the action's own catch and re-reported as a general error.
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => undefined) as any);

    await createGetCommand().parseAsync(["s1", "--api-key", "test-key", "--format", "md"], {
      from: "user",
    });

    expect(exitSpy).toHaveBeenCalledWith(EXIT_SUCCESS);
    const stderr = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(stderr).toContain(`Scanned commit: ${LOCAL_HEAD.slice(0, 12)}`);
  });
});
