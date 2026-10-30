import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Every side effect runRemoteScan can reach is stubbed: axios (no network),
// git (no repository reads), and ora (spinner calls are recorded, not drawn).
const spinner = vi.hoisted(() => ({
  start: vi.fn().mockReturnThis(),
  succeed: vi.fn().mockReturnThis(),
  fail: vi.fn().mockReturnThis(),
  stop: vi.fn().mockReturnThis(),
}));

vi.mock("ora", () => ({ default: () => spinner }));

vi.mock("axios", () => {
  const instance: any = {
    get: vi.fn(),
    post: vi.fn(),
    defaults: { maxRedirects: 0 },
    interceptors: { response: { use: vi.fn() }, request: { use: vi.fn() } },
  };
  return { default: { create: () => instance } };
});

vi.mock("../src/utils/git.js", () => ({
  detectRepo: vi.fn(() => ({ repo: "owner/repo", branch: "main" })),
  git: vi.fn(),
  remoteBranchSha: vi.fn(),
}));

import { runRemoteScan, type RunOpts } from "../src/commands/backend/run.js";
import { apiClient, EXIT_GENERAL_ERROR, EXIT_QUOTA_EXHAUSTED } from "../src/utils/api.js";
import { detectRepo, remoteBranchSha } from "../src/utils/git.js";
import { setAgentMode } from "../src/utils/formatter.js";

const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

const SPINNER = { quiet: false };
const QUIET = { quiet: true };

beforeEach(() => {
  vi.clearAllMocks();
  // A RAFTER_API_URL override makes apiUrl() print its own stderr warning.
  vi.stubEnv("RAFTER_API_URL", "");
});

afterEach(() => {
  setAgentMode(false);
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

/** Runs a fast scan for owner/repo@main; returns the exit code and stderr lines. */
async function runScan(opts: Partial<RunOpts>) {
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});

  vi.spyOn(process, "exit").mockImplementation((code) => {
    throw new Error(`EXIT:${code}`);
  });

  let exitCode: number | undefined;
  try {
    await runRemoteScan({ apiKey: "test-key", mode: "fast", skipInteractive: true, ...opts });
  } catch (e) {
    const match = /^EXIT:(\d+)$/.exec((e as Error).message);
    if (!match) throw e;
    exitCode = Number(match[1]);
  }

  return { exitCode, lines: stderr.mock.calls.map(([line]) => String(line)) };
}

describe.each([
  ["spinner", SPINNER],
  ["quiet", QUIET],
])("API errors (%s branch)", (_name, mode) => {
  it("formats structured API errors with status and detail", async () => {
    setAgentMode(true);
    vi.mocked(apiClient.post).mockRejectedValueOnce({
      response: { status: 500, data: { error: "scan backend unavailable" } },
    });

    const { exitCode, lines } = await runScan(mode);

    expect(exitCode).toBe(EXIT_GENERAL_ERROR);
    expect(lines).toEqual(["[ERROR] HTTP 500 — scan backend unavailable"]);
    expect(spinner.fail).toHaveBeenCalledTimes(mode.quiet ? 0 : 1);
  });
});

it("formats structured API errors in human mode", async () => {
  vi.mocked(apiClient.post).mockRejectedValueOnce({
    response: { status: 500, data: { error: "scan backend unavailable" } },
  });

  const { exitCode, lines } = await runScan(QUIET);

  expect(exitCode).toBe(EXIT_GENERAL_ERROR);
  expect(lines).toHaveLength(1);
  expect(stripAnsi(lines[0])).toBe("✗ HTTP 500 — scan backend unavailable");
});

it("reports quota exhaustion with exit 3 in the spinner branch", async () => {
  setAgentMode(true);
  vi.mocked(apiClient.post).mockRejectedValueOnce({ response: { status: 429, data: {} } });

  const { exitCode, lines } = await runScan(SPINNER);

  expect(exitCode).toBe(EXIT_QUOTA_EXHAUSTED);
  expect(lines).toEqual(["[ERROR] Quota exhausted"]);
  expect(spinner.fail).toHaveBeenCalledWith("Request failed");
});

it("stays silent on quota exhaustion in the quiet branch, still exiting 3", async () => {
  setAgentMode(true);
  vi.mocked(apiClient.post).mockRejectedValueOnce({ response: { status: 429, data: {} } });

  const { exitCode, lines } = await runScan(QUIET);

  expect(exitCode).toBe(EXIT_QUOTA_EXHAUSTED);
  expect(lines).toEqual([]);
});

it("formats repository detection errors without calling the API", async () => {
  setAgentMode(true);
  vi.mocked(detectRepo).mockImplementationOnce(() => {
    throw new Error("Could not auto-detect Git repository. Please pass --repo and --branch explicitly.");
  });

  const { exitCode, lines } = await runScan(QUIET);

  expect(exitCode).toBe(EXIT_GENERAL_ERROR);
  expect(lines).toEqual([
    "[ERROR] Could not auto-detect Git repository. Please pass --repo and --branch explicitly.",
  ]);
  expect(apiClient.post).not.toHaveBeenCalled();
});

it("formats an unpushed auto-detected branch without calling the API", async () => {
  setAgentMode(true);
  vi.mocked(detectRepo).mockReturnValueOnce({ repo: "owner/repo", branch: "feature", local_branch: true });
  vi.mocked(remoteBranchSha).mockReturnValueOnce(null);

  const { exitCode, lines } = await runScan(QUIET);

  expect(exitCode).toBe(EXIT_GENERAL_ERROR);
  expect(lines).toHaveLength(1);
  expect(lines[0]).toMatch(/^\[ERROR\] Branch "feature" does not exist on the remote \(origin\)\./);
  expect(apiClient.post).not.toHaveBeenCalled();
});
