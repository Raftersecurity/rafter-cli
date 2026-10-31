import { afterEach, beforeEach, expect, it, vi } from "vitest";

// The code calls `apiClient`, the instance axios.create() returns; mocking
// axios keeps every request in-process, so no backend or real key is involved.
vi.mock("axios", () => {
  const instance: any = {
    get: vi.fn(),
    post: vi.fn(),
    defaults: { maxRedirects: 0 },
    interceptors: { response: { use: vi.fn() }, request: { use: vi.fn() } },
  };
  return { default: { create: () => instance } };
});

import { createUsageCommand } from "../src/commands/backend/usage.js";
import { apiClient } from "../src/utils/api.js";
import { setAgentMode } from "../src/utils/formatter.js";

const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

beforeEach(() => {
  // A RAFTER_API_URL override makes apiUrl() print its own stderr warning.
  vi.stubEnv("RAFTER_API_URL", "");
});

afterEach(() => {
  setAgentMode(false);
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

/** Runs `usage` with apiClient.get rejecting `thrown`; returns the exit code and stderr lines. */
async function runUsageRejecting(thrown: unknown) {
  vi.mocked(apiClient.get).mockRejectedValueOnce(thrown);

  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});

  vi.spyOn(process, "exit").mockImplementation((code) => {
    throw new Error(`EXIT:${code}`);
  });

  let exitCode: number | undefined;
  try {
    await createUsageCommand().parseAsync(["--api-key", "test-key"], { from: "user" });
  } catch (e) {
    const match = /^EXIT:(\d+)$/.exec((e as Error).message);
    if (!match) throw e;
    exitCode = Number(match[1]);
  }

  return { exitCode, lines: stderr.mock.calls.map(([line]) => String(line)) };
}

it("formats structured HTTP error responses with status and detail", async () => {
  setAgentMode(true);

  const { exitCode, lines } = await runUsageRejecting({
    response: { status: 401, data: { error: "invalid api key" } },
  });

  expect(exitCode).toBe(1);
  expect(lines).toEqual(["[ERROR] HTTP 401 — invalid api key"]);
});

it("formats structured HTTP error responses in human mode", async () => {
  const { exitCode, lines } = await runUsageRejecting({
    response: { status: 401, data: { error: "invalid api key" } },
  });

  expect(exitCode).toBe(1);
  expect(lines).toHaveLength(1);
  expect(stripAnsi(lines[0])).toBe("✗ HTTP 401 — invalid api key");
});

it("formats network errors", async () => {
  setAgentMode(true);

  const { exitCode, lines } = await runUsageRejecting(
    Object.assign(new Error("getaddrinfo ENOTFOUND rafter.so"), { code: "ENOTFOUND" }),
  );

  expect(exitCode).toBe(1);
  expect(lines).toEqual(["[ERROR] getaddrinfo ENOTFOUND rafter.so"]);
});

it("preserves details of unexpected plain-object throws", async () => {
  setAgentMode(true);

  const { exitCode, lines } = await runUsageRejecting({ code: "EPROTO", reason: "bad handshake" });

  expect(exitCode).toBe(1);
  expect(lines).toEqual(['[ERROR] {"code":"EPROTO","reason":"bad handshake"}']);
});

it("prints successful usage data unchanged to stdout", async () => {
  const data = { used: 3, limit: 10 };
  vi.mocked(apiClient.get).mockResolvedValueOnce({ data });
  const stdout = vi.spyOn(console, "log").mockImplementation(() => {});
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});

  await createUsageCommand().parseAsync(["--api-key", "test-key"], { from: "user" });

  expect(stdout).toHaveBeenCalledWith(JSON.stringify(data, null, 2));
  expect(stderr).not.toHaveBeenCalled();
});
