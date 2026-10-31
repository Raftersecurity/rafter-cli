import { afterEach, expect, it, vi } from "vitest";
import { createGetCommand } from "../src/commands/backend/get.js";
import { describeHttpError, fetchScanWithRetry, PollGaveUpError } from "../src/commands/backend/scan-status.js";
import { setAgentMode } from "../src/utils/formatter.js";

// Network-facing functions are stubbed; describeHttpError is pure, so the real
// implementation is kept — it is the formatting under test.
vi.mock("../src/commands/backend/scan-status.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/commands/backend/scan-status.js")>();
  return {
    describeHttpError: actual.describeHttpError,
    fetchScanWithRetry: vi.fn(),
    handleScanStatus: vi.fn(),
    reportFailedScan: vi.fn(),
    warnIfPartial: vi.fn(),
    PollGaveUpError: class PollGaveUpError extends Error {},
  };
});

const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

afterEach(() => {
  setAgentMode(false);
  vi.restoreAllMocks();
});

/** Runs `get <scan_id>` with fetchScanWithRetry rejecting `thrown`; returns the exit code and stderr lines. */
async function runGetRejecting(thrown: unknown, scanId = "scan-123") {
  vi.mocked(fetchScanWithRetry).mockRejectedValueOnce(thrown);

  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});

  vi.spyOn(process, "exit").mockImplementation((code) => {
    throw new Error(`EXIT:${code}`);
  });

  let exitCode: number | undefined;
  try {
    await createGetCommand().parseAsync([scanId, "--api-key", "test-key"], { from: "user" });
  } catch (e) {
    const match = /^EXIT:(\d+)$/.exec((e as Error).message);
    if (!match) throw e;
    exitCode = Number(match[1]);
  }

  return { exitCode, lines: stderr.mock.calls.map(([line]) => String(line)) };
}

it("formats backend get 404 errors in agent mode", async () => {
  setAgentMode(true);

  vi.mocked(fetchScanWithRetry).mockRejectedValueOnce({
    response: { status: 404 },
  });

  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});

  vi.spyOn(process, "exit").mockImplementation((code) => {
    throw new Error(`EXIT:${code}`);
  });

  await expect(
    createGetCommand().parseAsync(
      ["missing-scan", "--api-key", "test-key"],
      { from: "user" },
    ),
  ).rejects.toThrow("EXIT:2");

  expect(stderr).toHaveBeenCalledWith(
    "[ERROR] Scan 'missing-scan' not found",
  );
});

it("formats backend get 404 errors in human mode", async () => {
  const { exitCode, lines } = await runGetRejecting({ response: { status: 404 } }, "missing-scan");

  expect(exitCode).toBe(2);
  expect(lines).toHaveLength(1);
  expect(stripAnsi(lines[0])).toBe("✗ Scan 'missing-scan' not found");
  expect(lines[0]).not.toContain("[ERROR]");
});

it("formats PollGaveUpError messages", async () => {
  setAgentMode(true);

  const { exitCode, lines } = await runGetRejecting(
    new PollGaveUpError("Gave up after 5 consecutive failures"),
  );

  expect(exitCode).toBe(1);
  expect(lines).toEqual(["[ERROR] Gave up after 5 consecutive failures"]);
});

it("formats string API response bodies with the HTTP status", async () => {
  setAgentMode(true);

  const { exitCode, lines } = await runGetRejecting({
    response: { status: 500, data: "Internal Server Error" },
  });

  expect(exitCode).toBe(1);
  expect(lines).toEqual(["[ERROR] HTTP 500 — Internal Server Error"]);
});

it("reports the error field of object API response bodies", async () => {
  setAgentMode(true);

  const { exitCode, lines } = await runGetRejecting({
    response: { status: 403, data: { error: "forbidden", detail: "key revoked" } },
  });

  expect(exitCode).toBe(1);
  expect(lines).toEqual(["[ERROR] HTTP 403 — forbidden"]);
});

it("serializes object API response bodies without an error field in human mode", async () => {
  const { exitCode, lines } = await runGetRejecting({
    response: { status: 403, data: { message: "key revoked" } },
  });

  expect(exitCode).toBe(1);
  expect(lines).toHaveLength(1);
  expect(stripAnsi(lines[0])).toBe('✗ HTTP 403 — {"message":"key revoked"}');
});

it("formats standard Error messages", async () => {
  setAgentMode(true);

  const { exitCode, lines } = await runGetRejecting(new Error("connect ECONNREFUSED 127.0.0.1:443"));

  expect(exitCode).toBe(1);
  expect(lines).toEqual(["[ERROR] connect ECONNREFUSED 127.0.0.1:443"]);
});

it("formats unknown thrown values", async () => {
  setAgentMode(true);

  const { exitCode, lines } = await runGetRejecting("socket hang up");

  expect(exitCode).toBe(1);
  expect(lines).toEqual(["[ERROR] socket hang up"]);
});

it("preserves details of plain-object thrown values", async () => {
  setAgentMode(true);

  const { exitCode, lines } = await runGetRejecting({ code: "EPROTO", reason: "bad handshake" });

  expect(exitCode).toBe(1);
  expect(lines).toEqual(['[ERROR] {"code":"EPROTO","reason":"bad handshake"}']);
});

it("survives circular API response bodies", async () => {
  setAgentMode(true);

  // No `error` field, so the whole (circular) body is what gets serialized.
  const body: Record<string, unknown> = { message: "upstream loop" };
  body.self = body;

  const { exitCode, lines } = await runGetRejecting({ response: { status: 502, data: body } });

  expect(exitCode).toBe(1);
  expect(lines).toHaveLength(1);
  expect(lines[0]).toMatch(/^\[ERROR\] HTTP 502 — /);
  expect(lines[0]).toContain("upstream loop");
  expect(lines[0]).toContain("[Circular");
  expect(lines[0]).not.toContain("[object Object]");
});

it("describeHttpError renders BigInt response bodies instead of throwing", () => {
  const text = describeHttpError({ response: { status: 500, data: { quota: 10n } } });

  expect(text).toMatch(/^HTTP 500 — /);
  expect(text).toContain("10n");
});
