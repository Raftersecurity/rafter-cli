import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * sable-l10k — a paying customer's GitHub Actions run died on
 *   "Rafter scan poll failed: HTTP 500 — Failed to fetch report from storage: Object not found"
 *
 * A report is not durable the instant a scan flips to completed, so a poll can
 * hit a 5xx on a scan that is perfectly healthy seconds later. These tests pin
 * the contract: transient read failures are retried, genuinely-missing reports
 * still fail, and the failure message is one a customer can act on.
 */

vi.mock("axios");
vi.mock("ora", () => ({
  default: () => ({
    start: vi.fn().mockReturnThis(),
    succeed: vi.fn().mockReturnThis(),
    fail: vi.fn().mockReturnThis(),
    stop: vi.fn().mockReturnThis(),
    text: "",
  }),
}));

import axios from "axios";
import {
  handleScanStatus,
  unreadableReportMessage,
  MAX_TRANSIENT_POLL_FAILURES,
} from "../src/commands/backend/scan-status.js";
import { EXIT_SUCCESS, EXIT_GENERAL_ERROR, EXIT_SCAN_NOT_FOUND } from "../src/utils/api.js";

const mockedAxios = vi.mocked(axios, true);

/** The verbatim body the customer saw. */
const OBJECT_NOT_FOUND = {
  response: { status: 500, data: { error: "Failed to fetch report from storage: Object not found" } },
};

function httpError(status: number, error?: string) {
  return { response: { status, data: error ? { error } : undefined } };
}

describe("handleScanStatus — transient poll failures (sable-l10k)", () => {
  const headers = { "x-api-key": "test-key" };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    // Belt and braces: every test restores real timers itself (see above), but
    // a failing assertion can skip that line.
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("rides out a single 500 mid-poll and completes", async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(OBJECT_NOT_FOUND)
      .mockResolvedValueOnce({ data: { status: "completed", markdown: "# Done" } });

    vi.useFakeTimers();
    const promise = handleScanStatus("s1", headers, "md");
    await vi.advanceTimersByTimeAsync(10000); // poll interval
    await vi.advanceTimersByTimeAsync(2000); // first backoff
    const code = await promise;
    vi.useRealTimers();

    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.get).toHaveBeenCalledTimes(3);
  });

  it("rides out several consecutive 500s, backing off between them", async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(OBJECT_NOT_FOUND)
      .mockRejectedValueOnce(OBJECT_NOT_FOUND)
      .mockRejectedValueOnce(OBJECT_NOT_FOUND)
      .mockResolvedValueOnce({ data: { status: "completed", markdown: "# Done" } });

    vi.useFakeTimers();
    const promise = handleScanStatus("s1", headers, "md");
    await vi.advanceTimersByTimeAsync(10000);
    await vi.advanceTimersByTimeAsync(2000 + 4000 + 8000); // 3 backoffs
    const code = await promise;
    vi.useRealTimers();

    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.get).toHaveBeenCalledTimes(5);
  });

  it("treats a mid-poll 404 as read-after-write lag, not a missing scan", async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(httpError(404))
      .mockResolvedValueOnce({ data: { status: "completed", markdown: "# Done" } });

    vi.useFakeTimers();
    const promise = handleScanStatus("s1", headers, "md");
    await vi.advanceTimersByTimeAsync(10000);
    await vi.advanceTimersByTimeAsync(2000);
    const code = await promise;
    vi.useRealTimers();

    expect(code).toBe(EXIT_SUCCESS);
  });

  it("still reports 'not found' when the FIRST poll 404s", async () => {
    mockedAxios.get.mockRejectedValueOnce(httpError(404));

    const code = await handleScanStatus("nope", headers, "md");

    expect(code).toBe(EXIT_SCAN_NOT_FOUND);
    expect(mockedAxios.get).toHaveBeenCalledTimes(1);
  });

  it("gives up when the report never becomes readable", async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { status: "processing" } });
    for (let i = 0; i < MAX_TRANSIENT_POLL_FAILURES; i++) {
      mockedAxios.get.mockRejectedValueOnce(OBJECT_NOT_FOUND);
    }

    vi.useFakeTimers();
    const promise = handleScanStatus("s1", headers, "md");
    await vi.advanceTimersByTimeAsync(10000);
    await vi.advanceTimersByTimeAsync(2000 + 4000 + 8000 + 16000);
    const code = await promise;
    vi.useRealTimers();

    expect(code).toBe(EXIT_GENERAL_ERROR);
    // One in-progress poll plus exactly the allowed number of retries.
    expect(mockedAxios.get).toHaveBeenCalledTimes(1 + MAX_TRANSIENT_POLL_FAILURES);
  });

  it("does not retry a non-transient error (403)", async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(httpError(403, "Invalid API key"));

    vi.useFakeTimers();
    const promise = handleScanStatus("s1", headers, "md");
    await vi.advanceTimersByTimeAsync(10000);
    const code = await promise;
    vi.useRealTimers();

    expect(code).toBe(EXIT_GENERAL_ERROR);
    expect(mockedAxios.get).toHaveBeenCalledTimes(2);
  });

  it("retries transport errors that carry no HTTP response", async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(new Error("ECONNRESET"))
      .mockResolvedValueOnce({ data: { status: "completed", markdown: "# Done" } });

    vi.useFakeTimers();
    const promise = handleScanStatus("s1", headers, "md");
    await vi.advanceTimersByTimeAsync(10000);
    await vi.advanceTimersByTimeAsync(2000);
    const code = await promise;
    vi.useRealTimers();

    expect(code).toBe(EXIT_SUCCESS);
  });
});

describe("unreadableReportMessage", () => {
  it("gives the customer the scan id and a next step, not just storage jargon", () => {
    const msg = unreadableReportMessage(
      "scan-abc",
      "HTTP 500 — Failed to fetch report from storage: Object not found"
    );

    expect(msg).toContain("scan-abc");
    expect(msg).toContain("rafter get scan-abc");
    expect(msg).toContain("dashboard");
    // The raw server wording survives as supporting detail...
    expect(msg).toContain("Object not found");
    // ...but is not the whole message.
    expect(msg.split("\n").length).toBeGreaterThan(1);
  });
});
