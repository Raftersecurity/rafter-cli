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
  backoffMs,
  BASE_BACKOFF_MS,
  MAX_TRANSIENT_POLL_FAILURES,
  MAX_TOTAL_TRANSIENT_POLL_FAILURES,
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

  it("retries a transient 500 on the FIRST poll", async () => {
    // The give-up message tells the user to run `rafter get <id>`, which
    // re-enters at the first poll. If that path did not retry, the remedy we
    // recommend would be defeated by one bad read.
    mockedAxios.get
      .mockRejectedValueOnce(OBJECT_NOT_FOUND)
      .mockResolvedValueOnce({ data: { status: "completed", markdown: "# Done" } });

    vi.useFakeTimers();
    const promise = handleScanStatus("s1", headers, "md", true);
    await vi.advanceTimersByTimeAsync(2000);
    const code = await promise;
    vi.useRealTimers();

    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.get).toHaveBeenCalledTimes(2);
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

  it("does NOT retry a plain programming error", async () => {
    // A TypeError thrown from our own code also has no `response`. Retrying it
    // five times would report a local bug as a flaky backend.
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(new TypeError("x is not a function"));

    vi.useFakeTimers();
    const promise = handleScanStatus("s1", headers, "md", true);
    await vi.advanceTimersByTimeAsync(10000);
    const code = await promise;
    vi.useRealTimers();

    expect(code).toBe(EXIT_GENERAL_ERROR);
    expect(mockedAxios.get).toHaveBeenCalledTimes(2);
  });

  it("retries transport errors that carry no HTTP response", async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(
        Object.assign(new Error("read ECONNRESET"), {
          isAxiosError: true,
          code: "ECONNRESET",
          request: {},
        })
      )
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

describe("backoff schedule (sable-l10k)", () => {
  const headers = { "x-api-key": "test-key" };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("is exponential, not flat — 2s, 4s, 8s, 16s", () => {
    expect(BASE_BACKOFF_MS).toBeGreaterThan(0);
    expect([1, 2, 3, 4].map(backoffMs)).toEqual([2000, 4000, 8000, 16000]);
  });

  /**
   * Record every delay the code asks for and fire the callback immediately.
   * This pins the SCHEDULE rather than an upper bound: with BASE_BACKOFF_MS
   * mutated to 0, or `2 ** (n-1)` mistyped as `2 * (n-1)`, the recorded
   * sequence changes and the test fails. A call-count assertion would not.
   */
  function recordDelays(): number[] {
    const delays: number[] = [];
    const real = globalThis.setTimeout;
    vi.stubGlobal("setTimeout", ((fn: any, ms?: number) => {
      delays.push(ms ?? 0);
      return real(fn, 0);
    }) as any);
    return delays;
  }

  it("actually SLEEPS the 2/4/8/16 schedule between retries", async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { status: "processing" } });
    for (let i = 0; i < MAX_TRANSIENT_POLL_FAILURES; i++) {
      mockedAxios.get.mockRejectedValueOnce(OBJECT_NOT_FOUND);
    }

    const delays = recordDelays();
    const code = await handleScanStatus("s1", headers, "md", true);

    expect(code).toBe(EXIT_GENERAL_ERROR);
    // 10s poll interval, then the four backoffs preceding the fifth failure.
    expect(delays).toEqual([10000, 2000, 4000, 8000, 16000]);
  });

  it("restarts the backoff after a successful poll clears the run", async () => {
    // Two blips far apart must NOT add up to a give-up.
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(OBJECT_NOT_FOUND)
      .mockRejectedValueOnce(OBJECT_NOT_FOUND)
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(OBJECT_NOT_FOUND)
      .mockRejectedValueOnce(OBJECT_NOT_FOUND)
      .mockResolvedValueOnce({ data: { status: "completed", markdown: "# Done" } });

    const delays = recordDelays();
    const code = await handleScanStatus("s1", headers, "md", true);

    expect(code).toBe(EXIT_SUCCESS);
    expect(delays).toEqual([10000, 2000, 4000, 10000, 2000, 4000]);
  });

  it("caps TOTAL transient failures, so a flapping server cannot loop forever", async () => {
    // Alternating success/failure resets the consecutive counter every time.
    // Without a total cap, and with no wall-clock deadline in the CLI, that
    // loop never terminates.
    mockedAxios.get.mockResolvedValueOnce({ data: { status: "processing" } });
    for (let i = 0; i < MAX_TOTAL_TRANSIENT_POLL_FAILURES + 5; i++) {
      mockedAxios.get
        .mockRejectedValueOnce(OBJECT_NOT_FOUND)
        .mockResolvedValueOnce({ data: { status: "processing" } });
    }

    recordDelays();
    const code = await handleScanStatus("s1", headers, "md", true);

    expect(code).toBe(EXIT_GENERAL_ERROR);
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
