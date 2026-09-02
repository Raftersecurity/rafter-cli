import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * sable-96ex — a 429 during polling used to be classified non-transient, in a
 * codebase that polls every 10 seconds from every customer repo. That is
 * exactly the traffic shape a rate limiter targets, so the first limiter in
 * front of GET /api/static/scan would have failed every customer build
 * instantly, on a condition one sleep would have resolved.
 *
 * It cannot simply join 408/5xx either: on scan SUBMIT a 429 means "out of
 * credits" (exit 3), and retrying a quota rejection for half a minute before
 * failing anyway is worse than failing now. `Retry-After` is the
 * disambiguator — a limiter sends one, a quota rejection does not.
 *
 * These tests pin both halves, plus the two things that make honoring a
 * server-supplied delay safe: the cap, and refusing to guess at a header we
 * cannot parse.
 */

vi.mock("axios", () => {
  // sable-2s6p — the code calls `apiClient`, an axios instance created with
  // maxRedirects: 0. `create` must return something, and the instance carries
  // its OWN mocks so a regression to bare `axios.get` fails these assertions
  // rather than silently passing them.
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
    text: "",
  }),
}));

import axios from "axios";
import {
  handleScanStatus,
  retryAfterMs,
  rateLimitedMessage,
  MAX_RETRY_AFTER_MS,
  MAX_TRANSIENT_POLL_FAILURES,
} from "../src/commands/backend/scan-status.js";
import { EXIT_SUCCESS, EXIT_GENERAL_ERROR } from "../src/utils/api.js";

const mockedAxios = vi.mocked((axios as any).create(), true);

/** A 429 as a limiter sends it: with a delay the client can act on. */
function throttled(retryAfter?: string | number | string[]) {
  return {
    response: {
      status: 429,
      data: { error: "Too many requests" },
      headers: retryAfter === undefined ? {} : { "retry-after": retryAfter },
    },
  };
}

/** Record every delay the code asks for, and fire the callback immediately. */
function recordDelays(): number[] {
  const delays: number[] = [];
  const real = globalThis.setTimeout;
  vi.stubGlobal("setTimeout", ((fn: any, ms?: number) => {
    delays.push(ms ?? 0);
    return real(fn, 0);
  }) as any);
  return delays;
}

describe("retryAfterMs", () => {
  it("reads a plain delay-seconds header", () => {
    expect(retryAfterMs(throttled("5"))).toBe(5000);
  });

  it("tolerates surrounding whitespace", () => {
    expect(retryAfterMs(throttled(" 5 "))).toBe(5000);
  });

  it("is case-insensitive about the header name", () => {
    expect(
      retryAfterMs({ response: { status: 429, headers: { "Retry-After": "7" } } })
    ).toBe(7000);
  });

  it("reads an AxiosHeaders-style accessor", () => {
    const headers: any = { get: (n: string) => (n === "retry-after" ? "9" : null) };
    expect(retryAfterMs({ response: { status: 429, headers } })).toBe(9000);
  });

  it("takes the first value when the header repeats", () => {
    expect(retryAfterMs(throttled(["4", "900"]))).toBe(4000);
  });

  it("honors Retry-After: 0", () => {
    // Distinct from absent, and the failure budget still bounds the loop.
    expect(retryAfterMs(throttled("0"))).toBe(0);
  });

  it("caps a limiter that asks for an hour", () => {
    expect(retryAfterMs(throttled("3600"))).toBe(MAX_RETRY_AFTER_MS);
  });

  it("clamps an absurd value rather than overflowing", () => {
    // 400 digits parses to Infinity; the clamp is what makes that harmless.
    expect(retryAfterMs(throttled("9".repeat(400)))).toBe(MAX_RETRY_AFTER_MS);
  });

  it("returns null for the HTTP-date form", () => {
    // Deliberately unparsed: the composite action has to make the same call in
    // bash on whatever `date` the runner ships. Unparseable means fail fast.
    expect(retryAfterMs(throttled("Wed, 21 Oct 2026 07:28:00 GMT"))).toBeNull();
  });

  it("returns null for a negative or non-numeric value", () => {
    expect(retryAfterMs(throttled("-5"))).toBeNull();
    expect(retryAfterMs(throttled("soon"))).toBeNull();
    expect(retryAfterMs(throttled("1.5"))).toBeNull();
  });

  it("returns null when the header is absent", () => {
    expect(retryAfterMs(throttled())).toBeNull();
    expect(retryAfterMs({ response: { status: 429 } })).toBeNull();
  });
});

describe("handleScanStatus — 429 during polling (sable-96ex)", () => {
  const headers = { "x-api-key": "test-key" };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("rides out a 429 that carries Retry-After", async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(throttled("5"))
      .mockResolvedValueOnce({ data: { status: "completed", markdown: "# Done" } });

    recordDelays();
    const code = await handleScanStatus("s1", headers, "md", true);

    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.get).toHaveBeenCalledTimes(3);
  });

  it("sleeps the server's delay, not its own backoff schedule", async () => {
    // 2000 is what the exponential schedule would have chosen for attempt 1.
    // Pinning the number, not just "it slept", is what makes this test able to
    // fail if the header is read but then ignored.
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(throttled("5"))
      .mockResolvedValueOnce({ data: { status: "completed", markdown: "# Done" } });

    const delays = recordDelays();
    await handleScanStatus("s1", headers, "md", true);

    expect(delays).toEqual([10000, 5000]);
  });

  it("caps the honored delay so a limiter cannot park a CI job", async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(throttled("3600"))
      .mockResolvedValueOnce({ data: { status: "completed", markdown: "# Done" } });

    const delays = recordDelays();
    await handleScanStatus("s1", headers, "md", true);

    expect(delays).toEqual([10000, MAX_RETRY_AFTER_MS]);
  });

  it("fails fast on a 429 with no Retry-After — that is quota, not throttling", async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(throttled());

    recordDelays();
    const code = await handleScanStatus("s1", headers, "md", true);

    expect(code).toBe(EXIT_GENERAL_ERROR);
    // The opening poll and the 429. A retry would make this 3 or more.
    expect(mockedAxios.get).toHaveBeenCalledTimes(2);
  });

  it("fails fast on a Retry-After it cannot parse", async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: { status: "processing" } })
      .mockRejectedValueOnce(throttled("Wed, 21 Oct 2026 07:28:00 GMT"));

    recordDelays();
    const code = await handleScanStatus("s1", headers, "md", true);

    expect(code).toBe(EXIT_GENERAL_ERROR);
    expect(mockedAxios.get).toHaveBeenCalledTimes(2);
  });

  it("spends the failure budget, so an endless throttle cannot loop forever", async () => {
    let call = 0;
    mockedAxios.get.mockImplementation(async () => {
      call += 1;
      if (call === 1) return { data: { status: "processing" } };
      throw throttled("1");
    });

    recordDelays();
    const code = await handleScanStatus("s1", headers, "md", true);

    expect(code).toBe(EXIT_GENERAL_ERROR);
    expect(call).toBe(1 + MAX_TRANSIENT_POLL_FAILURES);
  });

  it("says it was rate limited, not that the report could not be read", async () => {
    // Sending a throttled customer to look at their scan report — or at a
    // `rafter get` that will be throttled too — wastes their time on the wrong
    // problem entirely.
    let call = 0;
    mockedAxios.get.mockImplementation(async () => {
      call += 1;
      if (call === 1) return { data: { status: "processing" } };
      throw throttled("1");
    });
    const errors: string[] = [];
    vi.spyOn(console, "error").mockImplementation((m: any) => {
      errors.push(String(m));
    });

    recordDelays();
    await handleScanStatus("scan-abc", headers, "md", true);

    const said = errors.join("\n");
    expect(said).toContain("rate limited");
    expect(said).toContain("scan-abc");
    expect(said).not.toContain("could not read the report");
  });

  it("still calls a mid-poll 429 retryable after a success has reset the run", async () => {
    // The Retry-After gate is about the header, not about how far into the
    // poll we are — unlike 404, which is fatal on the first poll only.
    mockedAxios.get
      .mockRejectedValueOnce(throttled("2"))
      .mockResolvedValueOnce({ data: { status: "completed", markdown: "# Done" } });

    const delays = recordDelays();
    const code = await handleScanStatus("s1", headers, "md", true);

    expect(code).toBe(EXIT_SUCCESS);
    expect(delays).toEqual([2000]);
  });
});

describe("rateLimitedMessage", () => {
  it("names the scan, the cause, and a next step", () => {
    const msg = rateLimitedMessage("scan-abc", "HTTP 429 — Too many requests", 5);

    expect(msg).toContain("rate limited");
    expect(msg).toContain("scan-abc");
    expect(msg).toContain("rafter get scan-abc");
    expect(msg).toContain("dashboard");
    // The raw server wording survives as supporting detail, not as the whole
    // explanation.
    expect(msg).toContain("HTTP 429");
    expect(msg.split("\n").length).toBeGreaterThan(1);
  });
});
