import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Tests for `--wait`/`--timeout` on `rafter sites create` and
 * `rafter sites scan`. All tests mock axios (no network) and inject a fake
 * clock/sleep via the hidden third `waitDeps` parameter, so none of them
 * actually sleeps.
 *
 * The fake `now()` is a finite queue that throws if read more times than
 * scripted, and the mocked axios `get` returns `undefined` once its queued
 * responses run out (vi.fn()'s default with no calls queued). Both turn "the
 * poll loop didn't stop when it should have" into an immediate thrown error
 * instead of a hang, so a broken guard fails fast rather than timing out the
 * whole test run.
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

import axios from "axios";
import { runSitesCreate } from "../src/commands/sites/create.js";
import { runSitesScan } from "../src/commands/sites/scan.js";
import { EXIT_SUCCESS, EXIT_GENERAL_ERROR, apiUrl } from "../src/utils/api.js";
import { EXIT_WAIT_INTERRUPTED, type SitesWaitDeps } from "../src/commands/sites/wait.js";

const mockedAxios = vi.mocked((axios as any).create(), true);
const opts = { apiKey: "test-key", format: "json", quiet: true };

/** A fake clock that returns scripted values in order, and throws rather
 * than loop forever if the guard under test fails to stop polling. */
function fakeClock(values: number[]): () => number {
  const queue = [...values];
  return () => {
    if (queue.length === 0) throw new Error("now() called more times than scripted — the poll loop didn't stop");
    return queue.shift()!;
  };
}

const instantDeps = (nowValues: number[]): SitesWaitDeps => ({
  pollIntervalMs: 0,
  sleep: async () => {},
  now: fakeClock(nowValues),
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(process.stdout, "write").mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("sites create --wait", () => {
  it("polls until succeeded and exits 0, printing the final status payload", async () => {
    // Fails if --wait reports success before latest_run.status reaches a
    // terminal state, or never reports it at all.
    mockedAxios.post.mockResolvedValueOnce({
      data: { site: { id: "p1" }, run: { id: "r1" }, created: true },
    });
    mockedAxios.get
      .mockResolvedValueOnce({ data: { latest_run: { id: "r1", status: "running" } } })
      .mockResolvedValueOnce({ data: { latest_run: { id: "r1", status: "succeeded" } } });

    const code = await runSitesCreate("https://example.com", { ...opts, wait: true }, instantDeps([0, 0, 0]));

    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.get).toHaveBeenCalledWith(
      apiUrl("static/sites/p1"),
      expect.objectContaining({ headers: { "x-api-key": "test-key" } })
    );
    expect(process.stdout.write).toHaveBeenCalledWith(
      JSON.stringify({ latest_run: { id: "r1", status: "succeeded" } })
    );
  });

  it("exits 1 when the waited-for run fails", async () => {
    mockedAxios.post.mockResolvedValueOnce({
      data: { site: { id: "p1" }, run: { id: "r1" }, created: true },
    });
    mockedAxios.get.mockResolvedValueOnce({ data: { latest_run: { id: "r1", status: "failed" } } });

    const code = await runSitesCreate("https://example.com", { ...opts, wait: true }, instantDeps([0, 0]));
    expect(code).toBe(EXIT_GENERAL_ERROR);
  });

  it("exits 1 and names both run ids when a different run starts on the site", async () => {
    // Fails if --wait reports the OTHER run's status as if it were ours.
    mockedAxios.post.mockResolvedValueOnce({
      data: { site: { id: "p1" }, run: { id: "r1" }, created: true },
    });
    mockedAxios.get.mockResolvedValueOnce({ data: { latest_run: { id: "r2", status: "running" } } });

    const code = await runSitesCreate("https://example.com", { ...opts, wait: true }, instantDeps([0, 0]));

    expect(code).toBe(EXIT_GENERAL_ERROR);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("r1"));
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("r2"));
  });

  it("exits 1 naming the run and site id on timeout", async () => {
    mockedAxios.post.mockResolvedValueOnce({
      data: { site: { id: "p1" }, run: { id: "r1" }, created: true },
    });
    mockedAxios.get.mockResolvedValueOnce({ data: { latest_run: { id: "r1", status: "running" } } });

    // deadline = now()[0] + 1s*1000 = 1000; the next now() read (1500) is past it.
    const code = await runSitesCreate(
      "https://example.com",
      { ...opts, wait: true, timeout: 1 },
      instantDeps([0, 1500])
    );

    expect(code).toBe(EXIT_GENERAL_ERROR);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("r1"));
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("p1"));
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("timed out"));
  });

  it("Ctrl-C mid-sleep stops waiting with exit 130 and removes its handler", async () => {
    // Fails if Ctrl-C is ignored until the next poll, kills the process with
    // a generic code, or leaves a SIGINT listener behind.
    mockedAxios.post.mockResolvedValueOnce({
      data: { site: { id: "p1" }, run: { id: "r1" }, created: true },
    });
    mockedAxios.get.mockResolvedValueOnce({ data: { latest_run: { id: "r1", status: "running" } } });
    let fire: () => void = () => {};
    let unsubscribed = false;
    const deps: SitesWaitDeps = {
      pollIntervalMs: 0,
      sleep: () => { fire(); return new Promise(() => {}); }, // a sleep that never ends on its own
      now: fakeClock([0, 0]),
      onInterrupt: (cb) => { fire = cb; return () => { unsubscribed = true; }; },
    };

    const code = await runSitesCreate("https://example.com", { ...opts, wait: true }, deps);

    expect(code).toBe(EXIT_WAIT_INTERRUPTED);
    expect(code).toBe(130);
    expect(unsubscribed).toBe(true);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("rafter sites get p1"));
  });

  it("rejects a non-positive --timeout before making any request", async () => {
    const code = await runSitesCreate("https://example.com", { ...opts, wait: true, timeout: 0 });
    expect(code).toBe(EXIT_GENERAL_ERROR);
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });

  it("when create started no run (site already existed), prints a message and returns the plain create result", async () => {
    mockedAxios.post.mockResolvedValueOnce({
      data: { site: { id: "p1", is_archived: false }, run: null, created: false },
    });

    const code = await runSitesCreate("https://example.com", { ...opts, wait: true });

    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.get).not.toHaveBeenCalled();
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("nothing to wait for"));
  });
});

describe("sites scan --wait", () => {
  it("polls using the given project id and exits 0 on success", async () => {
    mockedAxios.post.mockResolvedValueOnce({ data: { run: { id: "r1" } } });
    mockedAxios.get.mockResolvedValueOnce({ data: { latest_run: { id: "r1", status: "succeeded" } } });

    const code = await runSitesScan("proj-123", { ...opts, wait: true }, instantDeps([0, 0]));

    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.get).toHaveBeenCalledWith(
      apiUrl("static/sites/proj-123"),
      expect.objectContaining({ headers: { "x-api-key": "test-key" } })
    );
  });

  it("exits 1 when the scan response names no site id and a URL was given", async () => {
    // Fails if --wait silently polls the wrong id (e.g. the raw URL) instead
    // of refusing when it cannot determine the real site id.
    mockedAxios.post.mockResolvedValueOnce({ data: { run: { id: "r1" } } });

    const code = await runSitesScan("https://example.com", { ...opts, wait: true });

    expect(code).toBe(EXIT_GENERAL_ERROR);
    expect(mockedAxios.get).not.toHaveBeenCalled();
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("r1"));
  });

  it("uses run.project_id from the response when given a URL", async () => {
    mockedAxios.post.mockResolvedValueOnce({ data: { run: { id: "r1", project_id: "p1" } } });
    mockedAxios.get.mockResolvedValueOnce({ data: { latest_run: { id: "r1", status: "succeeded" } } });

    const code = await runSitesScan("https://example.com", { ...opts, wait: true }, instantDeps([0, 0]));

    expect(code).toBe(EXIT_SUCCESS);
    expect(mockedAxios.get).toHaveBeenCalledWith(apiUrl("static/sites/p1"), expect.anything());
  });
});
