/**
 * Asserts the session-wide isolation setup file (env-isolation-setup.ts)
 * actually took effect. If this goes red, every other test's isolation is
 * suspect too.
 */
import { describe, it, expect } from "vitest";
import os from "os";

const LIVE_OPT_IN = process.env.RAFTER_TEST_LIVE_API === "1";

describe.skipIf(LIVE_OPT_IN)("test isolation guard", () => {
  it("HOME is an isolated temp dir, not the real home", () => {
    expect(os.homedir()).toContain("rafter-test-home-");
  });

  it("the API base is redirected away from production", async () => {
    const { apiUrl } = await import("../src/utils/api.js");
    const url = apiUrl("static/scan");
    expect(url.startsWith("http://127.0.0.1:")).toBe(true);
    expect(url.startsWith("https://rafter.so")).toBe(false);
  });
});
