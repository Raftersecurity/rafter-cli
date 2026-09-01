import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { apiClient } from "../src/utils/api.js";

/**
 * sable-2s6p — a custom `x-api-key` header is NOT stripped across a cross-host
 * redirect the way `Authorization` is. axios replays it verbatim, and the API
 * base is user-settable (`--rafter-url`, self-hosted installs), so a 302 from a
 * misconfigured or hostile endpoint walks the caller's API key to another host.
 *
 * Nothing in this CLI needs to follow a redirect. These tests pin that, and —
 * more importantly — pin that no NEW authenticated call site can reintroduce
 * the hole by reaching for bare `axios`.
 */

describe("apiClient (sable-2s6p)", () => {
  it("refuses to follow redirects", () => {
    expect(apiClient.defaults.maxRedirects).toBe(0);
  });

  it("explains why, instead of surfacing a bare 302", async () => {
    // Drive the interceptor directly: it is the thing that turns an opaque
    // status code into something a customer can act on.
    const handlers = (apiClient.interceptors.response as any).handlers.filter(Boolean);
    expect(handlers.length).toBeGreaterThan(0);
    const onRejected = handlers[handlers.length - 1].rejected;

    const err: any = {
      response: {
        status: 302,
        // ANSI escape included on purpose: an attacker-controlled Location must
        // not be able to rewrite the user's terminal.
        headers: { location: "https://evil.example/collect\u001b[31m" },
      },
      message: "Request failed with status code 302",
    };

    await expect(onRejected(err)).rejects.toBeDefined();
    expect(err.message).toContain("evil.example");
    expect(err.message).toContain("does not follow redirects");
    expect(err.message).not.toContain("\u001b");
    expect(err.message).toContain("self-hosted");
  });
});

/** Every .ts file under a directory, recursively. */
function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
    else if (entry.endsWith(".ts")) out.push(full);
  }
  return out;
}

describe("no authenticated call bypasses apiClient (sable-2s6p)", () => {
  it("creates no second axios instance outside the api utils", () => {
    const offenders: string[] = [];
    for (const file of sourceFiles("src")) {
      if (file.endsWith("utils/api.ts")) continue;
      const text = readFileSync(file, "utf8");
      if (/\baxios\.create\(/.test(text)) offenders.push(file);
    }
    expect(
      offenders,
      `A second axios instance can be created without maxRedirects: 0. Use ` +
        `apiClient from src/utils/api.ts:\n${offenders.join("\n")}`
    ).toEqual([]);
  });

  it("has no bare axios verb call that sends x-api-key", () => {
    const offenders: string[] = [];

    for (const file of sourceFiles("src")) {
      const text = readFileSync(file, "utf8");
      const lines = text.split("\n");
      lines.forEach((line, i) => {
        if (!/\baxios(\.(get|post|put|delete|patch|request))?\(/.test(line)) return;
        // Look at the call and the few lines after it — the header object is
        // usually on a following line.
        const window = lines.slice(i, i + 6).join("\n");
        if (window.includes("x-api-key")) {
          offenders.push(`${file}:${i + 1}`);
        }
      });
    }

    expect(
      offenders,
      `These calls send the API key through bare axios, which follows redirects ` +
        `across hosts. Use apiClient from src/utils/api.ts instead:\n${offenders.join("\n")}`
    ).toEqual([]);
  });
});

describe("API URL construction (sable-2s6p)", () => {
  it("builds no double slash after the scheme", () => {
    // Not cosmetic. `API` ends in "/", and concatenating "/static/..." produced
    // https://rafter.so/api//static/scan, which production answers with a 308.
    // That worked only because the client followed redirects — so refusing
    // them would have broken every core command. Caught by security review,
    // not by any test, because every other test mocks the transport.
    const offenders: string[] = [];
    for (const file of sourceFiles("src")) {
      const text = readFileSync(file, "utf8");
      text.split("\n").forEach((line, i) => {
        if (/\$\{API\}\//.test(line)) offenders.push(`${file}:${i + 1}`);
      });
    }
    expect(
      offenders,
      `These build a double-slash URL. Use apiUrl() instead:\n${offenders.join("\n")}`
    ).toEqual([]);
  });

  it("apiUrl joins cleanly regardless of slashes", async () => {
    const { apiUrl, API } = await import("../src/utils/api.js");
    expect(apiUrl("static/scan")).toBe("https://rafter.so/api/static/scan");
    expect(apiUrl("/static/scan")).toBe("https://rafter.so/api/static/scan");
    expect(API.endsWith("/")).toBe(true); // the trap this guards against
  });
});
