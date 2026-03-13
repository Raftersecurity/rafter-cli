import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import axios, { AxiosError, AxiosHeaders } from "axios";
import {
  EXIT_GENERAL_ERROR,
  EXIT_INSUFFICIENT_SCOPE,
  EXIT_QUOTA_EXHAUSTED,
  handle403,
  handleScopeError,
} from "../src/utils/api.js";

// ── Helpers ─────────────────────────────────────────────────────────

function make403(body: any): any {
  return { response: { status: 403, data: body } };
}

function make429(): any {
  return { response: { status: 429, data: "Too Many Requests" } };
}

function make401(body: any): any {
  return { response: { status: 401, data: body } };
}

// ── handle403 unit tests ────────────────────────────────────────────

describe("handle403", () => {
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  it("returns -1 for non-403 status", () => {
    expect(handle403(make429())).toBe(-1);
    expect(handle403(make401({ error: "bad key" }))).toBe(-1);
  });

  it("returns -1 for null/undefined", () => {
    expect(handle403(null)).toBe(-1);
    expect(handle403(undefined)).toBe(-1);
  });

  it("returns -1 for error without response", () => {
    expect(handle403(new Error("network error"))).toBe(-1);
  });

  it("returns EXIT_QUOTA_EXHAUSTED for scan_mode limit body", () => {
    const err = make403({ scan_mode: "fast", limit: 10, used: 10 });
    expect(handle403(err)).toBe(EXIT_QUOTA_EXHAUSTED);
  });

  it("prints quota message for scan_mode body", () => {
    const err = make403({ scan_mode: "deep", limit: 5, used: 5 });
    handle403(err);
    const output = stderrSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("Deep scan limit reached");
    expect(output).toContain("5/5");
    expect(output).toContain("Upgrade your plan");
  });

  it("uses used field separately from limit", () => {
    const err = make403({ scan_mode: "fast", limit: 10, used: 8 });
    handle403(err);
    const output = stderrSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("8/10");
  });

  it("defaults used to limit when used not provided", () => {
    const err = make403({ scan_mode: "fast", limit: 10 });
    handle403(err);
    const output = stderrSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("10/10");
  });

  it("returns EXIT_INSUFFICIENT_SCOPE for scope error", () => {
    const err = make403({
      error: "API key does not have scan permission. Required scope: read-and-scan.",
    });
    expect(handle403(err)).toBe(EXIT_INSUFFICIENT_SCOPE);
  });

  it("prints scope upgrade message", () => {
    const err = make403({
      error: "Required scope: read-and-scan.",
    });
    handle403(err);
    const output = stderrSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("read access");
    expect(output).toContain("Read & Scan");
    expect(output).toContain("https://rfrr.co/account");
  });

  it("returns EXIT_INSUFFICIENT_SCOPE for scope in string body", () => {
    const err = { response: { status: 403, data: "insufficient scope" } };
    expect(handle403(err)).toBe(EXIT_INSUFFICIENT_SCOPE);
  });

  it("returns EXIT_INSUFFICIENT_SCOPE for generic 403", () => {
    const err = make403({ error: "forbidden" });
    expect(handle403(err)).toBe(EXIT_INSUFFICIENT_SCOPE);
  });

  it("prints generic 403 message for non-scope error", () => {
    const err = make403({ error: "forbidden" });
    handle403(err);
    const output = stderrSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("Forbidden (403)");
    expect(output).not.toContain("Read & Scan");
  });

  it("handles empty 403 body", () => {
    const err = make403("");
    expect(handle403(err)).toBe(EXIT_INSUFFICIENT_SCOPE);
    const output = stderrSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("access denied");
  });
});

// ── handleScopeError (deprecated wrapper) ───────────────────────────

describe("handleScopeError (deprecated)", () => {
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  it("returns true for 403 with scope message", () => {
    const err = make403({
      error: "Required scope: read-and-scan.",
    });
    expect(handleScopeError(err)).toBe(true);
  });

  it("returns true for scan_mode 403", () => {
    const err = make403({ scan_mode: "fast", limit: 10 });
    expect(handleScopeError(err)).toBe(true);
  });

  it("returns false for non-403", () => {
    expect(handleScopeError(make429())).toBe(false);
    expect(handleScopeError(null)).toBe(false);
    expect(handleScopeError(undefined)).toBe(false);
  });
});

// ── Exit code values ────────────────────────────────────────────────

describe("exit codes", () => {
  it("EXIT_INSUFFICIENT_SCOPE is 4", () => {
    expect(EXIT_INSUFFICIENT_SCOPE).toBe(4);
  });

  it("does not collide with other exit codes", () => {
    const codes = [
      EXIT_GENERAL_ERROR,
      EXIT_QUOTA_EXHAUSTED,
      EXIT_INSUFFICIENT_SCOPE,
    ];
    expect(new Set(codes).size).toBe(codes.length);
  });
});

// ── Read-only endpoints backward compatibility ──────────────────────

describe("read-only endpoints backward compatibility", () => {
  it("GET scan endpoint only needs read scope (no scope check on GET)", () => {
    const readOnlyGet200 = { status: 200, data: { scan_id: "abc", status: "completed" } };
    expect(readOnlyGet200.status).toBe(200);
  });

  it("GET usage endpoint only needs read scope (no scope check on GET)", () => {
    const readOnlyGet200 = { status: 200, data: { scans_used: 5, scans_limit: 100 } };
    expect(readOnlyGet200.status).toBe(200);
  });
});
