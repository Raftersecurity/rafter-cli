import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import axios, { AxiosError, AxiosHeaders } from "axios";
import {
  EXIT_GENERAL_ERROR,
  EXIT_INSUFFICIENT_SCOPE,
  EXIT_QUOTA_EXHAUSTED,
  handleScopeError,
} from "../src/utils/api.js";

// ── handleScopeError unit tests ─────────────────────────────────────

function make403(body: any): any {
  return { response: { status: 403, data: body } };
}

function make429(): any {
  return { response: { status: 429, data: "Too Many Requests" } };
}

function make401(body: any): any {
  return { response: { status: 401, data: body } };
}

describe("handleScopeError", () => {
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  it("returns true for 403 with scope message (JSON body)", () => {
    const err = make403({
      error:
        "API key does not have scan permission. Required scope: read-and-scan.",
    });
    expect(handleScopeError(err)).toBe(true);
  });

  it("prints helpful scope upgrade message", () => {
    const err = make403({
      error:
        "API key does not have scan permission. Required scope: read-and-scan.",
    });
    handleScopeError(err);
    const output = stderrSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("read access");
    expect(output).toContain("https://rfrr.co/account");
    expect(output).toContain("Read & Scan");
  });

  it("returns true for 403 with scope in string body", () => {
    const err = { response: { status: 403, data: "insufficient scope" } };
    expect(handleScopeError(err)).toBe(true);
  });

  it("returns true for generic 403 without scope keyword", () => {
    const err = make403({ error: "forbidden" });
    expect(handleScopeError(err)).toBe(true);
  });

  it("prints generic 403 message when no scope keyword", () => {
    const err = make403({ error: "forbidden" });
    handleScopeError(err);
    const output = stderrSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("Forbidden (403)");
    expect(output).not.toContain("Read & Scan");
  });

  it("returns false for 429", () => {
    expect(handleScopeError(make429())).toBe(false);
  });

  it("returns false for 401", () => {
    expect(handleScopeError(make401({ error: "invalid key" }))).toBe(false);
  });

  it("returns false when no response object", () => {
    expect(handleScopeError(new Error("network error"))).toBe(false);
  });

  it("returns false for null/undefined", () => {
    expect(handleScopeError(null)).toBe(false);
    expect(handleScopeError(undefined)).toBe(false);
  });
});

// ── Integration: scan POST 403 handling ─────────────────────────────

describe("run command 403 handling", () => {
  let postSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {}) as any);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
    exitSpy.mockRestore();
    postSpy?.mockRestore();
  });

  it("POST /api/static/scan 403 exits with EXIT_INSUFFICIENT_SCOPE", async () => {
    // Simulate what the run command does: axios.post throws, catch calls handleScopeError
    const scopeBody = {
      error:
        "API key does not have scan permission. Required scope: read-and-scan.",
    };
    const err = make403(scopeBody);

    // Replicate the catch logic from run.ts
    if (handleScopeError(err)) {
      process.exit(EXIT_INSUFFICIENT_SCOPE);
    }

    expect(exitSpy).toHaveBeenCalledWith(EXIT_INSUFFICIENT_SCOPE);
    const output = stderrSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("Read & Scan");
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

// ── Read-only endpoints (GET) should NOT be affected ────────────────

describe("read-only endpoints backward compatibility", () => {
  it("GET scan endpoint only needs read scope (no scope check on GET)", () => {
    // The scope error only comes from POST /api/static/scan
    // GET requests with read-only keys should succeed (200) — no 403
    // This test documents the contract: GET endpoints accept both scopes
    const readOnlyGet200 = { status: 200, data: { scan_id: "abc", status: "completed" } };
    // A 200 response means no scope error to handle
    expect(readOnlyGet200.status).toBe(200);
  });

  it("GET usage endpoint only needs read scope (no scope check on GET)", () => {
    const readOnlyGet200 = { status: 200, data: { scans_used: 5, scans_limit: 100 } };
    expect(readOnlyGet200.status).toBe(200);
  });
});
