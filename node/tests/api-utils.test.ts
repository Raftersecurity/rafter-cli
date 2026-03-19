import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  resolveKey,
  writePayload,
  EXIT_SUCCESS,
  EXIT_GENERAL_ERROR,
  EXIT_SCAN_NOT_FOUND,
  EXIT_QUOTA_EXHAUSTED,
  EXIT_INSUFFICIENT_SCOPE,
  API,
} from "../src/utils/api.js";

/**
 * Tests for API utility functions — key resolution, payload output,
 * and exit code constants.
 */

describe("API constants", () => {
  it("API base URL is rafter.so", () => {
    expect(API).toBe("https://rafter.so/api/");
  });

  it("exit codes are distinct integers", () => {
    const codes = [EXIT_SUCCESS, EXIT_GENERAL_ERROR, EXIT_SCAN_NOT_FOUND, EXIT_QUOTA_EXHAUSTED, EXIT_INSUFFICIENT_SCOPE];
    expect(new Set(codes).size).toBe(codes.length);
    expect(EXIT_SUCCESS).toBe(0);
    expect(EXIT_GENERAL_ERROR).toBe(1);
    expect(EXIT_SCAN_NOT_FOUND).toBe(2);
    expect(EXIT_QUOTA_EXHAUSTED).toBe(3);
    expect(EXIT_INSUFFICIENT_SCOPE).toBe(4);
  });
});

describe("resolveKey", () => {
  const origEnv = process.env.RAFTER_API_KEY;

  afterEach(() => {
    if (origEnv !== undefined) {
      process.env.RAFTER_API_KEY = origEnv;
    } else {
      delete process.env.RAFTER_API_KEY;
    }
  });

  it("returns CLI key when provided", () => {
    expect(resolveKey("cli-key-123")).toBe("cli-key-123");
  });

  it("returns env var when CLI key not provided", () => {
    process.env.RAFTER_API_KEY = "env-key-456";
    expect(resolveKey()).toBe("env-key-456");
  });

  it("prefers CLI key over env var", () => {
    process.env.RAFTER_API_KEY = "env-key-456";
    expect(resolveKey("cli-key-123")).toBe("cli-key-123");
  });

  it("exits when no key available", () => {
    delete process.env.RAFTER_API_KEY;
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(() => resolveKey()).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(EXIT_GENERAL_ERROR);

    exitSpy.mockRestore();
    stderrSpy.mockRestore();
  });
});

describe("writePayload", () => {
  let stdoutSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
  });

  it("writes JSON by default", () => {
    const data = { scan_id: "abc", findings: [] };
    const code = writePayload(data);

    expect(code).toBe(EXIT_SUCCESS);
    expect(stdoutSpy).toHaveBeenCalled();
    const output = stdoutSpy.mock.calls[0][0] as string;
    expect(JSON.parse(output)).toEqual(data);
  });

  it("writes markdown when format is md and data has markdown field", () => {
    const data = { markdown: "# Results\nAll clean", findings: [] };
    writePayload(data, "md");

    const output = stdoutSpy.mock.calls[0][0] as string;
    expect(output).toBe("# Results\nAll clean");
  });

  it("falls back to JSON when format is md but no markdown field", () => {
    const data = { findings: [] };
    writePayload(data, "md");

    const output = stdoutSpy.mock.calls[0][0] as string;
    expect(JSON.parse(output)).toEqual(data);
  });

  it("compacts JSON in quiet mode", () => {
    const data = { a: 1 };
    writePayload(data, "json", true);

    const output = stdoutSpy.mock.calls[0][0] as string;
    expect(output).toBe('{"a":1}');
  });

  it("pretty-prints JSON in non-quiet mode", () => {
    const data = { a: 1 };
    writePayload(data, "json", false);

    const output = stdoutSpy.mock.calls[0][0] as string;
    expect(output).toContain("\n");
  });
});
