import { describe, it, expect, vi } from "vitest";
import { BetterleaksScanner } from "../src/scanners/betterleaks.js";
import { writeFileSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

// Access private methods via (scanner as any) for white-box tests
const scanner = new BetterleaksScanner();
const getSeverity = (scanner as any).getSeverity.bind(scanner);
const parseResults = (scanner as any).parseResults.bind(scanner);

describe("BetterleaksScanner.parseResults", () => {
  it("returns [] for JSON null without logging a version-mismatch warning", () => {
    const tmp = join(tmpdir(), `betterleaks-null-test-${Date.now()}.json`);
    writeFileSync(tmp, "null");
    const warnSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const results = parseResults(tmp);
      expect(results).toEqual([]);
      expect(warnSpy).not.toHaveBeenCalledWith(
        expect.stringContaining("not an array")
      );
    } finally {
      warnSpy.mockRestore();
      unlinkSync(tmp);
    }
  });

  it("logs version-mismatch warning for unexpected non-array JSON", () => {
    const tmp = join(tmpdir(), `betterleaks-obj-test-${Date.now()}.json`);
    writeFileSync(tmp, '{"unexpected": true}');
    const warnSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const results = parseResults(tmp);
      expect(results).toEqual([]);
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("not an array")
      );
    } finally {
      warnSpy.mockRestore();
      unlinkSync(tmp);
    }
  });

  it("returns [] for empty report file", () => {
    const tmp = join(tmpdir(), `betterleaks-empty-test-${Date.now()}.json`);
    writeFileSync(tmp, "");
    const results = parseResults(tmp);
    expect(results).toEqual([]);
    unlinkSync(tmp);
  });
});

describe("BetterleaksScanner.getSeverity", () => {
  // ── Critical tier ───────────────────────────────────────────────
  describe("critical", () => {
    it.each([
      ["private-key", []],
      ["rsa-private-key", []],
      ["password", []],
      ["database-password", []],
      ["database-url", []],
      ["github-access-token", []],
      ["slack-access-token", []],
      ["aws-secret-key", []],
      ["github-pat", []],
      ["azure-devops-pat", []],
    ])("rule '%s' → critical", (ruleID, tags) => {
      expect(getSeverity(ruleID, tags)).toBe("critical");
    });

    it("tags key+secret → critical", () => {
      expect(getSeverity("some-unknown-rule", ["key", "secret"])).toBe("critical");
    });
  });

  // ── High tier ─────────────────────────────────────────────────
  describe("high", () => {
    it.each([
      ["api-key", []],
      ["slack-webhook-token", []],
      ["oauth-token", []],
      ["token-refresh", []],
    ])("rule '%s' → high", (ruleID, tags) => {
      expect(getSeverity(ruleID, tags)).toBe("high");
    });

    it("tags with api → high", () => {
      expect(getSeverity("some-rule", ["api"])).toBe("high");
    });
  });

  // ── Medium tier ───────────────────────────────────────────────
  describe("medium", () => {
    it.each([
      ["generic-secret", []],
    ])("rule '%s' → medium", (ruleID, tags) => {
      expect(getSeverity(ruleID, tags)).toBe("medium");
    });
  });

  // ── No false positives ────────────────────────────────────────
  describe("no false positives from -pat / token", () => {
    it("'spatial-data' should NOT be critical (no -pat false positive)", () => {
      const sev = getSeverity("spatial-data", []);
      expect(sev).not.toBe("critical");
    });

    it("'file-pattern' should NOT be critical", () => {
      const sev = getSeverity("file-pattern", []);
      expect(sev).not.toBe("critical");
    });

    it("'tokenizer-config' should NOT match token rule (falls to default)", () => {
      // tokenizer doesn't contain '-token' or start with 'token-', so it won't
      // match the token rule. It falls through to default (high) for unknown rules.
      const sev = getSeverity("tokenizer-config", []);
      expect(sev).toBe("high"); // default, not via token match
    });
  });
});
