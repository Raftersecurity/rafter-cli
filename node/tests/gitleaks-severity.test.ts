import { describe, it, expect } from "vitest";
import { GitleaksScanner } from "../src/scanners/gitleaks.js";

// getSeverity is private, so we test it through the convertToPatternMatch flow
// by calling the static-accessible prototype method via a workaround.
const scanner = new GitleaksScanner();
const getSeverity = (scanner as any).getSeverity.bind(scanner);

describe("GitleaksScanner.getSeverity", () => {
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
