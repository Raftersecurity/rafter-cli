import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { fmt, setAgentMode, isAgentMode } from "../src/utils/formatter.js";

/**
 * Tests for the output formatter — validates both human (chalk) and agent
 * (plain text) modes produce correct output.
 */

describe("formatter", () => {
  afterEach(() => {
    setAgentMode(false);
  });

  describe("agent mode toggle", () => {
    it("defaults to false", () => {
      setAgentMode(false);
      expect(isAgentMode()).toBe(false);
    });

    it("can be enabled", () => {
      setAgentMode(true);
      expect(isAgentMode()).toBe(true);
    });
  });

  describe("agent mode output (plain text, no ANSI)", () => {
    beforeEach(() => setAgentMode(true));

    it("header wraps text in === delimiters", () => {
      expect(fmt.header("Test")).toBe("=== Test ===");
    });

    it("success prefixes with [OK]", () => {
      expect(fmt.success("done")).toBe("[OK] done");
    });

    it("warning prefixes with [WARN]", () => {
      expect(fmt.warning("caution")).toBe("[WARN] caution");
    });

    it("error prefixes with [ERROR]", () => {
      expect(fmt.error("failed")).toBe("[ERROR] failed");
    });

    it("severity wraps level in brackets", () => {
      expect(fmt.severity("critical")).toBe("[CRITICAL]");
      expect(fmt.severity("high")).toBe("[HIGH]");
      expect(fmt.severity("medium")).toBe("[MEDIUM]");
      expect(fmt.severity("low")).toBe("[LOW]");
    });

    it("divider returns ---", () => {
      expect(fmt.divider()).toBe("---");
    });

    it("info returns plain text", () => {
      expect(fmt.info("hello")).toBe("hello");
    });
  });

  describe("human mode output (chalk)", () => {
    beforeEach(() => setAgentMode(false));

    it("success contains check mark", () => {
      expect(fmt.success("done")).toContain("✓");
    });

    it("warning contains warning emoji", () => {
      expect(fmt.warning("caution")).toContain("⚠");
    });

    it("error contains X mark", () => {
      expect(fmt.error("failed")).toContain("✗");
    });

    it("severity returns non-empty string for all levels", () => {
      expect(fmt.severity("critical").length).toBeGreaterThan(0);
      expect(fmt.severity("high").length).toBeGreaterThan(0);
      expect(fmt.severity("medium").length).toBeGreaterThan(0);
      expect(fmt.severity("low").length).toBeGreaterThan(0);
    });

    it("severity handles unknown level", () => {
      expect(fmt.severity("unknown")).toBe("[UNKNOWN]");
    });
  });
});
