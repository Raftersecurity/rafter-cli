import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { fmt, setAgentMode, isAgentMode } from "../src/utils/formatter.js";

/**
 * Tests for the output formatter — validates both human (chalk) and agent
 * (plain text) modes produce correct output across all formatter methods.
 */

// Strip ANSI escape sequences for assertions
const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

describe("formatter", () => {
  afterEach(() => {
    setAgentMode(false);
  });

  // ── agent mode toggle ──────────────────────────────────────────────

  describe("agent mode toggle", () => {
    it("defaults to false", () => {
      setAgentMode(false);
      expect(isAgentMode()).toBe(false);
    });

    it("can be enabled", () => {
      setAgentMode(true);
      expect(isAgentMode()).toBe(true);
    });

    it("can be toggled back and forth", () => {
      setAgentMode(true);
      expect(isAgentMode()).toBe(true);
      setAgentMode(false);
      expect(isAgentMode()).toBe(false);
      setAgentMode(true);
      expect(isAgentMode()).toBe(true);
    });
  });

  // ── agent mode output (plain text, no ANSI) ───────────────────────

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

    // ── ANSI-free guarantee ──────────────────────────────────────────

    it("header contains no ANSI escape codes", () => {
      const out = fmt.header("Security Report");
      expect(out).toBe(stripAnsi(out));
    });

    it("success contains no ANSI escape codes", () => {
      const out = fmt.success("all clear");
      expect(out).toBe(stripAnsi(out));
    });

    it("warning contains no ANSI escape codes", () => {
      const out = fmt.warning("heads up");
      expect(out).toBe(stripAnsi(out));
    });

    it("error contains no ANSI escape codes", () => {
      const out = fmt.error("crash");
      expect(out).toBe(stripAnsi(out));
    });

    it("severity contains no ANSI escape codes for all levels", () => {
      for (const level of ["critical", "high", "medium", "low"]) {
        const out = fmt.severity(level);
        expect(out).toBe(stripAnsi(out));
      }
    });

    it("divider contains no ANSI escape codes", () => {
      const out = fmt.divider();
      expect(out).toBe(stripAnsi(out));
    });

    it("info contains no ANSI escape codes", () => {
      const out = fmt.info("plain text");
      expect(out).toBe(stripAnsi(out));
    });

    // ── no emoji in agent mode ───────────────────────────────────────

    it("no emoji characters in any output", () => {
      // Regex matches common emoji ranges (surrogate pairs, variation selectors, etc.)
      const emojiRe = /[\u2600-\u27BF\u{1F300}-\u{1F9FF}\u{1FA00}-\u{1FAFF}]/u;
      const outputs = [
        fmt.header("Test"),
        fmt.success("ok"),
        fmt.warning("warn"),
        fmt.error("err"),
        fmt.severity("critical"),
        fmt.severity("high"),
        fmt.severity("medium"),
        fmt.severity("low"),
        fmt.divider(),
        fmt.info("text"),
      ];
      for (const out of outputs) {
        expect(out).not.toMatch(emojiRe);
      }
    });

    // ── edge cases ───────────────────────────────────────────────────

    it("handles empty string input", () => {
      expect(fmt.header("")).toBe("===  ===");
      expect(fmt.success("")).toBe("[OK] ");
      expect(fmt.warning("")).toBe("[WARN] ");
      expect(fmt.error("")).toBe("[ERROR] ");
      expect(fmt.info("")).toBe("");
    });

    it("handles special characters in input", () => {
      expect(fmt.success("file: /tmp/<test> & \"quotes\""))
        .toBe("[OK] file: /tmp/<test> & \"quotes\"");
    });

    it("severity uppercases mixed-case input", () => {
      expect(fmt.severity("Critical")).toBe("[CRITICAL]");
      expect(fmt.severity("HIGH")).toBe("[HIGH]");
    });

    it("severity handles unknown level in agent mode", () => {
      expect(fmt.severity("unknown")).toBe("[UNKNOWN]");
      expect(fmt.severity("custom")).toBe("[CUSTOM]");
    });
  });

  // ── human mode output (chalk) ─────────────────────────────────────

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

    // ── human mode contains styled content ───────────────────────────

    it("header contains box-drawing characters", () => {
      const out = fmt.header("Report");
      expect(out).toContain("┌");
      expect(out).toContain("┐");
      expect(out).toContain("Report");
    });

    it("divider uses double-line box characters", () => {
      const raw = stripAnsi(fmt.divider());
      expect(raw).toContain("═");
      expect(raw.length).toBeGreaterThanOrEqual(50);
    });

    it("success preserves user text", () => {
      const raw = stripAnsi(fmt.success("all clear"));
      expect(raw).toContain("all clear");
    });

    it("warning preserves user text", () => {
      const raw = stripAnsi(fmt.warning("be careful"));
      expect(raw).toContain("be careful");
    });

    it("error preserves user text", () => {
      const raw = stripAnsi(fmt.error("it broke"));
      expect(raw).toContain("it broke");
    });

    it("info preserves user text", () => {
      const raw = stripAnsi(fmt.info("details here"));
      expect(raw).toContain("details here");
    });

    it("severity includes level name for all known levels", () => {
      for (const level of ["critical", "high", "medium", "low"]) {
        const raw = stripAnsi(fmt.severity(level));
        expect(raw.toLowerCase()).toContain(level);
      }
    });

    // ── human vs agent mode produce different output ─────────────────

    it("header output differs between modes", () => {
      setAgentMode(false);
      const human = fmt.header("Test");
      setAgentMode(true);
      const agent = fmt.header("Test");
      expect(human).not.toBe(agent);
    });

    it("success output differs between modes", () => {
      setAgentMode(false);
      const human = fmt.success("ok");
      setAgentMode(true);
      const agent = fmt.success("ok");
      expect(human).not.toBe(agent);
    });

    it("divider output differs between modes", () => {
      setAgentMode(false);
      const human = fmt.divider();
      setAgentMode(true);
      const agent = fmt.divider();
      expect(human).not.toBe(agent);
    });
  });

  // ── mode switching mid-stream ──────────────────────────────────────

  describe("mode switching mid-stream", () => {
    it("switching mode changes output immediately", () => {
      setAgentMode(true);
      const agentOut = fmt.success("test");
      expect(agentOut).toBe("[OK] test");

      setAgentMode(false);
      const humanOut = fmt.success("test");
      expect(humanOut).toContain("✓");
      expect(humanOut).not.toBe(agentOut);
    });

    it("all methods respect current mode at call time", () => {
      setAgentMode(true);
      expect(fmt.header("X")).toBe("=== X ===");
      expect(fmt.divider()).toBe("---");
      expect(fmt.info("Y")).toBe("Y");

      setAgentMode(false);
      expect(fmt.header("X")).toContain("┌");
      expect(fmt.divider()).toContain("═");
      // info in human mode wraps with chalk.cyan; in non-TTY chalk may strip
      // colors, so just verify the text is still present
      expect(fmt.info("Y")).toContain("Y");
    });
  });
});
