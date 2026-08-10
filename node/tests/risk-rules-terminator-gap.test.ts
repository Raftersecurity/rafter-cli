import { describe, it, expect } from "vitest";
import { assessCommandRisk, CRITICAL_PATTERNS, DEFAULT_BLOCKED_PATTERNS } from "../src/core/risk-rules.js";

/**
 * Regression tests for the rm terminator gap (sable-5adm).
 *
 * The critical rm rules terminated the path on whitespace or end-of-string. A
 * shell operator needs no whitespace before it, so appending one character
 * dropped an UNCONDITIONAL hard-block to `high` — a tier policy, mode, and
 * deny-list can all opt out of — while the command ran exactly the same.
 *
 * Every command here is valid, executable shell. `rm -rf /;` does what
 * `rm -rf /` does.
 *
 * These fail on the pre-fix detector: each one assessed `high` before.
 */

const TERMINATORS: Array<[string, string]> = [
  ["semicolon", ";"],
  ["semicolon + command", "; echo done"],
  ["semicolon, no space", ";ls"],
  ["and-and", "&& ls"],
  ["and-and, no space", "&&ls"],
  ["or-or", "|| ls"],
  ["pipe", "|cat"],
  ["background", "&"],
  ["subshell close", ")"],
  ["redirect out", ">f"],
  ["redirect out with path", ">/tmp/x"],
  ["redirect append", ">>log"],
  ["redirect in", "<f"],
];

describe("rm terminator gap (sable-5adm)", () => {
  describe("root stays critical through every operator", () => {
    for (const [label, suffix] of TERMINATORS) {
      it(`blocks rm -rf / followed by ${label}`, () => {
        expect(assessCommandRisk(`rm -rf /${suffix}`)).toBe("critical");
      });
    }
  });

  describe("critical directories stay critical through every operator", () => {
    for (const [label, suffix] of TERMINATORS) {
      it(`blocks rm -rf /etc followed by ${label}`, () => {
        expect(assessCommandRisk(`rm -rf /etc${suffix}`)).toBe("critical");
      });
    }

    it("covers the other critical dirs too", () => {
      for (const dir of ["home", "usr", "boot", "root", "sys", "proc", "lib", "bin", "sbin", "opt"]) {
        expect(assessCommandRisk(`rm -rf /${dir};`)).toBe("critical");
        expect(assessCommandRisk(`rm -rf /${dir}|cat`)).toBe("critical");
      }
    });
  });

  describe("flag order and wrappers still hold with an operator appended", () => {
    it("handles reversed and split flags", () => {
      expect(assessCommandRisk("rm -fr /;")).toBe("critical");
      expect(assessCommandRisk("rm -r -f /;")).toBe("critical");
      expect(assessCommandRisk("rm -f -r /etc;")).toBe("critical");
    });

    it("handles sudo and chained position", () => {
      expect(assessCommandRisk("sudo rm -rf /;")).toBe("critical");
      expect(assessCommandRisk("echo ok && rm -rf /boot;")).toBe("critical");
      expect(assessCommandRisk("cd /tmp; rm -rf /usr|cat")).toBe("critical");
    });

    it("handles a subshell, which was the ) case", () => {
      expect(assessCommandRisk("(rm -rf /)")).toBe("critical");
    });
  });

  describe("no new false positives", () => {
    it("does not promote a non-critical path", () => {
      expect(assessCommandRisk("rm -rf /tmp/build;")).toBe("high");
      expect(assessCommandRisk("rm -rf ./node_modules && npm i")).toBe("high");
      expect(assessCommandRisk("rm -rf build|tee log")).toBe("high");
    });

    it("does not match a longer path that merely starts with a critical dir name", () => {
      // /etcetera is not /etc — the terminator must still be required.
      expect(assessCommandRisk("rm -rf /etcetera;")).toBe("high");
      expect(assessCommandRisk("rm -rf /libraries;")).toBe("high");
      expect(assessCommandRisk("rm -rf /opts;")).toBe("high");
    });

    it("leaves non-rm commands alone", () => {
      expect(assessCommandRisk("ls /;")).toBe("low");
      expect(assessCommandRisk("cat /etc/hostname;")).toBe("low");
      expect(assessCommandRisk("git status && ls /")).toBe("low");
    });

    it("still treats a quoted mention as data", () => {
      expect(assessCommandRisk('git commit -m "never rm -rf /; really"')).toBe("low");
      expect(assessCommandRisk('echo "rm -rf /;" > notes.txt')).toBe("low");
    });

    it("keeps a bare rm -rf / critical (the case that always worked)", () => {
      expect(assessCommandRisk("rm -rf /")).toBe("critical");
      expect(assessCommandRisk("rm -rf / ")).toBe("critical");
      expect(assessCommandRisk("rm -rf /etc")).toBe("critical");
    });
  });

  describe("the default deny-list inherits the fix", () => {
    // CRITICAL_PATTERN_SOURCES is DEFAULT_BLOCKED_PATTERNS byte for byte, so a
    // terminator gap was a hard-block gap AND a default-deny gap.
    it("keeps the deny-list identical to the critical set", () => {
      // Compare through RegExp on both sides: `RegExp.prototype.source` escapes
      // forward slashes (`/` -> `\/`) so a raw string and the compiled pattern's
      // .source differ textually while being the same regex. Normalizing both
      // through the constructor compares the patterns, not the spelling.
      expect(DEFAULT_BLOCKED_PATTERNS.map((p) => new RegExp(p).source)).toEqual(
        CRITICAL_PATTERNS.map((p) => p.source)
      );
    });

    it("has a deny-list entry matching the operator-suffixed form", () => {
      const matches = DEFAULT_BLOCKED_PATTERNS.some((p) => new RegExp(p, "i").test("rm -rf /;"));
      expect(matches).toBe(true);
    });
  });
});
