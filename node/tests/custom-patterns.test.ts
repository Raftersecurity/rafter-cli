import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * Tests for custom pattern loading from ~/.rafter/patterns/,
 * .rafterignore suppression, and their interaction with the scanner.
 *
 * NOTE: We test the exported functions directly (loadCustomPatterns,
 * loadSuppressions, isSuppressed) and integration through RegexScanner.
 */

import {
  loadCustomPatterns,
  loadSuppressions,
  isSuppressed,
  Suppression,
} from "../src/core/custom-patterns.js";

// We mock getRafterDir so loadCustomPatterns reads from our tmp dir
vi.mock("../src/core/config-defaults.js", () => ({
  getRafterDir: () => (globalThis as any).__TEST_RAFTER_DIR__ ?? "/nonexistent",
}));

describe("Custom pattern loading", () => {
  let rafterDir: string;

  beforeEach(() => {
    rafterDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-cp-"));
    (globalThis as any).__TEST_RAFTER_DIR__ = rafterDir;
  });

  afterEach(() => {
    fs.rmSync(rafterDir, { recursive: true, force: true });
    delete (globalThis as any).__TEST_RAFTER_DIR__;
  });

  // ── .txt patterns ──────────────────────────────────────────────────

  describe(".txt pattern files", () => {
    it("loads one regex per line", () => {
      const pDir = path.join(rafterDir, "patterns");
      fs.mkdirSync(pDir, { recursive: true });
      fs.writeFileSync(
        path.join(pDir, "internal.txt"),
        "INTERNAL_[A-Z0-9]{32}\nCOMPANY_SECRET_[a-z]{16}\n"
      );

      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(2);
      expect(patterns[0].name).toBe("Custom (internal)");
      expect(patterns[0].regex).toBe("INTERNAL_[A-Z0-9]{32}");
      expect(patterns[0].severity).toBe("high");
      expect(patterns[1].regex).toBe("COMPANY_SECRET_[a-z]{16}");
    });

    it("ignores comments and blank lines", () => {
      const pDir = path.join(rafterDir, "patterns");
      fs.mkdirSync(pDir, { recursive: true });
      fs.writeFileSync(
        path.join(pDir, "sparse.txt"),
        "# comment\n\nACTUAL_PATTERN_[0-9]+\n  \n# another comment\n"
      );

      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(1);
      expect(patterns[0].regex).toBe("ACTUAL_PATTERN_[0-9]+");
    });
  });

  // ── .json patterns ─────────────────────────────────────────────────

  describe(".json pattern files", () => {
    it("loads array of pattern objects", () => {
      const pDir = path.join(rafterDir, "patterns");
      fs.mkdirSync(pDir, { recursive: true });
      fs.writeFileSync(
        path.join(pDir, "custom.json"),
        JSON.stringify([
          {
            name: "Internal API Key",
            pattern: "INTERNAL_[A-Z0-9]{32}",
            severity: "critical",
            description: "Internal API key",
          },
        ])
      );

      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(1);
      expect(patterns[0].name).toBe("Internal API Key");
      expect(patterns[0].regex).toBe("INTERNAL_[A-Z0-9]{32}");
      expect(patterns[0].severity).toBe("critical");
      expect(patterns[0].description).toBe("Internal API key");
    });

    it("defaults name from filename when missing", () => {
      const pDir = path.join(rafterDir, "patterns");
      fs.mkdirSync(pDir, { recursive: true });
      fs.writeFileSync(
        path.join(pDir, "mypatterns.json"),
        JSON.stringify([{ pattern: "FOO_[0-9]+" }])
      );

      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(1);
      expect(patterns[0].name).toBe("Custom (mypatterns)");
    });

    it("defaults severity to high when missing", () => {
      const pDir = path.join(rafterDir, "patterns");
      fs.mkdirSync(pDir, { recursive: true });
      fs.writeFileSync(
        path.join(pDir, "x.json"),
        JSON.stringify([{ name: "Test", pattern: "TEST_[0-9]+" }])
      );

      const patterns = loadCustomPatterns();
      expect(patterns[0].severity).toBe("high");
    });

    it("skips invalid regex with warning", () => {
      const pDir = path.join(rafterDir, "patterns");
      fs.mkdirSync(pDir, { recursive: true });
      fs.writeFileSync(
        path.join(pDir, "bad.json"),
        JSON.stringify([
          { name: "Bad", pattern: "[invalid(" },
          { name: "Good", pattern: "GOOD_[0-9]+" },
        ])
      );

      const spy = vi.spyOn(console, "error").mockImplementation(() => {});
      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(1);
      expect(patterns[0].name).toBe("Good");
      expect(spy).toHaveBeenCalledWith(
        expect.stringContaining("invalid regex")
      );
      spy.mockRestore();
    });

    it("skips invalid severity with warning", () => {
      const pDir = path.join(rafterDir, "patterns");
      fs.mkdirSync(pDir, { recursive: true });
      fs.writeFileSync(
        path.join(pDir, "sev.json"),
        JSON.stringify([
          { name: "Bad Sev", pattern: "BAD_[0-9]+", severity: "extreme" },
          { name: "Good Sev", pattern: "GOOD_[0-9]+", severity: "low" },
        ])
      );

      const spy = vi.spyOn(console, "error").mockImplementation(() => {});
      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(1);
      expect(patterns[0].name).toBe("Good Sev");
      expect(spy).toHaveBeenCalledWith(
        expect.stringContaining("invalid severity")
      );
      spy.mockRestore();
    });

    it("skips entries with missing/empty pattern field", () => {
      const pDir = path.join(rafterDir, "patterns");
      fs.mkdirSync(pDir, { recursive: true });
      fs.writeFileSync(
        path.join(pDir, "missing.json"),
        JSON.stringify([
          { name: "No pattern" },
          { name: "Empty pattern", pattern: "" },
          { name: "Valid", pattern: "OK_[0-9]+" },
        ])
      );

      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(1);
      expect(patterns[0].name).toBe("Valid");
    });

    it("returns empty for non-array JSON", () => {
      const pDir = path.join(rafterDir, "patterns");
      fs.mkdirSync(pDir, { recursive: true });
      fs.writeFileSync(path.join(pDir, "obj.json"), '{"not": "array"}');

      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(0);
    });
  });

  // ── Edge cases ─────────────────────────────────────────────────────

  describe("edge cases", () => {
    it("returns empty when patterns directory does not exist", () => {
      // rafterDir exists but no patterns/ subdir
      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(0);
    });

    it("returns empty when patterns directory is empty", () => {
      fs.mkdirSync(path.join(rafterDir, "patterns"), { recursive: true });
      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(0);
    });

    it("ignores non-.txt/.json files", () => {
      const pDir = path.join(rafterDir, "patterns");
      fs.mkdirSync(pDir, { recursive: true });
      fs.writeFileSync(path.join(pDir, "readme.md"), "PATTERN_[0-9]+");
      fs.writeFileSync(path.join(pDir, "data.yaml"), "pattern: STUFF_[0-9]+");

      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(0);
    });

    it("ignores subdirectories in patterns dir", () => {
      const pDir = path.join(rafterDir, "patterns");
      fs.mkdirSync(path.join(pDir, "subdir"), { recursive: true });

      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(0);
    });

    it("loads from both .txt and .json files", () => {
      const pDir = path.join(rafterDir, "patterns");
      fs.mkdirSync(pDir, { recursive: true });
      fs.writeFileSync(path.join(pDir, "a.txt"), "TXT_PAT_[0-9]+\n");
      fs.writeFileSync(
        path.join(pDir, "b.json"),
        JSON.stringify([{ name: "JSON Pat", pattern: "JSON_PAT_[0-9]+" }])
      );

      const patterns = loadCustomPatterns();
      expect(patterns).toHaveLength(2);
      const names = patterns.map((p) => p.name);
      expect(names).toContain("Custom (a)");
      expect(names).toContain("JSON Pat");
    });
  });
});

// ══════════════════════════════════════════════════════════════════════
// .rafterignore suppression
// ══════════════════════════════════════════════════════════════════════

describe(".rafterignore loading", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-ign-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("parses path-only suppressions", () => {
    fs.writeFileSync(path.join(tmpDir, ".rafterignore"), "node_modules/\ntest/fixtures/\n");
    const suppressions = loadSuppressions(tmpDir);
    expect(suppressions).toHaveLength(2);
    expect(suppressions[0]).toEqual({ pathGlob: "node_modules/", patternName: undefined });
    expect(suppressions[1]).toEqual({ pathGlob: "test/fixtures/", patternName: undefined });
  });

  it("parses pattern-specific suppressions", () => {
    fs.writeFileSync(
      path.join(tmpDir, ".rafterignore"),
      ".env:AWS Access Key ID\nvendor/**:Generic API Key\n"
    );
    const suppressions = loadSuppressions(tmpDir);
    expect(suppressions).toHaveLength(2);
    expect(suppressions[0]).toEqual({
      pathGlob: ".env",
      patternName: "AWS Access Key ID",
    });
    expect(suppressions[1]).toEqual({
      pathGlob: "vendor/**",
      patternName: "Generic API Key",
    });
  });

  it("ignores comments and blank lines", () => {
    fs.writeFileSync(
      path.join(tmpDir, ".rafterignore"),
      "# This is a comment\n\ntest/\n  \n# Another comment\n"
    );
    const suppressions = loadSuppressions(tmpDir);
    expect(suppressions).toHaveLength(1);
    expect(suppressions[0].pathGlob).toBe("test/");
  });

  it("returns empty when .rafterignore does not exist", () => {
    const suppressions = loadSuppressions(tmpDir);
    expect(suppressions).toHaveLength(0);
  });

  it("returns empty for empty .rafterignore", () => {
    fs.writeFileSync(path.join(tmpDir, ".rafterignore"), "");
    const suppressions = loadSuppressions(tmpDir);
    expect(suppressions).toHaveLength(0);
  });

  it("handles wildcard pattern: vendor/**:*", () => {
    fs.writeFileSync(path.join(tmpDir, ".rafterignore"), "vendor/**:*\n");
    const suppressions = loadSuppressions(tmpDir);
    expect(suppressions).toHaveLength(1);
    expect(suppressions[0]).toEqual({ pathGlob: "vendor/**", patternName: "*" });
  });
});

// ══════════════════════════════════════════════════════════════════════
// isSuppressed logic
// ══════════════════════════════════════════════════════════════════════

describe("isSuppressed", () => {
  it("suppresses all patterns when no pattern name specified", () => {
    const suppressions: Suppression[] = [{ pathGlob: "node_modules/**" }];
    expect(isSuppressed("node_modules/pkg/index.js", "AWS Access Key ID", suppressions)).toBe(true);
    expect(isSuppressed("node_modules/pkg/index.js", "Generic Secret", suppressions)).toBe(true);
  });

  it("suppresses only matching pattern name", () => {
    const suppressions: Suppression[] = [
      { pathGlob: ".env", patternName: "AWS Access Key ID" },
    ];
    expect(isSuppressed(".env", "AWS Access Key ID", suppressions)).toBe(true);
    expect(isSuppressed(".env", "Generic Secret", suppressions)).toBe(false);
  });

  it("does case-insensitive pattern name matching", () => {
    const suppressions: Suppression[] = [
      { pathGlob: "*.env", patternName: "aws access key id" },
    ];
    expect(isSuppressed("config/.env", "AWS Access Key ID", suppressions)).toBe(true);
    expect(isSuppressed("config/.env", "aws access key id", suppressions)).toBe(true);
  });

  it("does not suppress non-matching paths", () => {
    const suppressions: Suppression[] = [{ pathGlob: "vendor/**" }];
    expect(isSuppressed("src/main.ts", "Generic Secret", suppressions)).toBe(false);
  });

  it("basename matching: *.test.ts matches test files in any directory", () => {
    const suppressions: Suppression[] = [{ pathGlob: "*.test.ts" }];
    expect(isSuppressed("src/utils/auth.test.ts", "Generic Secret", suppressions)).toBe(true);
    expect(isSuppressed("auth.test.ts", "Generic Secret", suppressions)).toBe(true);
  });

  it("returns false when suppressions list is empty", () => {
    expect(isSuppressed("anything.ts", "Any Pattern", [])).toBe(false);
  });
});

// ══════════════════════════════════════════════════════════════════════
// Integration: custom patterns in RegexScanner constructor
// ══════════════════════════════════════════════════════════════════════

describe("Custom patterns from .rafter.yml (via constructor)", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-int-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("custom pattern name appears in scan results", async () => {
    // Dynamic import to get fresh module after mock is set up
    const { RegexScanner } = await import("../src/scanners/regex-scanner.js");
    const scanner = new RegexScanner([
      { name: "Internal Token", regex: "INTERNAL_TK_[A-Z0-9]{20}", severity: "critical" },
    ]);

    const f = path.join(tmpDir, "config.txt");
    fs.writeFileSync(f, "token = INTERNAL_TK_ABCDEFGHIJ0123456789\n");
    const result = scanner.scanFile(f);
    expect(result.matches.some((m) => m.pattern.name === "Internal Token")).toBe(true);
  });

  it("custom pattern severity is respected", async () => {
    const { RegexScanner } = await import("../src/scanners/regex-scanner.js");
    const scanner = new RegexScanner([
      { name: "Low Risk Token", regex: "LOW_RISK_[A-Z]{10}", severity: "low" },
    ]);

    const f = path.join(tmpDir, "test.txt");
    fs.writeFileSync(f, "LOW_RISK_ABCDEFGHIJ\n");
    const result = scanner.scanFile(f);
    const match = result.matches.find((m) => m.pattern.name === "Low Risk Token");
    expect(match).toBeDefined();
    expect(match!.pattern.severity).toBe("low");
  });

  it("custom pattern missing optional description works", async () => {
    const { RegexScanner } = await import("../src/scanners/regex-scanner.js");
    const scanner = new RegexScanner([
      { name: "No Desc", regex: "NODESC_[0-9]{8}", severity: "medium" },
    ]);

    const f = path.join(tmpDir, "file.txt");
    fs.writeFileSync(f, "NODESC_12345678\n");
    const result = scanner.scanFile(f);
    expect(result.matches.some((m) => m.pattern.name === "No Desc")).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════
// Interaction tests: custom patterns + .rafterignore
// ══════════════════════════════════════════════════════════════════════

describe("Interaction: custom patterns + .rafterignore", () => {
  it("custom pattern found in ignored file is suppressed", () => {
    const suppressions: Suppression[] = [{ pathGlob: "test/fixtures/**" }];
    // Custom pattern match in an ignored path
    expect(isSuppressed("test/fixtures/secrets.txt", "Custom (internal)", suppressions)).toBe(true);
  });

  it("custom pattern NOT in .rafterignore is reported", () => {
    const suppressions: Suppression[] = [{ pathGlob: "test/fixtures/**" }];
    // Custom pattern match in a non-ignored path
    expect(isSuppressed("src/config.ts", "Custom (internal)", suppressions)).toBe(false);
  });

  it("built-in pattern in .rafterignore is suppressed", () => {
    const suppressions: Suppression[] = [
      { pathGlob: "*.env", patternName: "AWS Access Key ID" },
    ];
    expect(isSuppressed("config/.env", "AWS Access Key ID", suppressions)).toBe(true);
  });

  it("built-in pattern NOT in .rafterignore is reported", () => {
    const suppressions: Suppression[] = [
      { pathGlob: "*.env", patternName: "AWS Access Key ID" },
    ];
    // Different pattern, same file
    expect(isSuppressed("config/.env", "Generic Secret", suppressions)).toBe(false);
    // Same pattern, different file
    expect(isSuppressed("src/main.ts", "AWS Access Key ID", suppressions)).toBe(false);
  });
});
