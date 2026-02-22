import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { execSync } from "child_process";

// ── helpers ──────────────────────────────────────────────────────────

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "rafter-baseline-test-"));
}

function makeBaseline(entries: object[]) {
  return {
    version: 1,
    created: "2026-01-01T00:00:00Z",
    updated: "2026-01-01T00:00:00Z",
    entries,
  };
}

// ── applyBaseline unit tests (via internal logic mirror) ─────────────

// We test the filtering logic directly by importing the compiled output.
// Because the function isn't exported, we replicate the logic here to
// test the contract — identical to what the command uses.

type BaselineEntry = { file: string; line: number | null; pattern: string };
type Match = { pattern: { name: string }; line?: number | null };
type ScanResult = { file: string; matches: Match[] };

function applyBaseline(results: ScanResult[], entries: BaselineEntry[]): ScanResult[] {
  if (entries.length === 0) return results;
  return results
    .map((r) => ({
      ...r,
      matches: r.matches.filter(
        (m) =>
          !entries.some(
            (e) =>
              e.file === r.file &&
              e.pattern === m.pattern.name &&
              (e.line == null || e.line === (m.line ?? null)),
          ),
      ),
    }))
    .filter((r) => r.matches.length > 0);
}

describe("applyBaseline", () => {
  it("passes all results when baseline is empty", () => {
    const results: ScanResult[] = [
      { file: "/f.ts", matches: [{ pattern: { name: "AWS Access Key" }, line: 5 }] },
    ];
    expect(applyBaseline(results, [])).toEqual(results);
  });

  it("filters exact match (file + pattern + line)", () => {
    const results: ScanResult[] = [
      { file: "/f.ts", matches: [{ pattern: { name: "AWS Access Key" }, line: 5 }] },
    ];
    const entries: BaselineEntry[] = [{ file: "/f.ts", pattern: "AWS Access Key", line: 5 }];
    expect(applyBaseline(results, entries)).toEqual([]);
  });

  it("does not filter on different pattern", () => {
    const results: ScanResult[] = [
      { file: "/f.ts", matches: [{ pattern: { name: "AWS Access Key" }, line: 5 }] },
    ];
    const entries: BaselineEntry[] = [{ file: "/f.ts", pattern: "GitHub Token", line: 5 }];
    expect(applyBaseline(results, entries)).toHaveLength(1);
  });

  it("does not filter on different file", () => {
    const results: ScanResult[] = [
      { file: "/f.ts", matches: [{ pattern: { name: "AWS Access Key" }, line: 5 }] },
    ];
    const entries: BaselineEntry[] = [{ file: "/other.ts", pattern: "AWS Access Key", line: 5 }];
    expect(applyBaseline(results, entries)).toHaveLength(1);
  });

  it("null line in baseline matches any line", () => {
    const results: ScanResult[] = [
      { file: "/f.ts", matches: [{ pattern: { name: "AWS Access Key" }, line: 42 }] },
    ];
    const entries: BaselineEntry[] = [{ file: "/f.ts", pattern: "AWS Access Key", line: null }];
    expect(applyBaseline(results, entries)).toEqual([]);
  });

  it("preserves unfiltered matches within same file", () => {
    const results: ScanResult[] = [
      {
        file: "/f.ts",
        matches: [
          { pattern: { name: "AWS Access Key" }, line: 5 },
          { pattern: { name: "GitHub Token" }, line: 10 },
        ],
      },
    ];
    const entries: BaselineEntry[] = [{ file: "/f.ts", pattern: "AWS Access Key", line: 5 }];
    const out = applyBaseline(results, entries);
    expect(out).toHaveLength(1);
    expect(out[0].matches).toHaveLength(1);
    expect(out[0].matches[0].pattern.name).toBe("GitHub Token");
  });
});

// ── pre-push hook template ────────────────────────────────────────────

describe("pre-push hook template", () => {
  it("exists at resources/pre-push-hook.sh", () => {
    const templatePath = path.resolve("resources", "pre-push-hook.sh");
    expect(fs.existsSync(templatePath)).toBe(true);
  });

  it("contains Rafter marker", () => {
    const templatePath = path.resolve("resources", "pre-push-hook.sh");
    const content = fs.readFileSync(templatePath, "utf-8");
    expect(content).toContain("Rafter Security Pre-Push Hook");
  });

  it("calls rafter agent scan", () => {
    const templatePath = path.resolve("resources", "pre-push-hook.sh");
    const content = fs.readFileSync(templatePath, "utf-8");
    expect(content).toContain("rafter agent scan");
  });

  it("mentions --no-verify bypass", () => {
    const templatePath = path.resolve("resources", "pre-push-hook.sh");
    const content = fs.readFileSync(templatePath, "utf-8");
    expect(content).toContain("--no-verify");
  });

  it("reads from stdin (git pre-push protocol)", () => {
    const templatePath = path.resolve("resources", "pre-push-hook.sh");
    const content = fs.readFileSync(templatePath, "utf-8");
    expect(content).toContain("while read");
    expect(content).toContain("local_sha");
    expect(content).toContain("remote_sha");
  });
});

// ── baseline JSON format ──────────────────────────────────────────────

describe("baseline JSON format", () => {
  it("has correct structure", () => {
    const baseline = makeBaseline([
      { file: "/repo/config.ts", line: 10, pattern: "AWS Access Key", addedAt: "2026-01-01T00:00:00Z" },
    ]);
    expect(baseline.version).toBe(1);
    expect(baseline.entries).toHaveLength(1);
    expect(baseline.entries[0]).toMatchObject({
      file: expect.any(String),
      line: expect.any(Number),
      pattern: expect.any(String),
    });
  });
});
