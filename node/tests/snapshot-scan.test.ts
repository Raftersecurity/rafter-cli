import { describe, it, expect, beforeAll } from "vitest";
import fs from "fs";
import path from "path";
import { RegexScanner, ScanResult } from "../src/scanners/regex-scanner.js";

const FIXTURES_DIR = path.join(__dirname, "snapshots", "fixtures");
const GOLDEN_DIR = path.join(__dirname, "snapshots", "golden");
const UPDATE = process.env.UPDATE_SNAPSHOTS === "1";

/**
 * Normalize a ScanResult for snapshot comparison:
 * - Replace absolute fixture paths with relative filenames
 * - Strip the `regex` field from patterns (implementation detail, not output contract)
 * - Sort matches deterministically by line, then column, then pattern name
 */
function normalize(result: ScanResult): object {
  return {
    file: path.basename(result.file),
    matches: result.matches
      .map((m) => ({
        pattern: {
          name: m.pattern.name,
          severity: m.pattern.severity,
        },
        line: m.line ?? null,
        column: m.column ?? null,
        redacted: m.redacted ?? null,
      }))
      .sort((a, b) => {
        if ((a.line ?? 0) !== (b.line ?? 0)) return (a.line ?? 0) - (b.line ?? 0);
        if ((a.column ?? 0) !== (b.column ?? 0)) return (a.column ?? 0) - (b.column ?? 0);
        return a.pattern.name.localeCompare(b.pattern.name);
      }),
  };
}

function normalizeResults(results: ScanResult[]): object[] {
  return results
    .map(normalize)
    .sort((a: any, b: any) => a.file.localeCompare(b.file));
}

function readGolden(name: string): object | object[] {
  const filePath = path.join(GOLDEN_DIR, name);
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

function writeGolden(name: string, data: object | object[]): void {
  fs.mkdirSync(GOLDEN_DIR, { recursive: true });
  fs.writeFileSync(
    path.join(GOLDEN_DIR, name),
    JSON.stringify(data, null, 2) + "\n"
  );
}

describe("Snapshot/Golden File Tests", () => {
  let scanner: RegexScanner;

  beforeAll(() => {
    scanner = new RegexScanner();
  });

  describe("single file scans", () => {
    const cases = [
      { fixture: "aws-keys.txt", golden: "aws-keys.json" },
      { fixture: "multi-pattern.py", golden: "multi-pattern.json" },
      { fixture: "mixed-severity.js", golden: "mixed-severity.json" },
      { fixture: "clean-file.txt", golden: "clean-file.json" },
      { fixture: "database-urls.env", golden: "database-urls.json" },
    ];

    for (const { fixture, golden } of cases) {
      it(`matches golden file for ${fixture}`, () => {
        const fixturePath = path.join(FIXTURES_DIR, fixture);
        const result = scanner.scanFile(fixturePath);
        const normalized = normalize(result);

        if (UPDATE) {
          writeGolden(golden, normalized);
          return;
        }

        const expected = readGolden(golden);
        expect(normalized).toEqual(expected);
      });
    }
  });

  describe("directory scan", () => {
    it("matches golden file for full directory scan", () => {
      const results = scanner.scanDirectory(FIXTURES_DIR);
      const normalized = normalizeResults(results);

      if (UPDATE) {
        writeGolden("directory-scan.json", normalized);
        return;
      }

      const expected = readGolden("directory-scan.json");
      expect(normalized).toEqual(expected);
    });
  });

  describe("redaction accuracy", () => {
    it("matches golden file for redaction samples", () => {
      const samples = [
        { input: "AKIAIOSFODNN7EXAMPLE", label: "aws-key-20char" },
        { input: "ghp_FAKEEFGHIJKLMNOPQRSTUVWXYZ0123456789", label: "github-pat-40char" },
        { input: "sk_l1ve_abcdefghijklmnopqrstuvwx", label: "stripe-30char" },
        { input: "xoxb-12", label: "short-token-7char" },
      ];

      const normalized = samples.map((s) => ({
        label: s.label,
        input_length: s.input.length,
        redacted: scanner.redact(s.input),
      }));

      if (UPDATE) {
        writeGolden("redaction-samples.json", normalized);
        return;
      }

      const expected = readGolden("redaction-samples.json");
      expect(normalized).toEqual(expected);
    });
  });

  describe("position accuracy", () => {
    it("matches golden file for line and column positions", () => {
      const fixturePath = path.join(FIXTURES_DIR, "multi-pattern.py");
      const result = scanner.scanFile(fixturePath);
      const positions = result.matches.map((m) => ({
        pattern: m.pattern.name,
        line: m.line,
        column: m.column,
      })).sort((a, b) => {
        if ((a.line ?? 0) !== (b.line ?? 0)) return (a.line ?? 0) - (b.line ?? 0);
        return a.pattern.localeCompare(b.pattern);
      });

      if (UPDATE) {
        writeGolden("positions-multi-pattern.json", positions);
        return;
      }

      const expected = readGolden("positions-multi-pattern.json");
      expect(positions).toEqual(expected);
    });
  });
});
