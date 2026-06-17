import { describe, it, expect } from "vitest";
import {
  normalizeDiffPath,
  parseUnifiedDiffAddedLines,
  type AddedDiffLine,
} from "../src/utils/git-diff.js";
import { scanAddedDiffLines } from "../src/scanners/git-diff-scan.js";
import { RegexScanner } from "../src/scanners/regex-scanner.js";

describe("normalizeDiffPath", () => {
  it("strips b/ prefix", () => {
    expect(normalizeDiffPath("b/foo/bar.ts")).toBe("foo/bar.ts");
  });

  it("strips a/ prefix", () => {
    expect(normalizeDiffPath("a/foo/bar.ts")).toBe("foo/bar.ts");
  });

  it("normalizes backslashes to forward slashes", () => {
    expect(normalizeDiffPath("b\\src\\app.ts")).toBe("src/app.ts");
  });
});

describe("parseUnifiedDiffAddedLines", () => {
  it("returns empty array for empty patch", () => {
    expect(parseUnifiedDiffAddedLines("")).toEqual([]);
    expect(parseUnifiedDiffAddedLines("   \n  ")).toEqual([]);
  });

  it("extracts added lines with file paths and line numbers", () => {
    const patch = [
      "diff --git a/src/config.ts b/src/config.ts",
      "index abc..def 100644",
      "--- a/src/config.ts",
      "+++ b/src/config.ts",
      "@@ -0,0 +1,2 @@",
      "+const key = 'AKIAIOSFODNN7EXAMPLE';",
      "+export {};",
    ].join("\n");

    expect(parseUnifiedDiffAddedLines(patch)).toEqual([
      { file: "src/config.ts", line: 1, text: "const key = 'AKIAIOSFODNN7EXAMPLE';" },
      { file: "src/config.ts", line: 2, text: "export {};" },
    ]);
  });

  it("parses multiple files in one patch", () => {
    const patch = [
      "diff --git a/a.ts b/a.ts",
      "--- a/a.ts",
      "+++ b/a.ts",
      "@@ -0,0 +1,1 @@",
      "+alpha = 1",
      "diff --git a/b.ts b/b.ts",
      "--- a/b.ts",
      "+++ b/b.ts",
      "@@ -0,0 +1,1 @@",
      "+beta = 2",
    ].join("\n");

    const lines = parseUnifiedDiffAddedLines(patch);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatchObject({ file: "a.ts", line: 1, text: "alpha = 1" });
    expect(lines[1]).toMatchObject({ file: "b.ts", line: 1, text: "beta = 2" });
  });

  it("handles -U0 hunks with modifications as + side only", () => {
    const patch = [
      "diff --git a/app.ts b/app.ts",
      "--- a/app.ts",
      "+++ b/app.ts",
      "@@ -10 +10,2 @@",
      "-const x = 1;",
      "+const x = 2;",
      "+const y = 'ghp_1234567890123456789012345678901234';",
    ].join("\n");

    const lines = parseUnifiedDiffAddedLines(patch);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatchObject({ file: "app.ts", line: 10, text: "const x = 2;" });
    expect(lines[1]).toMatchObject({ file: "app.ts", line: 11 });
  });

  it("ignores deletion lines and does not advance new-file line counter for them", () => {
    const patch = [
      "+++ b/item.ts",
      "@@ -5,3 +5,2 @@",
      "-removed only",
      "-also removed",
      "+kept replacement",
    ].join("\n");

    const lines = parseUnifiedDiffAddedLines(patch);
    expect(lines).toEqual([{ file: "item.ts", line: 5, text: "kept replacement" }]);
  });

  it("ignores context lines but advances the new-file line counter", () => {
    const patch = [
      "+++ b/with-context.ts",
      "@@ -1,3 +1,4 @@",
      " context one",
      "+inserted",
      " context two",
    ].join("\n");

    const lines = parseUnifiedDiffAddedLines(patch);
    expect(lines).toEqual([{ file: "with-context.ts", line: 2, text: "inserted" }]);
  });

  it("tracks line numbers across multiple hunks in the same file", () => {
    const patch = [
      "diff --git a/multi.ts b/multi.ts",
      "--- a/multi.ts",
      "+++ b/multi.ts",
      "@@ -1 +1,2 @@",
      "+top",
      "+more top",
      "@@ -20 +21,1 @@",
      "+bottom",
    ].join("\n");

    const lines = parseUnifiedDiffAddedLines(patch);
    expect(lines.map((l) => l.line)).toEqual([1, 2, 21]);
  });

  it("skips binary files and deletions-only files", () => {
    const patch = [
      "diff --git a/image.png b/image.png",
      "Binary files a/image.png and b/image.png differ",
      "diff --git a/removed.txt b/removed.txt",
      "deleted file mode 100644",
      "--- a/removed.txt",
      "+++ /dev/null",
      "@@ -1 +0,0 @@",
      "-gone",
    ].join("\n");

    expect(parseUnifiedDiffAddedLines(patch)).toEqual([]);
  });

  it("skips \\ No newline at end of file markers", () => {
    const patch = [
      "+++ b/x.ts",
      "@@ -0,0 +1,1 @@",
      "+line without newline",
      "\\ No newline at end of file",
    ].join("\n");

    expect(parseUnifiedDiffAddedLines(patch)).toEqual([
      { file: "x.ts", line: 1, text: "line without newline" },
    ]);
  });

  it("does not treat +++ file headers as added content", () => {
    const patch = ["+++ b/only-header.ts"].join("\n");
    expect(parseUnifiedDiffAddedLines(patch)).toEqual([]);
  });

  it("captures added content whose text starts with '++' (not a header)", () => {
    // Regression: an added line like `++counter` serializes as `+++counter` and
    // `++ spaced` as `+++ spaced` — both must be captured, not dropped/misread
    // as a header, since a secret could live on such a line.
    const patch = [
      "diff --git a/c.ts b/c.ts",
      "--- a/c.ts",
      "+++ b/c.ts",
      "@@ -0,0 +1,2 @@",
      "+++counter AKIAIOSFODNN7EXAMPLE",
      "++ spaced AKIAIOSFODNN7EXAMPLE",
    ].join("\n");
    expect(parseUnifiedDiffAddedLines(patch)).toEqual([
      { file: "c.ts", line: 1, text: "++counter AKIAIOSFODNN7EXAMPLE" },
      { file: "c.ts", line: 2, text: "+ spaced AKIAIOSFODNN7EXAMPLE" },
    ]);
  });

  it("handles CRLF line endings", () => {
    const patch = [
      "diff --git a/w.ts b/w.ts",
      "--- a/w.ts",
      "+++ b/w.ts",
      "@@ -0,0 +1 @@",
      "+const k = 'AKIAIOSFODNN7EXAMPLE';",
    ].join("\r\n");
    expect(parseUnifiedDiffAddedLines(patch)).toEqual([
      { file: "w.ts", line: 1, text: "const k = 'AKIAIOSFODNN7EXAMPLE';" },
    ]);
  });

  it("ignores a rename with no content change", () => {
    const patch = [
      "diff --git a/old.ts b/new.ts",
      "similarity index 100%",
      "rename from old.ts",
      "rename to new.ts",
    ].join("\n");
    expect(parseUnifiedDiffAddedLines(patch)).toEqual([]);
  });

  it("splits only on \\n / \\r\\n, not on bare CR or form-feed (parity)", () => {
    // A form-feed inside added content must stay on the same line — splitting on
    // it (like Python's str.splitlines) would drop the secret tail.
    const patch = [
      "diff --git a/f.ts b/f.ts",
      "--- a/f.ts",
      "+++ b/f.ts",
      "@@ -0,0 +1 @@",
      "+SECRET=\fAKIAIOSFODNN7EXAMPLE",
    ].join("\n");
    expect(parseUnifiedDiffAddedLines(patch)).toEqual([
      { file: "f.ts", line: 1, text: "SECRET=\fAKIAIOSFODNN7EXAMPLE" },
    ]);
  });
});

describe("scanAddedDiffLines", () => {
  it("reports findings with absolute file paths and line numbers", () => {
    const added: AddedDiffLine[] = [
      { file: "secrets.ts", line: 42, text: "const k = 'AKIAIOSFODNN7EXAMPLE';" },
    ];
    const results = scanAddedDiffLines(added, "/repo/root");
    expect(results).toHaveLength(1);
    expect(results[0].file).toBe("/repo/root/secrets.ts");
    expect(results[0].matches[0].line).toBe(42);
    expect(results[0].matches[0].pattern.name).toBe("AWS Access Key ID");
  });

  it("returns empty results when added lines are clean", () => {
    const added: AddedDiffLine[] = [{ file: "clean.ts", line: 1, text: "export const ok = true;" }];
    expect(scanAddedDiffLines(added, "/repo")).toEqual([]);
  });

  it("groups multiple findings in the same file", () => {
    const ghp = "ghp_123456789012345678901234567890123456";
    const added: AddedDiffLine[] = [
      { file: "a.ts", line: 1, text: "const k = 'AKIAIOSFODNN7EXAMPLE';" },
      { file: "a.ts", line: 2, text: `const t = '${ghp}';` },
    ];
    const results = scanAddedDiffLines(added, "/repo");
    expect(results).toHaveLength(1);
    expect(results[0].matches).toHaveLength(2);
  });
});

describe("RegexScanner.scanLine", () => {
  it("assigns the provided line number", () => {
    const scanner = new RegexScanner();
    const ghp = "ghp_123456789012345678901234567890123456";
    const matches = scanner.scanLine(`token = '${ghp}'`, 7);
    expect(matches[0].line).toBe(7);
  });
});
