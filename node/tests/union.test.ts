import { describe, it, expect } from "vitest";
import { unionScanResults } from "../src/scanners/union.js";
import { ScanResult } from "../src/scanners/regex-scanner.js";
import { applySuppressions } from "../src/core/custom-patterns.js";

// sable-j85 — auto mode unions betterleaks + patterns findings. These cover the
// dedup key (file, line, matched-text), the engine attribution, and ordering.

function match(name: string, m: string, line: number, column?: number) {
  return { pattern: { name, regex: "", severity: "high" as const }, match: m, line, column, redacted: m };
}

describe("unionScanResults (sable-j85)", () => {
  it("keeps engine-unique findings and attributes each", () => {
    const bl: ScanResult[] = [{ file: "a.env", matches: [match("private-key", "KEY", 2)] }];
    const pat: ScanResult[] = [{ file: "b.txt", matches: [match("AWS Access Key ID", "AKIA...", 1)] }];

    const out = unionScanResults(bl, pat);

    expect(out).toHaveLength(2);
    expect(out[0].file).toBe("a.env");
    expect(out[0].matches[0].engines).toEqual(["betterleaks"]);
    expect(out[1].file).toBe("b.txt");
    expect(out[1].matches[0].engines).toEqual(["patterns"]);
  });

  it("dedups a secret both engines report and keeps the betterleaks match", () => {
    const bl: ScanResult[] = [{ file: "a.env", matches: [match("private-key", "SAME", 5)] }];
    const pat: ScanResult[] = [{ file: "a.env", matches: [match("Private Key", "SAME", 5)] }];

    const out = unionScanResults(bl, pat);

    expect(out).toHaveLength(1);
    expect(out[0].matches).toHaveLength(1);
    // betterleaks rule-id format wins.
    expect(out[0].matches[0].pattern.name).toBe("private-key");
    expect(out[0].matches[0].engines).toEqual(["betterleaks", "patterns"]);
  });

  it("does NOT dedup same text on different lines", () => {
    const bl: ScanResult[] = [{ file: "a.env", matches: [match("k", "DUP", 1)] }];
    const pat: ScanResult[] = [{ file: "a.env", matches: [match("k", "DUP", 2)] }];

    const out = unionScanResults(bl, pat);

    expect(out[0].matches).toHaveLength(2);
  });

  it("does NOT dedup same text+line at different columns (distinct secrets)", () => {
    // e.g. `K1=AKIA... K2=AKIA...` — same token pasted twice on one line.
    const bl: ScanResult[] = [{ file: "a.env", matches: [match("k", "AKIA", 1, 4)] }];
    const pat: ScanResult[] = [{ file: "a.env", matches: [match("k", "AKIA", 1, 20)] }];

    const out = unionScanResults(bl, pat);

    expect(out[0].matches).toHaveLength(2);
  });

  it("dedups one secret both engines start at the same position, despite different extracted text", () => {
    // betterleaks extracts a whole PEM block; the regex pattern only its header.
    const bl: ScanResult[] = [{ file: "k.pem", matches: [match("private-key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE", 3, 5)] }];
    const pat: ScanResult[] = [{ file: "k.pem", matches: [match("Private Key", "-----BEGIN RSA PRIVATE KEY-----", 3, 5)] }];

    const out = unionScanResults(bl, pat);

    expect(out[0].matches).toHaveLength(1);
    expect(out[0].matches[0].engines).toEqual(["betterleaks", "patterns"]);
  });

  it("merges into one file group, betterleaks findings first", () => {
    const bl: ScanResult[] = [{ file: "a.env", matches: [match("bl-only", "X", 1)] }];
    const pat: ScanResult[] = [{ file: "a.env", matches: [match("pat-only", "Y", 2)] }];

    const out = unionScanResults(bl, pat);

    expect(out).toHaveLength(1);
    expect(out[0].matches.map((m) => m.pattern.name)).toEqual(["bl-only", "pat-only"]);
  });

  // A merged finding keeps only the betterleaks rule name for display, so a
  // suppression scoped to that rule must not also hide what patterns found.
  it("suppresses a merged finding only when every engine's rule is suppressed", () => {
    const merged = unionScanResults(
      [{ file: "a.env", matches: [match("aws-access-token", "AKIA1", 1, 9)] }],
      [{ file: "a.env", matches: [match("AWS Access Key ID", "AKIA1", 1, 9)] }],
    );
    const rule = (patternName: string) => ({ pathGlob: "**", patternName, source: ".rafter.yml" as const });

    const one = applySuppressions(merged, [rule("aws-access-token")]);
    expect(one.suppressed).toEqual([]);
    expect(one.results[0].matches).toHaveLength(1);

    const both = applySuppressions(merged, [rule("aws-access-token"), rule("AWS Access Key ID")]);
    expect(both.results).toEqual([]);
    expect(both.suppressed).toHaveLength(1);
  });

  it("returns empty when neither engine finds anything", () => {
    expect(unionScanResults([], [])).toEqual([]);
  });
});
