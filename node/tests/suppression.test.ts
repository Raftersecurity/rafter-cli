import { describe, it, expect } from "vitest";
import { applySuppressions, policyIgnoreToSuppressions, findSuppression, Suppression } from "../src/core/custom-patterns.js";
import { PatternMatch } from "../src/core/pattern-engine.js";

function mkMatch(name: string, severity = "high", line = 1): PatternMatch {
  return {
    pattern: { name, regex: ".*", severity: severity as any },
    match: "secret",
    line,
    column: 1,
    redacted: "***",
  };
}

describe("policyIgnoreToSuppressions", () => {
  it("flattens paths × rules, attaches reason and source", () => {
    const out = policyIgnoreToSuppressions([
      { paths: ["tests/**", "fixtures/**"], rules: ["AWS Access Key"], reason: "fixtures" },
    ]);
    expect(out.length).toBe(2);
    expect(out[0]).toMatchObject({ pathGlob: "tests/**", patternName: "AWS Access Key", reason: "fixtures", source: ".rafter.yml" });
    expect(out[1].pathGlob).toBe("fixtures/**");
  });

  it("omitting rules yields a single suppression covering all rule names", () => {
    const out = policyIgnoreToSuppressions([
      { paths: ["docs/**"], reason: "docs" },
    ]);
    expect(out.length).toBe(1);
    expect(out[0].patternName).toBeUndefined();
  });

  it("returns [] for empty/undefined input", () => {
    expect(policyIgnoreToSuppressions(undefined)).toEqual([]);
    expect(policyIgnoreToSuppressions([])).toEqual([]);
  });
});

describe("findSuppression", () => {
  it("returns first matching suppression — ordering matters", () => {
    const sups: Suppression[] = [
      { pathGlob: "tests/**", patternName: "AWS Access Key", reason: "first", source: ".rafter.yml" },
      { pathGlob: "tests/**", reason: "fallback", source: ".rafter.yml" },
    ];
    const hit = findSuppression("tests/foo.env", "AWS Access Key", sups);
    expect(hit?.reason).toBe("first");
  });

  it("rule-name match is case-insensitive", () => {
    const sups: Suppression[] = [
      { pathGlob: "**/*.env", patternName: "aws access key", source: ".rafter.yml" },
    ];
    expect(findSuppression("foo.env", "AWS Access Key", sups)).not.toBeNull();
  });

  it("non-existent rule name causes no match (harmless)", () => {
    const sups: Suppression[] = [
      { pathGlob: "tests/**", patternName: "Nonexistent Rule", source: ".rafter.yml" },
    ];
    expect(findSuppression("tests/foo.env", "AWS Access Key", sups)).toBeNull();
  });

  it("returns null when no rule matches", () => {
    const sups: Suppression[] = [
      { pathGlob: "src/**", source: ".rafter.yml" },
    ];
    expect(findSuppression("docs/foo.md", "AWS Access Key", sups)).toBeNull();
  });
});

describe("applySuppressions", () => {
  it("returns input unchanged when suppressions are empty", () => {
    const results = [{ file: "a.ts", matches: [mkMatch("AWS Access Key")] }];
    const out = applySuppressions(results, []);
    expect(out.results).toBe(results);
    expect(out.suppressed).toEqual([]);
  });

  it("splits matches into kept + suppressed structures", () => {
    const sups: Suppression[] = [
      { pathGlob: "tests/**", patternName: "AWS Access Key", reason: "fixtures", source: ".rafter.yml" },
    ];
    const results = [
      {
        file: "tests/foo.env",
        matches: [
          mkMatch("AWS Access Key", "critical", 5),
          mkMatch("Generic API Key", "high", 7),
        ],
      },
      {
        file: "src/api.ts",
        matches: [mkMatch("AWS Access Key", "critical", 12)],
      },
    ];
    const out = applySuppressions(results, sups);

    // tests/foo.env keeps Generic API Key, src/api.ts unchanged
    expect(out.results.length).toBe(2);
    expect(out.results[0].matches.length).toBe(1);
    expect(out.results[0].matches[0].pattern.name).toBe("Generic API Key");
    expect(out.results[1].matches[0].pattern.name).toBe("AWS Access Key");

    // One finding suppressed with structured detail
    expect(out.suppressed.length).toBe(1);
    expect(out.suppressed[0]).toMatchObject({
      file: "tests/foo.env",
      line: 5,
      rule: "AWS Access Key",
      severity: "critical",
      reason: "fixtures",
      source: ".rafter.yml",
    });
  });

  it("drops files with all matches suppressed", () => {
    const sups: Suppression[] = [
      { pathGlob: "fixtures/**", reason: "all fixtures", source: ".rafter.yml" },
    ];
    const results = [
      { file: "fixtures/a.env", matches: [mkMatch("AWS Access Key")] },
      { file: "src/x.ts", matches: [mkMatch("Generic API Key")] },
    ];
    const out = applySuppressions(results, sups);
    expect(out.results.map((r) => r.file)).toEqual(["src/x.ts"]);
    expect(out.suppressed.length).toBe(1);
    expect(out.suppressed[0].reason).toBe("all fixtures");
  });

  it("reason is null when source is .rafterignore (no rationale provided)", () => {
    const sups: Suppression[] = [
      { pathGlob: "vendor/**", source: ".rafterignore" },
    ];
    const results = [{ file: "vendor/lib.js", matches: [mkMatch("AWS Access Key")] }];
    const out = applySuppressions(results, sups);
    expect(out.suppressed[0].reason).toBeNull();
    expect(out.suppressed[0].source).toBe(".rafterignore");
  });
});
