/**
 * OpenAI + Supabase secret rules, and the runtime parity they were missing.
 *
 * rf-f5is / se-wagv (external report). The hook's Write gate is regex-only, and
 * secret-patterns.ts had NO OpenAI rule at all — so `sk-proj-` and legacy keys
 * were ALLOWED through the gate at any length, while `rafter secrets` caught
 * them via betterleaks. Two engines, disagreeing, and the one guarding writes
 * was the blind one. `sb_secret_` was caught by neither at any length.
 *
 * Fixtures come from the SHARED rf-f5is-key-fixtures.json so both runtimes
 * assert on byte-identical input; the python twin is
 * python/tests/test_secret_patterns_openai_supabase.py.
 *
 * Keys are ASSEMBLED at runtime rather than stored literally: a file of
 * real-shaped keys in the repo would be flagged by rafter's own scanner — these
 * rules would see to it — and a fixture that trips the product's CI is a
 * fixture someone deletes.
 */
import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { RegexScanner } from "../src/scanners/regex-scanner.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures: Array<{
  label: string; prefix: string; fill: string; len: number; suffix: string; expect: string | null;
}> = JSON.parse(fs.readFileSync(path.resolve(here, "../../rf-f5is-key-fixtures.json"), "utf8"));

const build = (r: (typeof fixtures)[number]) => r.prefix + r.fill.repeat(r.len) + r.suffix;
const names = (ms: any[]) => new Set((ms ?? []).map((m) => m.pattern?.name ?? m.name ?? "?"));

describe("OpenAI + Supabase secret rules (rf-f5is)", () => {
  for (const row of fixtures) {
    it(row.label, () => {
      const found = names(new RegexScanner().scanText(build(row)));
      if (row.expect === null) {
        expect([...found], row.label).toEqual([]);
      } else {
        expect([...found], row.label).toContain(row.expect);
      }
    });
  }

  it("CONTROL — an unrelated rule still fires", () => {
    // Without this, every row above could pass with the scanner broken outright.
    const found = names(new RegexScanner().scanText('GH = "ghp_16CharsMinimumxxxxxxxxxxxxxxxxxxxxxx"'));
    expect([...found]).toContain("GitHub Personal Access Token");
  });

  it("rules are case-sensitive", () => {
    // Matching an uppercased prefix would only add noise; the convention for
    // prefixed vendor tokens here (ghp_, AKIA, AIza, xox) is case-sensitive.
    const found = names(new RegexScanner().scanText('X = "SB_SECRET_' + "A".repeat(32) + '"'));
    expect([...found]).toEqual([]);
  });
});
