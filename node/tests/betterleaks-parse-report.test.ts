import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { BetterleaksScanner } from "../src/scanners/betterleaks.js";

// parseResults is private; exercise it directly rather than shelling out to the
// real binary, so these stay hermetic and run without betterleaks installed.
const scanner = new BetterleaksScanner();
const parseResults = (scanner as any).parseResults.bind(scanner);

let tmpDir: string;
let stderrSpy: ReturnType<typeof vi.spyOn>;

function writeReport(content: string): string {
  const p = path.join(tmpDir, "report.json");
  fs.writeFileSync(p, content, "utf-8");
  return p;
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bl-parse-test-"));
  stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  stderrSpy.mockRestore();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("BetterleaksScanner.parseResults", () => {
  // #217 — betterleaks >=1.1.2 writes the literal `null` for a clean scan via
  // the `dir`/`git` subcommands. Regression guard: this is an empty result, not
  // a version mismatch, and must not emit warning noise on every clean file.
  it("treats a literal `null` report as an empty result set", () => {
    expect(parseResults(writeReport("null"))).toEqual([]);
  });

  it("does not warn on a `null` report", () => {
    parseResults(writeReport("null"));
    expect(stderrSpy).not.toHaveBeenCalled();
  });

  it("tolerates trailing whitespace around `null`", () => {
    expect(parseResults(writeReport("null\n"))).toEqual([]);
    expect(stderrSpy).not.toHaveBeenCalled();
  });

  it("returns an empty result set for an empty report", () => {
    expect(parseResults(writeReport(""))).toEqual([]);
    expect(stderrSpy).not.toHaveBeenCalled();
  });

  it("returns findings from a normal array report", () => {
    const findings = [{ RuleID: "aws-secret-key", Description: "AWS key", StartLine: 3 }];
    expect(parseResults(writeReport(JSON.stringify(findings)))).toEqual(findings);
    expect(stderrSpy).not.toHaveBeenCalled();
  });

  it("returns an empty result set for an empty array report", () => {
    expect(parseResults(writeReport("[]"))).toEqual([]);
    expect(stderrSpy).not.toHaveBeenCalled();
  });

  // sable-o4k — the stale-binary guard must survive the #217 fix.
  it("still warns about a non-array object report", () => {
    expect(parseResults(writeReport('{"findings": []}'))).toEqual([]);
    expect(stderrSpy).toHaveBeenCalledOnce();
    expect(String(stderrSpy.mock.calls[0][0])).toContain("possible version mismatch");
  });

  it("still warns about malformed JSON", () => {
    expect(parseResults(writeReport("{not json"))).toEqual([]);
    expect(stderrSpy).toHaveBeenCalledOnce();
    expect(String(stderrSpy.mock.calls[0][0])).toContain("Failed to parse");
  });
});
