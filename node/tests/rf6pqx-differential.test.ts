import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Runs the committed node differential (`rf6pqx-differential.ts`) so that it is
 * actually a gate.
 *
 * It was committed alongside its Python twin, but nothing invoked it: vitest
 * collects `*.test.ts`, and the corpus file is a plain `.ts` script. So the
 * repo had a node differential on disk, a Python differential in a pytest, and
 * only one of them running — which reads, from a file listing, exactly like
 * having both. That is the same shape as the bug the differential exists to
 * catch: a check that is present is not a check that runs.
 *
 * Mirrors python/tests/test_rf6pqx_differential.py, including its rule that an
 * unobtainable baseline FAILS rather than skips. A differential that silently
 * skips is worse than no differential, because the green tick is still there.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "../..");
const candidate = path.resolve(repo, "node/src/core/risk-rules.ts");
const harness = path.resolve(here, "rf6pqx-differential.ts");
const MAIN_PATH = "node/src/core/risk-rules.ts";

function baselineFromMain(): string {
  // `git show` rather than a checkout: the baseline must be main's classifier,
  // not whatever happens to be in the working tree.
  const src = execFileSync("git", ["show", `origin/main:${MAIN_PATH}`], {
    cwd: repo,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  const dir = mkdtempSync(path.join(tmpdir(), "rf6pqx-base-"));
  const file = path.join(dir, "risk-rules.ts");
  writeFileSync(file, src);
  return file;
}

describe("rf-6pqx differential: this branch is never more permissive than main", () => {
  it("obtains main's classifier as the baseline", () => {
    // Asserted separately so a missing baseline reports as a missing baseline
    // rather than as a classifier regression.
    expect(() => baselineFromMain()).not.toThrow();
  });

  it("finds no permissive move outside the allowlisted data-heredoc", () => {
    const base = baselineFromMain();
    let out = "";
    let failed = false;
    try {
      out = execFileSync(
        "npx",
        ["tsx", harness, base, candidate],
        { cwd: path.resolve(repo, "node"), encoding: "utf8", maxBuffer: 32 * 1024 * 1024 },
      );
    } catch (e: any) {
      failed = true;
      out = `${e.stdout ?? ""}${e.stderr ?? ""}`;
    }
    // The harness prints every regression it finds; surface them in the failure
    // rather than making someone re-run it locally to see what broke.
    expect(out, out).toContain("DIFFERENTIAL CLEAN");
    expect(failed, out).toBe(false);
  });
});
