import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { KIND_SPECS } from "../src/core/surface/kind-specs.js";
import { UNANALYZED_REASONS } from "../src/core/surface/model.js";

/**
 * Docs-sync guard for `rafter surface diff`.
 *
 * CLI_SPEC.md is the output contract both runtimes implement, so a property kind
 * or an unanalyzed reason that reaches a user without being documented there is a
 * contract gap. This is a repo-level check over shared docs rather than runtime
 * behavior, so it lives only here — mirroring it into pytest would duplicate
 * maintenance without testing anything different.
 */
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CLI_SPEC = fs.readFileSync(path.join(REPO_ROOT, "shared-docs/CLI_SPEC.md"), "utf8");

describe("surface diff docs sync", () => {
  it("documents every property kind in CLI_SPEC.md", () => {
    const undocumented = KIND_SPECS.map((spec) => spec.kind).filter(
      (kind) => !CLI_SPEC.includes(`"${kind}"`),
    );
    expect(undocumented).toEqual([]);
  });

  it("documents every unanalyzed reason in CLI_SPEC.md", () => {
    const undocumented = UNANALYZED_REASONS.filter(
      (reason) => !CLI_SPEC.includes(`"${reason}"`),
    );
    expect(undocumented).toEqual([]);
  });

  it("documents the full exit-code matrix and its precedence", () => {
    expect(CLI_SPEC).toContain("### Attack-Surface Diff (`rafter surface diff`)");
    // Exit 4 is the fail-safe against an author disabling the gate by introducing
    // syntax the parser rejects, so its meaning must stay documented.
    expect(CLI_SPEC).toContain("Inconclusive");
    expect(CLI_SPEC).toContain("**3 > 2 > 4 > 1 > 0**");
  });
});
