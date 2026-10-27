import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { GATES_FIXTURE, writeFixture } from "./fixtures/gates-fixture.js";

/**
 * `rafter gates` end to end: a small multi-language tree with gates, a
 * non-gate, files that must be skipped, and a twin pair where one member
 * lacks the escape call the other makes. Mirrors python/tests/test_gates.py.
 */

const CLI = path.resolve(__dirname, "../dist/index.js");

function rafter(args: string[]) {
  const r = spawnSync("node", [CLI, ...args], { encoding: "utf-8", timeout: 15000 });
  return { stdout: r.stdout || "", stderr: r.stderr || "", exitCode: r.status ?? 1 };
}

describe("rafter gates", () => {
  let root: string;

  beforeAll(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-gates-"));
    writeFixture(root, GATES_FIXTURE);
  });

  afterAll(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("finds the gates, skips test and vendored files, and flags the twin that lacks escaping", () => {
    const r = rafter(["gates", root, "--json"]);
    expect(r.exitCode).toBe(0);
    const out = JSON.parse(r.stdout);

    const found = out.gates.map((g: any) => `${g.file}:${g.name}`).sort();
    expect(found).toEqual([
      "auth/authz.go:Authorize",
      "backends/ldap.py:authenticate",
      "backends/local.py:authenticate",
      "web/middleware.js:isSafeRedirect",
      "web/middleware.js:requireAdmin",
    ]);
    expect(out.stats.files_scanned).toBe(4);

    const twin = out.twins.find((t: any) => t.key === "authenticate");
    expect(twin.flagged).toBe(true);
    expect(twin.missing).toEqual(["escape"]);
    const local = twin.members.find((m: any) => m.file === "backends/local.py");
    const ldap = twin.members.find((m: any) => m.file === "backends/ldap.py");
    expect(local.lacks).toEqual(["escape"]);
    expect(ldap.guards.escape).toEqual(["escape_filter_chars"]);
    expect(out.stats.flagged_groups).toBe(1);
  });

  it("prints a text map with the flagged twin", () => {
    const r = rafter(["gates", root]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("auth/authz.go:3");
    expect(r.stdout).toMatch(/Flagged twin groups[\s\S]*backends\/local\.py:1[^\n]*lacks: escape/);
  });

  it("exits 2 on a missing path or a bad --limit", () => {
    expect(rafter(["gates", path.join(root, "nope")]).exitCode).toBe(2);
    expect(rafter(["gates", root, "--limit", "0"]).exitCode).toBe(2);
  });
});
