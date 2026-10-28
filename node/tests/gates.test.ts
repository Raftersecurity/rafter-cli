import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { GATES_FIXTURE, LEADS_EXPECTED, LEADS_FIXTURE, leadsCapFixture, writeFixture } from "./fixtures/gates-fixture.js";

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
    // `url.startsWith("/")` also accepts //evil.com, so a literal "/" still raises a lead on a URL prefix.
    expect(out.leads.map((l: any) => `${l.file}:${l.line}:${l.rule}`)).toEqual(["web/middleware.js:6:loose-match"]);

    const twin = out.twins.find((t: any) => t.key === "authenticate");
    expect(twin.flagged).toBe(true);
    expect(twin.missing).toEqual(["escape"]);
    const local = twin.members.find((m: any) => m.file === "backends/local.py");
    const ldap = twin.members.find((m: any) => m.file === "backends/ldap.py");
    expect(local.lacks).toEqual(["escape"]);
    expect(local.lacks_calls).toEqual(["escape_filter_chars"]);
    expect(ldap.guards.escape).toEqual(["escape_filter_chars"]);
    expect(twin.confidence).toBe(4); // escape (3) + members in different files (1)
    expect(out.stats.flagged_groups).toBe(1);
  });

  it("prints a text map whose flagged twin names the call it lacks", () => {
    const r = rafter(["gates", root]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("auth/authz.go:3");
    expect(r.stdout).toMatch(/Flagged twin groups[\s\S]*backends\/local\.py:1[^\n]*lacks: escape \(twins call escape_filter_chars\(\); this one does not\)/);
  });

  it("raises each lead rule on its positive line and not on its near miss", () => {
    const tree = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-gates-leads-"));
    try {
      writeFixture(tree, LEADS_FIXTURE);
      const r = rafter(["gates", tree, "--json"]);
      expect(r.exitCode).toBe(0);
      const out = JSON.parse(r.stdout);
      const got = out.leads.map((l: any) => `${l.file}:${l.line}:${l.rule}`).sort();
      expect(got).toEqual([...LEADS_EXPECTED].sort());
      expect(out.stats.leads_found).toBe(LEADS_EXPECTED.length);
      // A twin that only calls its sibling is not missing the sibling's guard.
      const clean = out.twins.find((t: any) => t.key === "cleanpath");
      expect(clean.flagged).toBe(false);
      expect(clean.members.map((m: any) => m.status)).toEqual(["delegates", "checked"]);
    } finally {
      fs.rmSync(tree, { recursive: true, force: true });
    }
  });

  it("caps leads per file and in text, and points to --json for the rest", () => {
    const tree = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-gates-cap-"));
    try {
      writeFixture(tree, leadsCapFixture(10));
      const json = JSON.parse(rafter(["gates", tree, "--json"]).stdout);
      expect(json.stats.leads_found).toBe(30);
      expect(json.leads).toHaveLength(30);
      const text = rafter(["gates", tree]).stdout;
      expect(text.match(/\[tls-verify-off\]/g)).toHaveLength(25);
      expect(text).toContain("... 5 more, use --json");
    } finally {
      fs.rmSync(tree, { recursive: true, force: true });
    }
  });

  it("exits 2 on a missing path or a bad --limit", () => {
    expect(rafter(["gates", path.join(root, "nope")]).exitCode).toBe(2);
    expect(rafter(["gates", root, "--limit", "0"]).exitCode).toBe(2);
  });
});
