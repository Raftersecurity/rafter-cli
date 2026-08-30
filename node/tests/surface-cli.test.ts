import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync, spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * `rafter surface diff` CLI contract (§6, §9.1, §9.2) — the full exit-code
 * matrix, its precedence, stream discipline, and the three text outcomes that
 * must never read alike.
 *
 * Real temp git repos, CLI invoked as a subprocess. Properties come from the
 * W4 stub extractor (`*.surface-stub.json`), so these tests exercise the shell
 * without waiting on the Wave 2 extractors.
 */

const CLI = path.resolve(__dirname, "../dist/index.js");

function rafter(
  args: string[],
  opts?: { cwd?: string },
): { stdout: string; stderr: string; exitCode: number } {
  // spawnSync, not execFileSync: stderr must be captured on success too, since
  // "every status message goes to stderr" is exactly what these tests check.
  const result = spawnSync("node", [CLI, ...args], { encoding: "utf-8", cwd: opts?.cwd });
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    exitCode: result.status ?? 1,
  };
}

function git(repo: string, args: string[]): void {
  execFileSync("git", args, { cwd: repo, stdio: "ignore" });
}

interface StubProperty {
  kind: string;
  key: string;
  subject: string;
  label: string;
  levels: Record<string, string | null>;
  line?: number;
}

function port(key: string, binding: string, label = `port ${key}`): StubProperty {
  return {
    kind: "container.port",
    key: `container.port:compose:${key}`,
    subject: `service ${key}`,
    label,
    levels: { binding },
    line: 3,
  };
}

function iam(key: string, resource: string, action = "literal"): StubProperty {
  return {
    kind: "iam.allow",
    key: `iam.allow:iam-json:${key}`,
    subject: `statement ${key}`,
    label: `Allow s3:GetObject on ${resource}`,
    levels: {
      action,
      resource,
      principal: "absent-or-literal",
      condition: "present",
    },
    line: 18,
  };
}

function writeStub(
  repo: string,
  file: string,
  properties: StubProperty[],
  unanalyzed: Array<{ reason: string; detail: string }> = [],
): void {
  fs.writeFileSync(
    path.join(repo, file),
    JSON.stringify({ properties, unanalyzed }, null, 2),
    "utf-8",
  );
}

describe("rafter surface diff", () => {
  let repo: string;

  beforeEach(() => {
    repo = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-surface-cli-"));
    git(repo, ["init", "-q", "."]);
    git(repo, ["config", "user.email", "test@rafter.so"]);
    git(repo, ["config", "user.name", "Rafter Test"]);
    git(repo, ["config", "commit.gpgsign", "false"]);
  });

  afterEach(() => {
    fs.rmSync(repo, { recursive: true, force: true });
  });

  function commit(message = "state"): void {
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", message]);
  }

  // ── Exit-code matrix (§6.3) ────────────────────────────────────────

  it("exits 0 when the analyzed surface is unchanged", () => {
    writeStub(repo, "a.surface-stub.json", [port("redis", "loopback-published")]);
    commit();
    const result = rafter(["surface", "diff"], { cwd: repo });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Attack surface unchanged");
  });

  it("exits 1 on a danger increase at or above --fail-on", () => {
    writeStub(repo, "a.surface-stub.json", [port("redis", "loopback-published")]);
    commit();
    writeStub(repo, "a.surface-stub.json", [port("redis", "host-published")]);
    const result = rafter(["surface", "diff"], { cwd: repo });
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain("became more dangerous");
  });

  it("exits 0 when the increase is below --fail-on", () => {
    writeStub(repo, "a.surface-stub.json", [port("redis", "not-published")]);
    commit();
    writeStub(repo, "a.surface-stub.json", [port("redis", "loopback-published")]);
    // loopback-published is severity "low"; the default threshold is "high".
    expect(rafter(["surface", "diff"], { cwd: repo }).exitCode).toBe(0);
    expect(rafter(["surface", "diff", "--fail-on", "low"], { cwd: repo }).exitCode).toBe(1);
  });

  it("exits 2 on an invalid flag value", () => {
    commit0(repo);
    const result = rafter(["surface", "diff", "--format", "yaml"], { cwd: repo });
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("--format");
  });

  it("exits 2 on an unknown flag", () => {
    commit0(repo);
    expect(rafter(["surface", "diff", "--nope"], { cwd: repo }).exitCode).toBe(2);
  });

  it("exits 2 on an option-shaped ref, before git is invoked", () => {
    commit0(repo);
    for (const ref of ["--upload-pack=/bin/false", "-i"]) {
      const result = rafter(["surface", "diff", `--base=${ref}`], { cwd: repo });
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain("Invalid git ref");
    }
  });

  it("exits 2 outside a git repository", () => {
    const bare = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-surface-nogit-"));
    try {
      const result = rafter(["surface", "diff"], { cwd: bare });
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain("Not a git repository");
    } finally {
      fs.rmSync(bare, { recursive: true, force: true });
    }
  });

  it("exits 3 with an actionable message when the base is unresolvable", () => {
    commit0(repo);
    const result = rafter(["surface", "diff", "--base", "origin/main"], { cwd: repo });
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toContain("Cannot resolve base ref 'origin/main'");
    expect(result.stderr).toContain("fetch-depth: 0");
    expect(result.stderr).toContain("--fetch-base");
    // Never silently treated as an empty base: nothing is reported as appeared.
    expect(result.stdout).toBe("");
  });

  it("exits 4 when a changed candidate could not be analyzed", () => {
    commit0(repo);
    fs.writeFileSync(path.join(repo, "broken.surface-stub.json"), "{not json", "utf-8");
    const result = rafter(["surface", "diff"], { cwd: repo });
    expect(result.exitCode).toBe(4);
    expect(result.stdout).toContain("INCONCLUSIVE");
  });

  it("does not gate on an unanalyzable file the change did not touch", () => {
    fs.writeFileSync(path.join(repo, "legacy.surface-stub.json"), "{not json", "utf-8");
    commit();
    const result = rafter(["surface", "diff"], { cwd: repo });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).not.toContain("INCONCLUSIVE");
    expect(result.stdout).toContain("could not be analyzed");
  });

  // ── Precedence 3 > 2 > 4 > 1 > 0 ──────────────────────────────────

  it("prefers exit 4 over exit 1 when both apply", () => {
    writeStub(repo, "a.surface-stub.json", [port("redis", "loopback-published")]);
    commit();
    writeStub(repo, "a.surface-stub.json", [port("redis", "host-published")]);
    fs.writeFileSync(path.join(repo, "broken.surface-stub.json"), "{not json", "utf-8");
    const result = rafter(["surface", "diff"], { cwd: repo });
    expect(result.exitCode).toBe(4);
    // The body still carries every transition found (§6.3).
    const json = JSON.parse(rafter(["surface", "diff", "--json"], { cwd: repo }).stdout);
    expect(json.summary.increased).toBe(1);
    expect(json.coverage.inconclusive).toBe(true);
  });

  it("prefers exit 2 over exit 4", () => {
    writeStub(repo, "a.surface-stub.json", [port("redis", "loopback-published")]);
    commit();
    fs.writeFileSync(path.join(repo, "broken.surface-stub.json"), "{not json", "utf-8");
    expect(rafter(["surface", "diff", "--fail-on", "sometimes"], { cwd: repo }).exitCode).toBe(2);
  });

  it("prefers exit 3 over exit 4", () => {
    commit0(repo);
    fs.writeFileSync(path.join(repo, "broken.surface-stub.json"), "{not json", "utf-8");
    expect(rafter(["surface", "diff", "--base", "origin/main"], { cwd: repo }).exitCode).toBe(3);
  });

  // ── --fail-on none and --on-inconclusive ──────────────────────────

  it("--fail-on none forces 0 and downgrades an inconclusive result", () => {
    writeStub(repo, "a.surface-stub.json", [port("redis", "loopback-published")]);
    commit();
    writeStub(repo, "a.surface-stub.json", [port("redis", "host-published")]);
    fs.writeFileSync(path.join(repo, "broken.surface-stub.json"), "{not json", "utf-8");
    const result = rafter(["surface", "diff", "--fail-on", "none"], { cwd: repo });
    expect(result.exitCode).toBe(0);
    // Report-only reports: the inconclusive block is still printed.
    expect(result.stdout).toContain("INCONCLUSIVE");
    expect(result.stderr).toContain("downgraded to a warning");
  });

  it("--fail-on none does not suppress exit 3", () => {
    commit0(repo);
    const result = rafter(
      ["surface", "diff", "--base", "origin/main", "--fail-on", "none"],
      { cwd: repo },
    );
    expect(result.exitCode).toBe(3);
  });

  it("--on-inconclusive warn downgrades exit 4 to exit 0", () => {
    commit0(repo);
    fs.writeFileSync(path.join(repo, "broken.surface-stub.json"), "{not json", "utf-8");
    const result = rafter(["surface", "diff", "--on-inconclusive", "warn"], { cwd: repo });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("INCONCLUSIVE");
    expect(result.stdout).toContain("--on-inconclusive warn");
  });

  it("--on-inconclusive exit still gates under --fail-on none", () => {
    commit0(repo);
    fs.writeFileSync(path.join(repo, "broken.surface-stub.json"), "{not json", "utf-8");
    const result = rafter(
      ["surface", "diff", "--fail-on", "none", "--on-inconclusive", "exit"],
      { cwd: repo },
    );
    expect(result.exitCode).toBe(4);
  });

  // ── Stream discipline (§9.2) ──────────────────────────────────────

  it("writes only JSON to stdout under --json, with every status on stderr", () => {
    writeStub(repo, "a.surface-stub.json", [port("redis", "loopback-published")]);
    commit();
    writeStub(repo, "a.surface-stub.json", [port("redis", "host-published")]);
    fs.writeFileSync(path.join(repo, "broken.surface-stub.json"), "{not json", "utf-8");
    const result = rafter(
      ["surface", "diff", "--json", "--fail-on", "none", "--explain"],
      { cwd: repo },
    );
    const parsed = JSON.parse(result.stdout);
    expect(parsed.schema_version).toBe(1);
    expect(parsed.base.resolved).toMatch(/^[0-9a-f]{40}$/);
    expect(parsed.head.ref).toBe("WORKTREE");
    expect(parsed.head.resolved).toBeNull();
    expect(parsed.transitions[0].label).not.toContain("→");
    expect(result.stderr).toContain("downgraded to a warning");
    expect(result.stderr).not.toContain("{");
  });

  it("--quiet suppresses stderr status but keeps the result on stdout", () => {
    commit0(repo);
    fs.writeFileSync(path.join(repo, "broken.surface-stub.json"), "{not json", "utf-8");
    const result = rafter(
      ["surface", "diff", "--json", "--on-inconclusive", "warn", "--quiet"],
      { cwd: repo },
    );
    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout).coverage.inconclusive).toBe(true);
  });

  // ── The three text outcomes must not be confusable (§9.2) ─────────

  it("clean, degraded-clean, and inconclusive are visibly different", () => {
    writeStub(repo, "a.surface-stub.json", [port("redis", "loopback-published")]);
    commit();
    const clean = rafter(["surface", "diff"], { cwd: repo }).stdout;

    fs.writeFileSync(path.join(repo, "legacy.surface-stub.json"), "{not json", "utf-8");
    commit("legacy");
    const degraded = rafter(["surface", "diff"], { cwd: repo }).stdout;

    fs.writeFileSync(path.join(repo, "touched.surface-stub.json"), "{not json", "utf-8");
    const inconclusive = rafter(["surface", "diff"], { cwd: repo }).stdout;

    expect(clean.trim()).toMatch(/^Attack surface unchanged/);
    expect(degraded).toContain("no change detected, but");
    expect(degraded).not.toContain("Attack surface unchanged");
    expect(degraded).not.toContain("INCONCLUSIVE");
    expect(inconclusive).toContain("INCONCLUSIVE");
    expect(inconclusive).toContain("This is not a clean result");
    expect(inconclusive).not.toContain("Attack surface unchanged");
    expect(inconclusive).not.toContain("no change detected");
    expect(new Set([clean, degraded, inconclusive]).size).toBe(3);
  });

  // ── Rendering details ─────────────────────────────────────────────

  it("composes delta phrasing in the renderer, not from label", () => {
    writeStub(repo, "p.surface-stub.json", [iam("policy.json|sid=App", "prefix-wildcard")]);
    commit();
    writeStub(repo, "p.surface-stub.json", [iam("policy.json|sid=App", "global-wildcard")]);
    const result = rafter(["surface", "diff"], { cwd: repo });
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain("resource widened: prefix-wildcard → global-wildcard");
    // The label itself stays a property description (amendment A1).
    expect(result.stdout).toContain("Allow s3:GetObject on global-wildcard");
  });

  it("reports an incomparable transition as ambiguous rather than suppressing it", () => {
    writeStub(repo, "p.surface-stub.json", [
      iam("policy.json|sid=App", "prefix-wildcard", "service-wildcard"),
    ]);
    commit();
    writeStub(repo, "p.surface-stub.json", [
      iam("policy.json|sid=App", "global-wildcard", "literal"),
    ]);
    const result = rafter(["surface", "diff", "--fail-on", "medium"], { cwd: repo });
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain("ambiguous");
    expect(result.stdout).toContain("incomparable — review by hand");
  });

  it("--min-severity filters display without changing the exit code", () => {
    writeStub(repo, "a.surface-stub.json", [port("redis", "not-published")]);
    commit();
    writeStub(repo, "a.surface-stub.json", [port("redis", "loopback-published")]);
    const result = rafter(
      ["surface", "diff", "--fail-on", "low", "--min-severity", "high"],
      { cwd: repo },
    );
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain("no property became more dangerous");
    expect(result.stdout).not.toContain("binding widened");
  });

  it("--explain enumerates unanalyzed candidates", () => {
    fs.writeFileSync(path.join(repo, "legacy.surface-stub.json"), "{not json", "utf-8");
    commit();
    const result = rafter(["surface", "diff", "--explain"], { cwd: repo });
    expect(result.stdout).toContain("Unanalyzed candidates");
    expect(result.stdout).toContain("legacy.surface-stub.json");
    expect(result.stdout).toContain("parse_error");
  });

  it("--include-decreased shows properties that became safer", () => {
    writeStub(repo, "a.surface-stub.json", [port("redis", "host-published")]);
    commit();
    writeStub(repo, "a.surface-stub.json", [port("redis", "not-published")]);
    const hidden = rafter(["surface", "diff"], { cwd: repo });
    expect(hidden.exitCode).toBe(0);
    expect(hidden.stdout).toContain("(--include-decreased)");
    const shown = rafter(["surface", "diff", "--include-decreased"], { cwd: repo });
    expect(shown.stdout).toContain("binding narrowed: host-published → not-published");
  });

  it("compares two committed refs when --head is given", () => {
    writeStub(repo, "a.surface-stub.json", [port("redis", "loopback-published")]);
    commit("base");
    const baseSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf-8" }).trim();
    writeStub(repo, "a.surface-stub.json", [port("redis", "host-published")]);
    commit("head");
    const result = rafter(
      ["surface", "diff", "--base", baseSha, "--head", "HEAD", "--json"],
      { cwd: repo },
    );
    expect(result.exitCode).toBe(1);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.head.resolved).toMatch(/^[0-9a-f]{40}$/);
    expect(parsed.summary.increased).toBe(1);
  });
});

/** A repo needs one commit before HEAD resolves; this is the smallest one. */
function commit0(repo: string): void {
  fs.writeFileSync(path.join(repo, "README.md"), "seed\n", "utf-8");
  execFileSync("git", ["add", "-A"], { cwd: repo, stdio: "ignore" });
  execFileSync("git", ["commit", "-q", "-m", "seed"], { cwd: repo, stdio: "ignore" });
}
