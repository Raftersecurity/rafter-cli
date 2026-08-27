/**
 * A scan that did not happen must never look like a scan that found nothing.
 *
 * Two silent false negatives, both found by grey-box beta users driving the
 * real CLI and both confirmed by re-running their repro:
 *
 *   - `rafter secrets <unreadable>` returned `results: []` and exit 0 — byte
 *     for byte what a genuinely clean directory returns. A CI job gating on
 *     the exit code cannot tell "nothing found" from "could not look", and the
 *     directory a scanner cannot enter is exactly where an unnoticed
 *     credential is most likely to be.
 *   - `--engine betterleaks`, explicitly requested, returned zero findings and
 *     exit 0 on a file containing a canonical AWS key, because the binary
 *     emitted a shape the parser rejects. On `auto` a fallback is defensible;
 *     on an engine the user named there is nothing to fall back to.
 *
 * The general fix is a degradation channel — `skipped` and `degraded` in the
 * JSON payload, warnings on stderr, and a non-zero exit when the thing the
 * user actually asked for did not run.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

const CLI = path.resolve(__dirname, "../dist/index.js");

function rafter(args: string[], home: string): { stdout: string; stderr: string; exitCode: number } {
  try {
    const stdout = execFileSync("node", [CLI, ...args], {
      encoding: "utf-8",
      env: { ...process.env, HOME: home, CI: "1" },
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 60_000,
    });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (e: any) {
    return { stdout: e.stdout || "", stderr: e.stderr || "", exitCode: e.status ?? 1 };
  }
}

const AWS_CANARY = "AKIA" + "IOSFODNN7" + "EXAMPLE";

let tmp: string;
let home: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-coverage-"));
  home = path.join(tmp, "home");
  fs.mkdirSync(home);
});

afterEach(() => {
  // Restore permissions first or the cleanup itself fails.
  for (const d of fs.readdirSync(tmp)) {
    try { fs.chmodSync(path.join(tmp, d), 0o755); } catch { /* not a dir we locked */ }
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("an unreadable target is an error, not a clean result", () => {
  it("exits 2 and says nothing was scanned", () => {
    const locked = path.join(tmp, "locked");
    fs.mkdirSync(locked);
    fs.writeFileSync(path.join(locked, "secret.js"), `const k = "${AWS_CANARY}";\n`);
    fs.chmodSync(locked, 0o000);

    const r = rafter(["secrets", locked], home);

    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("Cannot read");
    expect(r.stderr).toContain("Nothing was scanned");
  });

  it("does not answer like an empty directory does", () => {
    const locked = path.join(tmp, "locked");
    fs.mkdirSync(locked);
    fs.writeFileSync(path.join(locked, "secret.js"), `const k = "${AWS_CANARY}";\n`);
    fs.chmodSync(locked, 0o000);
    const empty = path.join(tmp, "empty");
    fs.mkdirSync(empty);

    const unreadable = rafter(["secrets", locked, "--json"], home);
    const emptyScan = rafter(["secrets", empty, "--json"], home);

    expect(emptyScan.exitCode).toBe(0);
    expect(JSON.parse(emptyScan.stdout).results).toEqual([]);
    // The whole bug in one assertion: these two used to be identical.
    expect(unreadable.exitCode).not.toBe(emptyScan.exitCode);
  });

  it("reports unreadable subdirectories found during a walk", () => {
    const root = path.join(tmp, "project");
    fs.mkdirSync(root);
    fs.writeFileSync(path.join(root, "app.js"), `const k = "${AWS_CANARY}";\n`);
    const locked = path.join(root, "vault");
    fs.mkdirSync(locked);
    fs.writeFileSync(path.join(locked, "keys.js"), `const k = "${AWS_CANARY}";\n`);
    fs.chmodSync(locked, 0o000);

    const r = rafter(["secrets", root, "--json"], home);
    const payload = JSON.parse(r.stdout);

    // The readable finding is still reported...
    expect(payload.results.length).toBeGreaterThan(0);
    // ...and the part we could not read is named rather than passed over.
    expect(payload.skipped).toBeDefined();
    expect(payload.skipped.map((s: any) => s.path).join(" ")).toContain("vault");

    fs.chmodSync(locked, 0o755);
  });

  it("says nothing about coverage when coverage was complete", () => {
    const root = path.join(tmp, "clean");
    fs.mkdirSync(root);
    fs.writeFileSync(path.join(root, "ok.js"), "const x = 1;\n");

    // --engine patterns pins this to the one engine that cannot degrade. On
    // `auto` the result depends on whether the developer's betterleaks binary
    // happens to work, and a test whose meaning changes with the machine is
    // testing the machine.
    const r = rafter(["secrets", root, "--json", "--engine", "patterns"], home);
    const payload = JSON.parse(r.stdout);

    expect(r.exitCode).toBe(0);
    expect(payload.skipped).toBeUndefined();
    expect(payload.degraded).toBeUndefined();
  });
});
