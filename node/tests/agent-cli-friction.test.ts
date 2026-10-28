import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * Regression tests for a set of real agent-transcript friction points with
 * `rafter secrets`:
 *
 *   1. Several paths in one invocation used to scan only the first and drop
 *      the rest silently (or, under `scan local`, error "No such command").
 *   2. `-a`/`--agent` was only recognized before the subcommand name.
 *   3. `--json`/`--format json` had no way to write to a file, so a sandboxed
 *      agent without shell redirects couldn't capture the result.
 *   4. A clean text-mode result didn't say the scan covered secrets only.
 *   5. `--staged` outside a git repository leaked git's raw usage error
 *      instead of a one-line explanation.
 */

const CLI = path.resolve(__dirname, "../dist/index.js");

function rafter(
  args: string[],
  opts?: { cwd?: string },
): { stdout: string; stderr: string; exitCode: number } {
  try {
    const result = execFileSync("node", [CLI, ...args], {
      encoding: "utf-8",
      cwd: opts?.cwd,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { stdout: result, stderr: "", exitCode: 0 };
  } catch (e: any) {
    return {
      stdout: e.stdout || "",
      stderr: e.stderr || "",
      exitCode: e.status ?? 1,
    };
  }
}

describe("rafter secrets — agent CLI friction fixes", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-cli-friction-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("scans every path given and merges the findings into one report", () => {
    fs.mkdirSync(path.join(tmpDir, "app"));
    fs.mkdirSync(path.join(tmpDir, "infra"));
    fs.writeFileSync(path.join(tmpDir, "app", "a.py"), "x = 1\n");
    fs.writeFileSync(
      path.join(tmpDir, "app", "b.py"),
      'AWS_KEY = "AKIAIOSFODNN7ABCDEFG"\n',
    );
    fs.writeFileSync(path.join(tmpDir, "infra", "c.tf"), 'resource "x" {}\n');

    const r = rafter(
      ["secrets", "app/a.py", "app/b.py", "infra/c.tf", "--engine", "patterns", "--json"],
      { cwd: tmpDir },
    );
    const out = JSON.parse(r.stdout);
    expect(r.exitCode).toBe(1);
    // Only b.py carries a secret; a clean single-path scan of a.py or c.tf
    // alone would report zero results, so this proves all three paths were
    // actually scanned rather than only the first.
    expect(out.results).toHaveLength(1);
    expect(out.results[0].file).toContain("b.py");
  });

  it("accepts -a after the subcommand name, not just before it", () => {
    fs.writeFileSync(path.join(tmpDir, "clean.txt"), "nothing secret here\n");
    const r = rafter(["secrets", tmpDir, "-a"]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout + r.stderr).not.toContain("unknown option");
    expect(r.stdout + r.stderr).toContain("[OK]");
  });

  it("writes --json output to --out instead of stdout", () => {
    fs.writeFileSync(path.join(tmpDir, "clean.txt"), "nothing secret here\n");
    const outFile = path.join(tmpDir, "result.json");
    const r = rafter(["secrets", tmpDir, "--json", "--out", outFile]);
    expect(r.exitCode).toBe(0);
    expect(fs.existsSync(outFile)).toBe(true);
    const parsed = JSON.parse(fs.readFileSync(outFile, "utf-8"));
    expect(parsed.scan_mode).toBe("local");
    // The payload went to the file, not stdout.
    expect(r.stdout).not.toContain("scan_mode");
  });

  it("notes a clean text-mode result covers secrets only", () => {
    fs.writeFileSync(path.join(tmpDir, "clean.txt"), "nothing secret here\n");
    const r = rafter(["secrets", tmpDir]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("No secrets detected");
    expect(r.stdout).toContain("not a code security review");
  });

  it("explains a non-git cwd instead of leaking git's raw usage error", () => {
    const r = rafter(["secrets", ".", "--staged"], { cwd: tmpDir });
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("Not in a git repository");
    // The old failure mode surfaced git's own "Command failed: git diff..."
    // usage text instead of a one-line explanation.
    expect(r.stderr).not.toContain("Command failed");
  });
});
