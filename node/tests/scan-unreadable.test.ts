import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "child_process";
import path from "path";
import fs from "fs";
import os from "os";

// sable-ilbx — a file that could not be read must not be reported as a clean
// scan. The CLI surfaces it in an `unreadable` field and exits non-zero so a
// gate cannot read "could not open" as "no secrets".

const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_PATH = path.resolve(PROJECT_ROOT, "dist/index.js");

function runScan(args: string, cwd?: string): { stdout: string; stderr: string; exitCode: number } {
  const result = spawnSync(`node ${CLI_PATH} agent scan ${args}`, {
    encoding: "utf-8",
    cwd: cwd || process.cwd(),
    shell: true,
    timeout: 20_000,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, NO_COLOR: "1" },
  });
  return { stdout: result.stdout || "", stderr: result.stderr || "", exitCode: result.status ?? 1 };
}

describe("scan reports unreadable files", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-unreadable-"));
  });

  afterEach(() => {
    // Restore perms so cleanup can remove the file.
    for (const f of fs.readdirSync(tmpDir)) {
      try { fs.chmodSync(path.join(tmpDir, f), 0o644); } catch { /* ignore */ }
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("JSON output lists an unreadable file and exits 2 (no findings)", { timeout: 25000 }, () => {
    const f = path.join(tmpDir, "secret.env");
    fs.writeFileSync(f, "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdef1234567890ABCDEFGHIJKL\n");
    fs.chmodSync(f, 0o000);

    const result = runScan(`${tmpDir} --engine patterns --json`);
    const parsed = JSON.parse(result.stdout);

    expect(parsed.results).toHaveLength(0);
    expect(Array.isArray(parsed.unreadable)).toBe(true);
    expect(parsed.unreadable).toHaveLength(1);
    expect(parsed.unreadable[0].file).toBe(f);
    expect(result.exitCode).toBe(2);
  });

  it("text output does not claim a clean scan for an unreadable file", { timeout: 25000 }, () => {
    const f = path.join(tmpDir, "secret.env");
    fs.writeFileSync(f, "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdef1234567890ABCDEFGHIJKL\n");
    fs.chmodSync(f, 0o000);

    const result = runScan(`${tmpDir} --engine patterns`);
    expect(result.stdout).not.toContain("No secrets detected");
    expect(result.exitCode).toBe(2);
  });
});
