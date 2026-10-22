import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "child_process";
import path from "path";
import fs from "fs";
import os from "os";

// sable-lu0j — policy/suppression must be discovered and anchored from the scan
// target, not the process cwd. An ambient `.rafter.yml` in cwd must not suppress
// real secrets in a scan of a different tree, and a policy in the scanned tree
// must still work.

const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_PATH = path.resolve(PROJECT_ROOT, "dist/index.js");
const SECRET = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCDEFG\n";

function runScan(args: string, cwd: string): { stdout: string; exitCode: number } {
  const result = spawnSync(`node ${CLI_PATH} agent scan ${args}`, {
    encoding: "utf-8",
    cwd,
    shell: true,
    timeout: 20_000,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, NO_COLOR: "1" },
  });
  return { stdout: result.stdout || "", exitCode: result.status ?? 1 };
}

describe("scan policy anchoring", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "rafter-anchor-")));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("an ambient cwd .rafter.yml does not suppress findings in another tree", { timeout: 25000 }, () => {
    const cwdDir = path.join(tmp, "cwd");
    const target = path.join(tmp, "target");
    fs.mkdirSync(cwdDir);
    fs.mkdirSync(target);
    const leaf = path.basename(target);
    fs.writeFileSync(
      path.join(cwdDir, ".rafter.yml"),
      `ignore:\n  - paths: ["**/${leaf}/**"]\n    reason: ambient\n`,
    );
    fs.writeFileSync(path.join(target, "creds.env"), SECRET);

    const result = runScan(`${target} --engine patterns --json`, cwdDir);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.results.length).toBeGreaterThanOrEqual(1);
    expect(result.exitCode).toBe(1);
  });

  it("a policy in the scanned tree still suppresses (normal case)", { timeout: 25000 }, () => {
    const repo = path.join(tmp, "repo");
    fs.mkdirSync(path.join(repo, "fixtures"), { recursive: true });
    fs.writeFileSync(
      path.join(repo, ".rafter.yml"),
      `ignore:\n  - paths: ["fixtures/**"]\n    reason: ok\n`,
    );
    fs.writeFileSync(path.join(repo, "fixtures", "creds.env"), SECRET);

    const result = runScan(`${repo} --engine patterns --json`, repo);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.results).toHaveLength(0);
    expect(parsed._suppressed.length).toBeGreaterThanOrEqual(1);
  });
});
