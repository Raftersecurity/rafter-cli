import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync, spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

// sable-28lv — `secrets --history` handed history to betterleaks alone. The
// patterns engine scanned the working tree instead, so a secret in a deleted
// file was found only if a betterleaks rule matched it, and without
// betterleaks `--history` reported a clean scan of history it never read.

const CLI = path.resolve(__dirname, "../dist/index.js");

function git(cwd: string, ...args: string[]): void {
  execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", ...args], { cwd, stdio: "ignore" });
}

function secrets(cwd: string, ...args: string[]) {
  const r = spawnSync("node", [CLI, "secrets", ...args], {
    cwd, encoding: "utf-8", timeout: 30000, env: { ...process.env, HOME: cwd },
  });
  return { stdout: r.stdout || "", stderr: r.stderr || "", code: r.status };
}

describe("secrets --history with the patterns engine", () => {
  let tmp: string;
  let repo: string;

  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-history-"));
    repo = fs.realpathSync(fs.mkdirSync(path.join(tmp, "repo"), { recursive: true })!);
    git(repo, "init", "-q");
    fs.writeFileSync(path.join(repo, "README"), "hello\n");
    fs.writeFileSync(path.join(repo, "aws.cfg"), "[default]\nregion = us-east-1\naws_access_key_id = AKIAIOSFODNN7ABCDEFG\n");
    git(repo, "add", ".");
    git(repo, "commit", "-q", "-m", "add");
    git(repo, "rm", "-q", "aws.cfg");
    git(repo, "commit", "-q", "-m", "remove");
  });

  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it("finds a secret that exists only in a deleted file", () => {
    const r = secrets(repo, ".", "--history", "--engine", "patterns", "--json");
    expect(r.code).toBe(1);
    const results = JSON.parse(r.stdout).results;
    expect(results).toHaveLength(1);
    expect(results[0].file).toBe(path.join(repo, "aws.cfg"));
    const m = results[0].matches[0];
    expect(m.pattern.name).toBe("AWS Access Key ID");
    expect([m.line, m.column]).toEqual([3, 21]);
  }, 30000);

  it("does not report the working tree's state as history outside a git repo", () => {
    const plain = fs.mkdtempSync(path.join(tmp, "plain-"));
    const r = secrets(plain, ".", "--history", "--engine", "patterns");
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/not a git repository/i);
  }, 30000);
});
