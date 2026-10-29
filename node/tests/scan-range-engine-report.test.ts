import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync, execSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * sable-jiqb — two surfaces:
 *   --range <a>..<b>  scope a scan to a commit range's changed files, so a
 *                     huge repo can be scanned without the full file list.
 *   engine reporting  the JSON (and text) must name the engine actually used
 *                     and flag any fall-back, so a betterleaks miss is never
 *                     silent to a json/MCP/CI consumer.
 */

const CLI = path.resolve(__dirname, "../dist/index.js");

// Invoke via the absolute node path so a test can blank PATH (to force
// betterleaks unavailable) without breaking the node lookup itself.
function rafter(
  args: string[],
  opts?: { cwd?: string; env?: Record<string, string> },
): { stdout: string; stderr: string; exitCode: number } {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], {
      encoding: "utf-8",
      cwd: opts?.cwd,
      env: { ...process.env, ...opts?.env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (e: any) {
    return { stdout: e.stdout || "", stderr: e.stderr || "", exitCode: e.status ?? 1 };
  }
}

describe("secrets --range (sable-jiqb)", () => {
  let repo: string;
  const git = (args: string) =>
    execSync(`git ${args}`, { cwd: repo, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }).trim();

  beforeEach(() => {
    repo = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-range-"));
    git("init");
    git('config user.email "t@example.com"');
    git('config user.name "t"');
    fs.writeFileSync(path.join(repo, "README.md"), "# repo\n");
    git("add README.md");
    git('commit -m initial');
  });

  afterEach(() => fs.rmSync(repo, { recursive: true, force: true }));

  it("finds a secret introduced within the range", () => {
    const base = git("rev-parse HEAD");
    fs.writeFileSync(path.join(repo, "cfg.ts"), "const k = 'AKIAIOSFODNN7ABCDEFG';\n");
    git("add cfg.ts");
    git('commit -m "add secret"');
    const head = git("rev-parse HEAD");

    const r = rafter(["secrets", repo, "--range", `${base}..${head}`, "--engine", "patterns", "--json"], { cwd: repo });
    expect(r.exitCode).toBe(1);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.results[0].matches[0].pattern.name).toBe("AWS Access Key ID");
  });

  it("ignores a secret outside the range (pre-existing before the range start)", () => {
    // Secret committed first, then the range starts after it.
    fs.writeFileSync(path.join(repo, "old.ts"), "const k = 'AKIAIOSFODNN7ABCDEFG';\n");
    git("add old.ts");
    git('commit -m "old secret"');
    const base = git("rev-parse HEAD");
    fs.writeFileSync(path.join(repo, "clean.ts"), "const x = 1;\n");
    git("add clean.ts");
    git('commit -m "clean"');
    const head = git("rev-parse HEAD");

    const r = rafter(["secrets", repo, "--range", `${base}..${head}`, "--engine", "patterns", "--quiet"], { cwd: repo });
    expect(r.exitCode).toBe(0);
  });

  it("rejects a range git would read as an option", () => {
    const r = rafter(["secrets", repo, "--range", "--output=/tmp/x", "--engine", "patterns", "--quiet"], { cwd: repo });
    expect(r.exitCode).toBe(2);
  });
});

describe("secrets engine reporting in JSON (sable-jiqb)", () => {
  let dir: string;
  let cleanHome: string;
  let emptyBin: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-engjson-"));
    fs.writeFileSync(path.join(dir, "cfg.ts"), "const k = 'AKIAIOSFODNN7ABCDEFG';\n");
    cleanHome = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-home-"));
    emptyBin = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-emptybin-"));
  });

  afterEach(() => {
    for (const d of [dir, cleanHome, emptyBin]) fs.rmSync(d, { recursive: true, force: true });
  });

  it("names the requested and used engine with degraded=false on a patterns scan", () => {
    const r = rafter(["secrets", dir, "--engine", "patterns", "--json"]);
    expect(r.exitCode).toBe(1);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.engine_requested).toBe("patterns");
    expect(parsed.engine_used).toBe("patterns");
    expect(parsed.degraded).toBe(false);
  });

  it("flags degraded=true in JSON when betterleaks is requested but unavailable", () => {
    // PATH holds no betterleaks and HOME holds no managed binary, so the
    // requested betterleaks engine resolves to patterns — a downgrade the JSON
    // must carry rather than swallow.
    const r = rafter(["secrets", dir, "--engine", "betterleaks", "--json"], {
      env: { HOME: cleanHome, PATH: emptyBin },
    });
    expect(r.exitCode).toBe(1);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.engine_requested).toBe("betterleaks");
    expect(parsed.engine_used).toBe("patterns");
    expect(parsed.degraded).toBe(true);
    expect(typeof parsed.degraded_reason).toBe("string");
    expect(parsed.degraded_reason.length).toBeGreaterThan(0);
    // The scan still works — patterns catches the planted AWS key.
    expect(parsed.results[0].matches[0].pattern.name).toBe("AWS Access Key ID");
  });
});
