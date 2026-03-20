import { describe, it, expect, beforeEach, afterEach, beforeAll } from "vitest";
import { execSync, execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * End-to-end CLI tests — invoke the actual rafter binary and validate
 * exit codes, stdout, and stderr. These demonstrate the real agent
 * experience of calling rafter as a subprocess.
 */

const CLI = path.resolve(__dirname, "../dist/index.js");

function rafter(args: string | string[], opts?: { cwd?: string; env?: Record<string, string> }): {
  stdout: string;
  stderr: string;
  exitCode: number;
} {
  const argList = Array.isArray(args) ? args : args.split(/\s+/);
  try {
    const result = execFileSync("node", [CLI, ...argList], {
      encoding: "utf-8",
      cwd: opts?.cwd,
      env: { ...process.env, ...opts?.env },
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

// Build before running e2e tests — use beforeAll at file level
beforeAll(() => {
  try {
    execSync("pnpm run build", { cwd: path.resolve(__dirname, ".."), stdio: "ignore", timeout: 30000 });
  } catch {
    // Build may have already been done or dist may exist
  }
}, 60000);

describe("CLI e2e — version and help", () => {

  it("--version outputs a semver string", () => {
    const r = rafter("--version");
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("--help outputs usage information", () => {
    const r = rafter("--help");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("rafter");
  });

  it("agent --help shows agent subcommands", () => {
    const r = rafter("agent --help");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("scan");
    expect(r.stdout).toContain("exec");
    expect(r.stdout).toContain("audit");
  });
});

describe("CLI e2e — local secret scanning", () => {
  let tmpDir: string;

  beforeEach(() => {

    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-e2e-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("exits 0 for clean file", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "no secrets here\n");
    const r = rafter(`scan local ${f} --engine patterns --quiet`);
    expect(r.exitCode).toBe(0);
  });

  it("exits 1 when secrets detected", () => {
    const f = path.join(tmpDir, "secrets.txt");
    fs.writeFileSync(f, "AKIAIOSFODNN7EXAMPLE\n");
    const r = rafter(`scan local ${f} --engine patterns --quiet`);
    expect(r.exitCode).toBe(1);
  });

  it("--json outputs valid JSON", () => {
    const f = path.join(tmpDir, "secrets.txt");
    fs.writeFileSync(f, "AKIAIOSFODNN7EXAMPLE\n");
    const r = rafter(`scan local ${f} --engine patterns --json`);
    expect(r.exitCode).toBe(1);
    const parsed = JSON.parse(r.stdout);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0].matches[0].pattern.name).toBe("AWS Access Key ID");
  });

  it("--format sarif outputs SARIF schema", () => {
    const f = path.join(tmpDir, "secrets.txt");
    fs.writeFileSync(f, "AKIAIOSFODNN7EXAMPLE\n");
    const r = rafter(`scan local ${f} --engine patterns --format sarif`);
    expect(r.exitCode).toBe(1);
    const sarif = JSON.parse(r.stdout);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("rafter");
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });

  it("scans directory recursively", () => {
    const sub = path.join(tmpDir, "src");
    fs.mkdirSync(sub);
    fs.writeFileSync(path.join(sub, "config.ts"), "const key = 'AKIAIOSFODNN7EXAMPLE';\n");
    const r = rafter(`scan local ${tmpDir} --engine patterns --json`);
    expect(r.exitCode).toBe(1);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.length).toBeGreaterThan(0);
  });

  it("exits 2 for nonexistent path", () => {
    const r = rafter(`scan local /tmp/nonexistent-rafter-path-12345 --engine patterns`);
    expect(r.exitCode).toBe(2);
  });

  it("exits 2 for invalid engine", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "ok\n");
    const r = rafter(`scan local ${f} --engine badengine`);
    expect(r.exitCode).toBe(2);
  });

  it("exits 2 for invalid format", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "ok\n");
    const r = rafter(`scan local ${f} --engine patterns --format xml`);
    expect(r.exitCode).toBe(2);
  });
});

describe("CLI e2e — command risk assessment", () => {


  it("agent exec blocks critical commands", () => {
    const r = rafter(["agent", "exec", "rm -rf /"]);
    // Should either exit non-zero or print a block message
    expect(r.exitCode).not.toBe(0);
  });

  it("agent exec allows safe commands", () => {
    const r = rafter(["agent", "exec", "echo hello"]);
    expect(r.exitCode).toBe(0);
  });
});

describe("CLI e2e — agent mode flag", () => {
  let tmpDir: string;

  beforeEach(() => {

    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-agent-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("-a flag produces plain text output (no ANSI)", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "no secrets\n");
    const r = rafter(`-a scan local ${f} --engine patterns`);
    expect(r.exitCode).toBe(0);
    // Agent mode should not contain ANSI escape codes
    expect(r.stdout).not.toMatch(/\x1b\[/);
  });
});

describe("CLI e2e — config commands", () => {
  let tmpDir: string;

  beforeEach(() => {

    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-cfg-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("agent config show outputs current config", () => {
    const r = rafter("agent config show", { env: { HOME: tmpDir } });
    // Should output something (even default config) without crashing
    expect(r.exitCode).toBe(0);
  });
});

describe("CLI e2e — backend commands without API key", () => {


  it("rafter run exits 1 without API key", () => {
    const r = rafter("run --repo test/repo --branch main", {
      env: { RAFTER_API_KEY: "" },
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("API key");
  });

  it("rafter usage exits 1 without API key", () => {
    const r = rafter("usage", {
      env: { RAFTER_API_KEY: "" },
    });
    expect(r.exitCode).toBe(1);
  });
});
