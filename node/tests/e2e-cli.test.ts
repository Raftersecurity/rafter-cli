import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync, spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * End-to-end CLI tests — invoke the actual rafter binary and validate
 * exit codes, stdout, and stderr. These demonstrate the real agent
 * experience of calling rafter as a subprocess.
 *
 * All tests use a 30s timeout because each spawns a Node subprocess.
 */

const CLI = path.resolve(__dirname, "../dist/index.js");
const EXEC_TIMEOUT = 15000; // 15s max per CLI invocation

function rafter(args: string | string[], opts?: { cwd?: string; env?: Record<string, string> }): {
  stdout: string;
  stderr: string;
  exitCode: number;
} {
  const argList = Array.isArray(args) ? args : args.split(/\s+/);
  const result = spawnSync("node", [CLI, ...argList], {
    encoding: "utf-8",
    cwd: opts?.cwd,
    env: opts?.env ?? process.env,
    stdio: ["pipe", "pipe", "pipe"],
    timeout: EXEC_TIMEOUT,
  });
  return {
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    exitCode: result.status ?? 1,
  };
}

describe("CLI e2e — version and help", () => {

  it("--version outputs a semver string", () => {
    const r = rafter("--version");
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  }, 30000);

  it("--version matches package.json version", () => {
    const pkg = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../package.json"), "utf-8"));
    const r = rafter("--version");
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toBe(pkg.version);
  }, 30000);

  it("--help outputs usage information", () => {
    const r = rafter("--help");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("rafter");
  }, 30000);

  it("--help lists all top-level commands", () => {
    const r = rafter("--help");
    expect(r.exitCode).toBe(0);
    for (const cmd of ["scan", "agent", "mcp", "policy", "ci", "hook", "brief", "notify", "run", "get", "usage", "issues", "completion", "report"]) {
      expect(r.stdout).toContain(cmd);
    }
  }, 30000);

  it("agent --help shows agent subcommands", () => {
    const r = rafter("agent --help");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("scan");
    expect(r.stdout).toContain("exec");
    expect(r.stdout).toContain("audit");
  }, 30000);

  it("scan --help shows scan subcommands", () => {
    const r = rafter("scan --help");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("local");
    expect(r.stdout).toContain("remote");
  }, 30000);

  it("policy --help shows policy subcommands", () => {
    const r = rafter("policy --help");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("export");
  }, 30000);

  it("mcp --help shows mcp subcommands", () => {
    const r = rafter("mcp --help");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("serve");
  }, 30000);

  it("ci --help shows ci subcommands", () => {
    const r = rafter("ci --help");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("init");
  }, 30000);
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
  }, 30000);

  it("exits 1 when secrets detected", () => {
    const f = path.join(tmpDir, "secrets.txt");
    fs.writeFileSync(f, "AKIAIOSFODNN7EXAMPLE\n");
    const r = rafter(`scan local ${f} --engine patterns --quiet`);
    expect(r.exitCode).toBe(1);
  }, 30000);

  it("--json outputs valid JSON", () => {
    const f = path.join(tmpDir, "secrets.txt");
    fs.writeFileSync(f, "AKIAIOSFODNN7EXAMPLE\n");
    const r = rafter(`scan local ${f} --engine patterns --json`);
    expect(r.exitCode).toBe(1);
    const parsed = JSON.parse(r.stdout);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0].matches[0].pattern.name).toBe("AWS Access Key ID");
  }, 30000);

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
  }, 30000);

  it("scans directory recursively", () => {
    const sub = path.join(tmpDir, "src");
    fs.mkdirSync(sub);
    fs.writeFileSync(path.join(sub, "config.ts"), "const key = 'AKIAIOSFODNN7EXAMPLE';\n");
    const r = rafter(`scan local ${tmpDir} --engine patterns --json`);
    expect(r.exitCode).toBe(1);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.length).toBeGreaterThan(0);
  }, 30000);

  it("exits 2 for nonexistent path", () => {
    const r = rafter(`scan local /tmp/nonexistent-rafter-path-12345 --engine patterns`);
    expect(r.exitCode).toBe(2);
  }, 30000);

  it("exits 2 for invalid engine", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "ok\n");
    const r = rafter(`scan local ${f} --engine badengine`);
    expect(r.exitCode).toBe(2);
  }, 30000);

  it("exits 2 for invalid format", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "ok\n");
    const r = rafter(`scan local ${f} --engine patterns --format xml`);
    expect(r.exitCode).toBe(2);
  }, 30000);
});

describe("CLI e2e — command risk assessment", () => {

  it("agent exec blocks critical commands", () => {
    const r = rafter(["agent", "exec", "rm -rf /"]);
    expect(r.exitCode).not.toBe(0);
  }, 30000);

  it("agent exec allows safe commands", () => {
    const r = rafter(["agent", "exec", "echo hello"]);
    expect(r.exitCode).toBe(0);
  }, 30000);
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
  }, 30000);
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
    const r = rafter("agent config show", { env: { ...process.env, HOME: tmpDir } });
    expect(r.exitCode).toBe(0);
  }, 30000);
});

describe("CLI e2e — command routing", () => {

  it("no arguments shows help/usage", () => {
    const r = rafter([]);
    const combined = r.stdout + r.stderr;
    expect(combined.toLowerCase()).toContain("rafter");
  }, 30000);

  it("unknown command exits nonzero", () => {
    const r = rafter("nonexistent-command");
    expect(r.exitCode).not.toBe(0);
  }, 30000);

  it("scan local routes to scanner (exit 2 for missing path)", () => {
    const r = rafter("scan local /tmp/nonexistent-rafter-routing-test");
    expect(r.exitCode).toBe(2);
  }, 30000);

  it("agent exec routes to interceptor", () => {
    const r = rafter(["agent", "exec", "echo routing-test"]);
    expect(r.exitCode).toBe(0);
  }, 30000);

  it("policy export routes to exporter", () => {
    const r = rafter("policy export --format claude");
    expect(r.exitCode).toBe(0);
    expect(r.stdout.length).toBeGreaterThan(0);
  }, 30000);
});

describe("CLI e2e — agent scan deprecation", () => {

  it("agent scan emits deprecation warning on stderr", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-dep-"));
    try {
      const f = path.join(tmpDir, "clean.txt");
      fs.writeFileSync(f, "no secrets\n");
      const r = rafter(`agent scan ${f} --engine patterns`);
      expect(r.stderr).toContain("deprecated");
      expect(r.stderr).toContain("rafter scan local");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 30000);

  it("scan local does NOT emit deprecation warning", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-dep-"));
    try {
      const f = path.join(tmpDir, "clean.txt");
      fs.writeFileSync(f, "no secrets\n");
      const r = rafter(`scan local ${f} --engine patterns`);
      expect(r.stderr).not.toContain("deprecated");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 30000);
});

describe("CLI e2e — update checker", () => {

  it("update check is suppressed in CI environment", () => {
    const r = rafter("--version", {
      env: { ...process.env, CI: "true" },
    });
    expect(r.exitCode).toBe(0);
    expect(r.stderr).not.toContain("Update available");
  }, 30000);

  it("update check is suppressed with CONTINUOUS_INTEGRATION env", () => {
    const r = rafter("--version", {
      env: { ...process.env, CONTINUOUS_INTEGRATION: "true" },
    });
    expect(r.exitCode).toBe(0);
    expect(r.stderr).not.toContain("Update available");
  }, 30000);
});

describe("CLI e2e — dotenv loading", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-dotenv-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("loads RAFTER_API_KEY from .env file in cwd", () => {
    // Write a .env file with a fake API key
    fs.writeFileSync(path.join(tmpDir, ".env"), "RAFTER_API_KEY=test-key-from-dotenv\n");
    // Run from tmpDir WITHOUT setting RAFTER_API_KEY in env — let .env provide it.
    // The usage command will attempt to call the API (and fail), but it should NOT
    // complain about a missing API key since .env provides one.
    const envWithoutKey = { ...process.env };
    delete envWithoutKey.RAFTER_API_KEY;
    const r = rafter("usage", { cwd: tmpDir, env: envWithoutKey as Record<string, string> });
    const combined = (r.stdout + r.stderr).toLowerCase();
    expect(combined).not.toContain("no api key");
  }, 30000);
});

describe("CLI e2e — version parity", () => {

  it("node and python versions match", () => {
    const nodePkg = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../package.json"), "utf-8")
    );
    const pyproject = fs.readFileSync(
      path.resolve(__dirname, "../../python/pyproject.toml"), "utf-8"
    );
    const pyVersionMatch = pyproject.match(/^version\s*=\s*"([^"]+)"/m);
    expect(pyVersionMatch).not.toBeNull();
    expect(nodePkg.version).toBe(pyVersionMatch![1]);
  });
});

describe("CLI e2e — backend commands without API key", () => {

  it("rafter run exits 1 without API key", () => {
    const r = rafter("run --repo test/repo --branch main", {
      env: { ...process.env, RAFTER_API_KEY: "" },
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("API key");
  }, 30000);

  it("rafter usage exits 1 without API key", () => {
    const r = rafter("usage", {
      env: { ...process.env, RAFTER_API_KEY: "" },
    });
    expect(r.exitCode).toBe(1);
  }, 30000);
});
