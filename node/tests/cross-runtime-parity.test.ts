import { describe, it, expect, beforeEach, afterEach, beforeAll } from "vitest";
import { execSync, execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * Cross-runtime parity tests — invoke both Node.js and Python CLIs
 * with identical inputs and compare exit codes, output structure,
 * and behavior. These ensure the dual-implementation contract from
 * CLI_SPEC.md holds across runtimes.
 */

const NODE_CLI = path.resolve(__dirname, "../dist/index.js");
const PYTHON_MODULE = "rafter_cli";

// Build test secrets at runtime to avoid triggering push protection
function fakeSecret(prefix: string, body: string): string {
  return prefix + body;
}
const REPO_ROOT = path.resolve(__dirname, "../..");
// Preserve real user site-packages so overriding HOME doesn't break Python imports
let PYTHON_USER_SITE = "";
try {
  PYTHON_USER_SITE = execSync("python3 -c \"import site; print(site.getusersitepackages())\"", {
    encoding: "utf-8",
    timeout: 5000,
  }).trim();
} catch {
  // Fall back — tests requiring Python config may still fail
}

interface CLIResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

function runNode(args: string[], opts?: { cwd?: string; env?: Record<string, string> }): CLIResult {
  try {
    const result = execFileSync("node", [NODE_CLI, ...args], {
      encoding: "utf-8",
      cwd: opts?.cwd ?? REPO_ROOT,
      env: { ...process.env, ...opts?.env },
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 30000,
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

function runPython(args: string[], opts?: { cwd?: string; env?: Record<string, string> }): CLIResult {
  try {
    const result = execFileSync("python3", ["-m", PYTHON_MODULE, ...args], {
      encoding: "utf-8",
      cwd: opts?.cwd ?? REPO_ROOT,
      env: { ...process.env, ...opts?.env, PYTHONPATH: [path.join(REPO_ROOT, "python"), PYTHON_USER_SITE].join(path.delimiter) },
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 30000,
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

/** Run both CLIs with the same args, return results side-by-side */
function runBoth(args: string[], opts?: { cwd?: string; env?: Record<string, string> }) {
  return {
    node: runNode(args, opts),
    python: runPython(args, opts),
  };
}

// Build Node CLI before running tests
beforeAll(() => {
  try {
    execSync("pnpm run build", {
      cwd: path.resolve(__dirname, ".."),
      stdio: "ignore",
      timeout: 30000,
    });
  } catch {
    // Build may already be done
  }
}, 60000);

// ─── Version ────────────────────────────────────────────────────────

describe("parity: version", () => {
  it("both exit 0 for --version", () => {
    const r = runBoth(["--version"]);
    expect(r.node.exitCode).toBe(0);
    expect(r.python.exitCode).toBe(0);
  });

  it("both report the same semver", () => {
    const r = runBoth(["--version"]);
    // Node: "0.6.6\n", Python: "rafter 0.6.6\n" — extract semver
    const nodeSemver = r.node.stdout.trim().match(/(\d+\.\d+\.\d+)/)?.[1];
    const pythonSemver = r.python.stdout.trim().match(/(\d+\.\d+\.\d+)/)?.[1];
    expect(nodeSemver).toBeTruthy();
    expect(nodeSemver).toBe(pythonSemver);
  });
});

// ─── Help ───────────────────────────────────────────────────────────

describe("parity: help", () => {
  it("both exit 0 for --help", () => {
    const r = runBoth(["--help"]);
    expect(r.node.exitCode).toBe(0);
    expect(r.python.exitCode).toBe(0);
  });

  it("both mention core subcommands in help", () => {
    const r = runBoth(["--help"]);
    for (const runtime of [r.node, r.python]) {
      const out = runtime.stdout.toLowerCase();
      expect(out).toContain("scan");
      expect(out).toContain("agent");
    }
  });

  it("agent --help lists subcommands in both", () => {
    const r = runBoth(["agent", "--help"]);
    expect(r.node.exitCode).toBe(0);
    expect(r.python.exitCode).toBe(0);
    for (const runtime of [r.node, r.python]) {
      const out = runtime.stdout.toLowerCase();
      expect(out).toContain("exec");
      expect(out).toContain("audit");
    }
  });
});

// ─── Local Secret Scanning ──────────────────────────────────────────

describe("parity: scan local", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-parity-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("both exit 0 for clean file", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "no secrets here\n");
    const r = runBoth(["scan", "local", f, "--engine", "patterns", "--quiet"]);
    expect(r.node.exitCode).toBe(0);
    expect(r.python.exitCode).toBe(0);
  });

  it("both exit 1 when secrets detected", () => {
    const f = path.join(tmpDir, "secrets.txt");
    fs.writeFileSync(f, "AKIAIOSFODNN7EXAMPLE\n");
    const r = runBoth(["scan", "local", f, "--engine", "patterns", "--quiet"]);
    expect(r.node.exitCode).toBe(1);
    expect(r.python.exitCode).toBe(1);
  });

  it("both exit 2 for nonexistent path", () => {
    const r = runBoth(["scan", "local", "/tmp/nonexistent-rafter-parity-12345", "--engine", "patterns"]);
    expect(r.node.exitCode).toBe(2);
    expect(r.python.exitCode).toBe(2);
  });

  it("both exit 2 for invalid engine", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "ok\n");
    const r = runBoth(["scan", "local", f, "--engine", "badengine"]);
    expect(r.node.exitCode).toBe(2);
    expect(r.python.exitCode).toBe(2);
  });

  it("--json produces identical schema for AWS key", () => {
    const f = path.join(tmpDir, "secrets.txt");
    fs.writeFileSync(f, "AKIAIOSFODNN7EXAMPLE\n");
    const r = runBoth(["scan", "local", f, "--engine", "patterns", "--json"]);

    const nodeJson = JSON.parse(r.node.stdout);
    const pyJson = JSON.parse(r.python.stdout);

    // Both are arrays with one entry
    expect(Array.isArray(nodeJson)).toBe(true);
    expect(Array.isArray(pyJson)).toBe(true);
    expect(nodeJson).toHaveLength(1);
    expect(pyJson).toHaveLength(1);

    // File paths point to the same file
    expect(nodeJson[0].file).toBe(f);
    expect(pyJson[0].file).toBe(f);

    // Same number of matches
    expect(nodeJson[0].matches).toHaveLength(pyJson[0].matches.length);

    // Compare first match structure
    const nodeMatch = nodeJson[0].matches[0];
    const pyMatch = pyJson[0].matches[0];

    expect(nodeMatch.pattern.name).toBe(pyMatch.pattern.name);
    expect(nodeMatch.pattern.severity).toBe(pyMatch.pattern.severity);
    expect(nodeMatch.line).toBe(pyMatch.line);
    expect(nodeMatch.column).toBe(pyMatch.column);
    expect(nodeMatch.redacted).toBe(pyMatch.redacted);
  });

  it("--json produces matching schema fields", () => {
    const f = path.join(tmpDir, "secrets.txt");
    fs.writeFileSync(f, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12\n");
    const r = runBoth(["scan", "local", f, "--engine", "patterns", "--json"]);

    const nodeJson = JSON.parse(r.node.stdout);
    const pyJson = JSON.parse(r.python.stdout);

    // Validate schema shape matches on both
    for (const result of [nodeJson, pyJson]) {
      expect(result[0]).toHaveProperty("file");
      expect(result[0]).toHaveProperty("matches");
      expect(result[0].matches[0]).toHaveProperty("pattern");
      expect(result[0].matches[0]).toHaveProperty("line");
      expect(result[0].matches[0]).toHaveProperty("column");
      expect(result[0].matches[0]).toHaveProperty("redacted");
      expect(result[0].matches[0].pattern).toHaveProperty("name");
      expect(result[0].matches[0].pattern).toHaveProperty("severity");
      expect(result[0].matches[0].pattern).toHaveProperty("description");
    }
  });

  it("directory recursive scan finds same secrets", () => {
    const sub = path.join(tmpDir, "src");
    fs.mkdirSync(sub);
    fs.writeFileSync(path.join(sub, "config.ts"), "const key = 'AKIAIOSFODNN7EXAMPLE';\n");
    const r = runBoth(["scan", "local", tmpDir, "--engine", "patterns", "--json"]);

    expect(r.node.exitCode).toBe(1);
    expect(r.python.exitCode).toBe(1);

    const nodeJson = JSON.parse(r.node.stdout);
    const pyJson = JSON.parse(r.python.stdout);

    expect(nodeJson.length).toBeGreaterThan(0);
    expect(nodeJson.length).toBe(pyJson.length);

    // Both should find the same pattern name
    const nodePatterns = nodeJson.flatMap((f: any) => f.matches.map((m: any) => m.pattern.name)).sort();
    const pyPatterns = pyJson.flatMap((f: any) => f.matches.map((m: any) => m.pattern.name)).sort();
    expect(nodePatterns).toEqual(pyPatterns);
  });

  it("multiple secrets in one file produce same count", () => {
    const f = path.join(tmpDir, "multi.txt");
    fs.writeFileSync(f, [
      "aws_key=AKIAIOSFODNN7EXAMPLE",
      "github_token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12",
      "stripe_key=" + fakeSecret("sk_live", "_ABCDEFGHIJKLMNOPQRSTuvwx"),
    ].join("\n") + "\n");
    const r = runBoth(["scan", "local", f, "--engine", "patterns", "--json"]);

    expect(r.node.exitCode).toBe(1);
    expect(r.python.exitCode).toBe(1);

    const nodeJson = JSON.parse(r.node.stdout);
    const pyJson = JSON.parse(r.python.stdout);

    const nodeCount = nodeJson[0].matches.length;
    const pyCount = pyJson[0].matches.length;
    expect(nodeCount).toBe(pyCount);

    // Same pattern names detected (order may differ)
    const nodeNames = nodeJson[0].matches.map((m: any) => m.pattern.name).sort();
    const pyNames = pyJson[0].matches.map((m: any) => m.pattern.name).sort();
    expect(nodeNames).toEqual(pyNames);
  });

  it("redaction format matches between runtimes", () => {
    const f = path.join(tmpDir, "secrets.txt");
    // Long secret: first 4 + last 4 visible, middle masked
    fs.writeFileSync(f, "AKIAIOSFODNN7EXAMPLE\n");
    const r = runBoth(["scan", "local", f, "--engine", "patterns", "--json"]);

    const nodeRedacted = JSON.parse(r.node.stdout)[0].matches[0].redacted;
    const pyRedacted = JSON.parse(r.python.stdout)[0].matches[0].redacted;

    expect(nodeRedacted).toBe(pyRedacted);
  });
});

// ─── Agent Exec — Risk Classification ──────────────────────────────

describe("parity: agent exec", () => {
  it("both allow safe commands (exit 0)", () => {
    const r = runBoth(["agent", "exec", "echo hello"]);
    expect(r.node.exitCode).toBe(0);
    expect(r.python.exitCode).toBe(0);
  });

  it("both block critical commands (exit non-zero)", () => {
    const r = runBoth(["agent", "exec", "rm -rf /"]);
    expect(r.node.exitCode).not.toBe(0);
    expect(r.python.exitCode).not.toBe(0);
  });

  it("safe command output contains success marker", () => {
    const r = runBoth(["agent", "exec", "echo parity-test"]);
    expect(r.node.stdout).toContain("parity-test");
    expect(r.python.stdout).toContain("parity-test");
  });

  it("agent mode (-a) produces identical success markers", () => {
    const r = runBoth(["-a", "agent", "exec", "echo parity-test"]);
    // Both should have [OK] in agent mode
    expect(r.node.stdout).toContain("[OK]");
    expect(r.python.stdout).toContain("[OK]");
  });
});

// ─── Agent Mode Flag ───────────────────────────────────────────────

describe("parity: agent mode flag (-a)", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-parity-agent-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("both produce no ANSI escape codes in agent mode", () => {
    const f = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(f, "no secrets\n");
    const r = runBoth(["-a", "scan", "local", f, "--engine", "patterns"]);
    expect(r.node.exitCode).toBe(0);
    expect(r.python.exitCode).toBe(0);
    // No ANSI escape sequences in either output
    expect(r.node.stdout).not.toMatch(/\x1b\[/);
    expect(r.python.stdout).not.toMatch(/\x1b\[/);
  });
});

// ─── Config Commands ───────────────────────────────────────────────

describe("parity: agent config", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-parity-cfg-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("both exit 0 for agent config show", () => {
    const r = runBoth(["agent", "config", "show"], { env: { HOME: tmpDir } });
    expect(r.node.exitCode).toBe(0);
    expect(r.python.exitCode).toBe(0);
  });

  it("both output valid JSON for config show", () => {
    const r = runBoth(["agent", "config", "show"], { env: { HOME: tmpDir } });
    expect(() => JSON.parse(r.node.stdout)).not.toThrow();
    expect(() => JSON.parse(r.python.stdout)).not.toThrow();
  });

  it("config structures have equivalent top-level keys", () => {
    const r = runBoth(["agent", "config", "show"], { env: { HOME: tmpDir } });
    const nodeConfig = JSON.parse(r.node.stdout);
    const pyConfig = JSON.parse(r.python.stdout);

    // Both must have version and agent sections
    expect(nodeConfig).toHaveProperty("version");
    expect(pyConfig).toHaveProperty("version");
    expect(nodeConfig).toHaveProperty("agent");
    expect(pyConfig).toHaveProperty("agent");
  });

  it("config risk level defaults match", () => {
    const r = runBoth(["agent", "config", "show"], { env: { HOME: tmpDir } });
    const nodeConfig = JSON.parse(r.node.stdout);
    const pyConfig = JSON.parse(r.python.stdout);

    // Node uses camelCase, Python uses snake_case — but the value should match
    const nodeRisk = nodeConfig.agent?.riskLevel ?? nodeConfig.agent?.risk_level;
    const pyRisk = pyConfig.agent?.risk_level ?? pyConfig.agent?.riskLevel;
    expect(nodeRisk).toBe(pyRisk);
  });

  it("config command policy mode defaults match", () => {
    const r = runBoth(["agent", "config", "show"], { env: { HOME: tmpDir } });
    const nodeConfig = JSON.parse(r.node.stdout);
    const pyConfig = JSON.parse(r.python.stdout);

    const nodeMode = nodeConfig.agent?.commandPolicy?.mode ?? nodeConfig.agent?.command_policy?.mode;
    const pyMode = pyConfig.agent?.command_policy?.mode ?? pyConfig.agent?.commandPolicy?.mode;
    expect(nodeMode).toBe(pyMode);
  });

  it("config blocked patterns match", () => {
    const r = runBoth(["agent", "config", "show"], { env: { HOME: tmpDir } });
    const nodeConfig = JSON.parse(r.node.stdout);
    const pyConfig = JSON.parse(r.python.stdout);

    const nodeBlocked = (nodeConfig.agent?.commandPolicy?.blockedPatterns ??
      nodeConfig.agent?.command_policy?.blocked_patterns ?? []).sort();
    const pyBlocked = (pyConfig.agent?.command_policy?.blocked_patterns ??
      pyConfig.agent?.commandPolicy?.blockedPatterns ?? []).sort();
    expect(nodeBlocked).toEqual(pyBlocked);
  });
});

// ─── Brief Command ─────────────────────────────────────────────────

describe("parity: brief", () => {
  it("both exit 0 for brief commands", () => {
    const r = runBoth(["brief", "commands"]);
    expect(r.node.exitCode).toBe(0);
    expect(r.python.exitCode).toBe(0);
  });

  it("brief commands produces matching content", () => {
    const r = runBoth(["brief", "commands"]);
    // Both should have the same markdown heading
    expect(r.node.stdout).toContain("# Rafter Command Reference");
    expect(r.python.stdout).toContain("# Rafter Command Reference");
  });

  it("both exit 0 for brief security", () => {
    const r = runBoth(["brief", "security"]);
    expect(r.node.exitCode).toBe(0);
    expect(r.python.exitCode).toBe(0);
  });

  it("brief output length is within 20% between runtimes", () => {
    const r = runBoth(["brief", "commands"]);
    const nodeLenght = r.node.stdout.length;
    const pyLength = r.python.stdout.length;
    const ratio = Math.min(nodeLenght, pyLength) / Math.max(nodeLenght, pyLength);
    expect(ratio).toBeGreaterThan(0.8);
  });
});

// ─── CI Init ────────────────────────────────────────────────────────

describe("parity: ci init", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-parity-ci-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("both exit 0 for ci init --platform github", () => {
    const outNode = path.join(tmpDir, "node-ci.yml");
    const outPy = path.join(tmpDir, "py-ci.yml");

    const nodeR = runNode(["ci", "init", "--platform", "github", "--output", outNode], { cwd: tmpDir });
    const pyR = runPython(["ci", "init", "--platform", "github", "--output", outPy], { cwd: tmpDir });

    expect(nodeR.exitCode).toBe(0);
    expect(pyR.exitCode).toBe(0);
  });

  it("generated GitHub workflow YAML has same structure", () => {
    const outNode = path.join(tmpDir, "node-ci.yml");
    const outPy = path.join(tmpDir, "py-ci.yml");

    runNode(["ci", "init", "--platform", "github", "--output", outNode], { cwd: tmpDir });
    runPython(["ci", "init", "--platform", "github", "--output", outPy], { cwd: tmpDir });

    if (fs.existsSync(outNode) && fs.existsSync(outPy)) {
      const nodeYaml = fs.readFileSync(outNode, "utf-8");
      const pyYaml = fs.readFileSync(outPy, "utf-8");

      // Both should contain standard GH Actions structure
      expect(nodeYaml).toContain("name:");
      expect(pyYaml).toContain("name:");
      expect(nodeYaml).toContain("rafter");
      expect(pyYaml).toContain("rafter");
    }
  });
});

// ─── Backend Commands Without API Key ──────────────────────────────

describe("parity: backend commands without API key", () => {
  const noKeyEnv = { RAFTER_API_KEY: "" };

  it("both exit 1 for rafter run without API key", () => {
    const r = runBoth(["run", "--repo", "test/repo", "--branch", "main"], { env: noKeyEnv });
    expect(r.node.exitCode).toBe(1);
    expect(r.python.exitCode).toBe(1);
  });

  it("both exit 1 for rafter usage without API key", () => {
    const r = runBoth(["usage"], { env: noKeyEnv });
    expect(r.node.exitCode).toBe(1);
    expect(r.python.exitCode).toBe(1);
  });

  it("both mention API key in error output", () => {
    const r = runBoth(["run", "--repo", "test/repo", "--branch", "main"], { env: noKeyEnv });
    const nodeMsg = (r.node.stderr + r.node.stdout).toLowerCase();
    const pyMsg = (r.python.stderr + r.python.stdout).toLowerCase();
    expect(nodeMsg).toContain("api key");
    expect(pyMsg).toContain("api key");
  });
});

// ─── Secret Pattern Coverage ───────────────────────────────────────

describe("parity: secret pattern detection", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-parity-patterns-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const testSecrets: Record<string, string> = {
    "AWS Access Key ID": "AKIAIOSFODNN7EXAMPLE",
    "GitHub Personal Access Token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12",
    "Stripe Secret Key": fakeSecret("sk_live", "_ABCDEFGHIJKLMNOPQRSTuvwx"),
    "Slack Webhook URL": fakeSecret("https://hooks.slack", ".com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    "Generic Private Key": "-----BEGIN RSA PRIVATE KEY-----",
  };

  for (const [patternName, secret] of Object.entries(testSecrets)) {
    it(`both detect: ${patternName}`, () => {
      const f = path.join(tmpDir, "test-secret.txt");
      fs.writeFileSync(f, secret + "\n");
      const r = runBoth(["scan", "local", f, "--engine", "patterns", "--json"]);

      expect(r.node.exitCode).toBe(1);
      expect(r.python.exitCode).toBe(1);

      const nodeJson = JSON.parse(r.node.stdout);
      const pyJson = JSON.parse(r.python.stdout);

      expect(nodeJson).toHaveLength(1);
      expect(pyJson).toHaveLength(1);
      expect(nodeJson[0].matches.length).toBeGreaterThan(0);
      expect(pyJson[0].matches.length).toBeGreaterThan(0);

      // Same pattern name detected
      const nodePatternName = nodeJson[0].matches[0].pattern.name;
      const pyPatternName = pyJson[0].matches[0].pattern.name;
      expect(nodePatternName).toBe(pyPatternName);
    });
  }
});

// ─── Stdout/Stderr Separation ──────────────────────────────────────

describe("parity: stdout/stderr separation", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-parity-io-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("--json scan results go to stdout (not stderr) in both", () => {
    const f = path.join(tmpDir, "secrets.txt");
    fs.writeFileSync(f, "AKIAIOSFODNN7EXAMPLE\n");

    // Run node
    let nodeResult: CLIResult;
    try {
      const stdout = execFileSync("node", [NODE_CLI, "scan", "local", f, "--engine", "patterns", "--json"], {
        encoding: "utf-8",
        cwd: REPO_ROOT,
        stdio: ["pipe", "pipe", "pipe"],
        timeout: 30000,
      });
      nodeResult = { stdout, stderr: "", exitCode: 0 };
    } catch (e: any) {
      nodeResult = { stdout: e.stdout || "", stderr: e.stderr || "", exitCode: e.status ?? 1 };
    }

    // Run python
    let pyResult: CLIResult;
    try {
      const stdout = execFileSync("python3", ["-m", PYTHON_MODULE, "scan", "local", f, "--engine", "patterns", "--json"], {
        encoding: "utf-8",
        cwd: REPO_ROOT,
        env: { ...process.env, PYTHONPATH: [path.join(REPO_ROOT, "python"), PYTHON_USER_SITE].join(path.delimiter) },
        stdio: ["pipe", "pipe", "pipe"],
        timeout: 30000,
      });
      pyResult = { stdout, stderr: "", exitCode: 0 };
    } catch (e: any) {
      pyResult = { stdout: e.stdout || "", stderr: e.stderr || "", exitCode: e.status ?? 1 };
    }

    // JSON must be valid on stdout for both
    expect(() => JSON.parse(nodeResult.stdout)).not.toThrow();
    expect(() => JSON.parse(pyResult.stdout)).not.toThrow();

    // Stderr should NOT contain the JSON array
    expect(nodeResult.stderr).not.toContain('"matches"');
    expect(pyResult.stderr).not.toContain('"matches"');
  });
});
