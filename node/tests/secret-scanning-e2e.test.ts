import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execSync, execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { RegexScanner } from "../src/scanners/regex-scanner.js";

/**
 * End-to-end secret scanning tests with real filesystem operations.
 *
 * These tests go beyond pattern matching — they create realistic project
 * structures, git repos, and multi-file scenarios to validate the scanning
 * pipeline from file discovery through result reporting.
 */

// Build test secrets at runtime to avoid triggering push protection
function fakeSecret(prefix: string, body: string): string {
  return prefix + body;
}

const CLI = path.resolve(__dirname, "../dist/index.js");

function rafter(
  args: string | string[],
  opts?: { cwd?: string; env?: Record<string, string> },
): { stdout: string; stderr: string; exitCode: number } {
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

// ── Realistic project structure scanning ────────────────────────────

describe("E2E: realistic project scanning", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-e2e-project-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("finds secrets across a multi-file project structure", () => {
    // Create a realistic project layout
    const dirs = ["src", "src/config", "src/utils", "tests", "scripts"];
    for (const d of dirs) {
      fs.mkdirSync(path.join(tmpDir, d), { recursive: true });
    }

    // .env with database URL
    fs.writeFileSync(
      path.join(tmpDir, ".env"),
      "DATABASE_URL=postgres://admin:s3cret@db.example.com:5432/mydb\nNODE_ENV=production\n",
    );

    // Source file with API key
    fs.writeFileSync(
      path.join(tmpDir, "src/config/keys.ts"),
      `// API configuration
const API_BASE = "https://api.example.com";
const API_KEY = "AKIAIOSFODNN7EXAMPLE";
export { API_BASE, API_KEY };
`,
    );

    // Source file with GitHub token
    fs.writeFileSync(
      path.join(tmpDir, "src/utils/auth.ts"),
      `export function getToken() {
  return "ghp_FAKEEFghijklmnopqrstuvwxyz0123456789";
}
`,
    );

    // Clean source file (no secrets)
    fs.writeFileSync(
      path.join(tmpDir, "src/index.ts"),
      `import { API_BASE } from "./config/keys";
console.log("Starting app");
`,
    );

    // Clean test file
    fs.writeFileSync(
      path.join(tmpDir, "tests/app.test.ts"),
      `describe("app", () => { it("works", () => { expect(true).toBe(true); }); });`,
    );

    // Script with private key
    fs.writeFileSync(
      path.join(tmpDir, "scripts/deploy.sh"),
      `#!/bin/bash
# Deploy script
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
ssh deploy@server "restart-app"
`,
    );

    const scanner = new RegexScanner();
    const results = scanner.scanDirectory(tmpDir);

    // Should find secrets in 4 files
    expect(results.length).toBe(4);

    const files = results.map((r) => path.basename(r.file)).sort();
    expect(files).toContain(".env");
    expect(files).toContain("keys.ts");
    expect(files).toContain("auth.ts");
    expect(files).toContain("deploy.sh");
  });

  it("finds secrets in common config file formats", () => {
    // YAML config
    fs.writeFileSync(
      path.join(tmpDir, "config.yml"),
      `database:
  host: localhost
  password: "MyS3cur3Pa55w0rd!"
  port: 5432
`,
    );

    // JSON config
    fs.writeFileSync(
      path.join(tmpDir, "config.json"),
      JSON.stringify(
        {
          api: {
            key: fakeSecret("sk_live", "_abcdefghijklmnopqrstuvwx"),
            url: "https://api.stripe.com",
          },
        },
        null,
        2,
      ),
    );

    // INI-style config
    fs.writeFileSync(
      path.join(tmpDir, "app.conf"),
      `[database]
host = localhost
connection = mysql://root:password123@localhost:3306/app
`,
    );

    const scanner = new RegexScanner();
    const results = scanner.scanDirectory(tmpDir);

    expect(results.length).toBe(3);

    const patterns = results.flatMap((r) => r.matches.map((m) => m.pattern.name));
    expect(patterns).toContain("Generic Secret");
    expect(patterns).toContain("Stripe API Key");
    expect(patterns).toContain("Database Connection String");
  });

  it("correctly skips node_modules even when they contain secrets", () => {
    // Secret in the main src
    fs.writeFileSync(
      path.join(tmpDir, "index.js"),
      "const token = 'ghp_FAKEEFghijklmnopqrstuvwxyz0123456789';\n",
    );

    // Secret buried in node_modules
    const nmDir = path.join(tmpDir, "node_modules", "some-pkg", "src");
    fs.mkdirSync(nmDir, { recursive: true });
    fs.writeFileSync(
      path.join(nmDir, "config.js"),
      "module.exports = { key: 'AKIAIOSFODNN7EXAMPLE' };\n",
    );

    const scanner = new RegexScanner();
    const results = scanner.scanDirectory(tmpDir);

    // Only the root file, not node_modules
    expect(results.length).toBe(1);
    expect(results[0].file).toContain("index.js");
  });
});

// ── Mixed content: secrets buried in legitimate files ───────────────

describe("E2E: mixed content scanning", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-e2e-mixed-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("finds a secret buried in a large file", () => {
    // 100 lines of clean code, then a secret, then 100 more lines
    const cleanLines = Array.from({ length: 100 }, (_, i) => `const x${i} = ${i};\n`);
    const secretLine = `const token = "${fakeSecret("sk_live", "_abcdefghijklmnopqrstuvwx")}";\n`;
    const content = cleanLines.join("") + secretLine + cleanLines.join("");

    fs.writeFileSync(path.join(tmpDir, "large-file.ts"), content);

    const scanner = new RegexScanner();
    const results = scanner.scanDirectory(tmpDir);

    expect(results.length).toBe(1);
    expect(results[0].matches[0].line).toBe(101);
    expect(results[0].matches[0].pattern.name).toBe("Stripe API Key");
  });

  it("reports correct line numbers for multiple secrets in one file", () => {
    const content = [
      "// Line 1: clean",
      "// Line 2: clean",
      `const aws = "AKIAIOSFODNN7EXAMPLE";`, // line 3
      "// Line 4: clean",
      "// Line 5: clean",
      `const gh = "ghp_FAKEEFghijklmnopqrstuvwxyz0123456789";`, // line 6
      "// Line 7: clean",
      "-----BEGIN RSA PRIVATE KEY-----", // line 8
      "MIIEpAIBAAKCAQEA...",
      "-----END RSA PRIVATE KEY-----",
    ].join("\n");

    fs.writeFileSync(path.join(tmpDir, "multi-secret.ts"), content);

    const scanner = new RegexScanner();
    const result = scanner.scanFile(path.join(tmpDir, "multi-secret.ts"));

    expect(result.matches.length).toBeGreaterThanOrEqual(3);

    const awsMatch = result.matches.find((m) => m.pattern.name === "AWS Access Key ID");
    const ghMatch = result.matches.find((m) => m.pattern.name === "GitHub Personal Access Token");
    const pkMatch = result.matches.find((m) => m.pattern.name === "Private Key");

    expect(awsMatch?.line).toBe(3);
    expect(ghMatch?.line).toBe(6);
    expect(pkMatch?.line).toBe(8);
  });

  it("does not false-positive on variable names containing secret-like substrings", () => {
    const content = [
      "const awsKeyId = process.env.AWS_KEY_ID;",
      "const githubToken = getToken();",
      "const stripe_api_key = config.get('stripe');",
      "function generatePrivateKey() { return crypto.generateKey(); }",
    ].join("\n");

    fs.writeFileSync(path.join(tmpDir, "clean-code.ts"), content);

    const scanner = new RegexScanner();
    const result = scanner.scanFile(path.join(tmpDir, "clean-code.ts"));
    expect(result.matches.length).toBe(0);
  });
});

// ── Edge cases ──────────────────────────────────────────────────────

describe("E2E: edge cases", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-e2e-edge-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("handles empty files gracefully", () => {
    fs.writeFileSync(path.join(tmpDir, "empty.txt"), "");

    const scanner = new RegexScanner();
    const result = scanner.scanFile(path.join(tmpDir, "empty.txt"));
    expect(result.matches.length).toBe(0);
  });

  it("handles files with only whitespace", () => {
    fs.writeFileSync(path.join(tmpDir, "whitespace.txt"), "   \n\n\t\t\n   ");

    const scanner = new RegexScanner();
    const result = scanner.scanFile(path.join(tmpDir, "whitespace.txt"));
    expect(result.matches.length).toBe(0);
  });

  it("handles files with unicode content around secrets", () => {
    const content = `# 配置文件 — Configuration
api_key = "sk1234567890abcdef"
# Ключ доступа — Access key
aws_key = AKIAIOSFODNN7EXAMPLE
# アクセストークン — Token
`;

    fs.writeFileSync(path.join(tmpDir, "unicode.txt"), content);

    const scanner = new RegexScanner();
    const result = scanner.scanFile(path.join(tmpDir, "unicode.txt"));
    expect(result.matches.length).toBeGreaterThan(0);
    expect(result.matches.some((m) => m.pattern.name === "AWS Access Key ID")).toBe(true);
  });

  it("handles deeply nested directory structures", () => {
    const deepPath = path.join(tmpDir, "a", "b", "c", "d", "e", "f");
    fs.mkdirSync(deepPath, { recursive: true });
    fs.writeFileSync(
      path.join(deepPath, "secret.txt"),
      "AKIAIOSFODNN7EXAMPLE\n",
    );

    const scanner = new RegexScanner();
    const results = scanner.scanDirectory(tmpDir);
    expect(results.length).toBe(1);
  });

  it("skips binary files even when they happen to contain secret-like patterns", () => {
    const binaryExts = [".jpg", ".png", ".exe", ".dll", ".zip", ".pyc"];
    for (const ext of binaryExts) {
      fs.writeFileSync(
        path.join(tmpDir, `file${ext}`),
        "AKIAIOSFODNN7EXAMPLE\n",
      );
    }

    // One text file that should be caught
    fs.writeFileSync(path.join(tmpDir, "file.txt"), "AKIAIOSFODNN7EXAMPLE\n");

    const scanner = new RegexScanner();
    const results = scanner.scanDirectory(tmpDir);
    expect(results.length).toBe(1);
    expect(results[0].file).toContain("file.txt");
  });

  it("returns empty results for nonexistent file", () => {
    const scanner = new RegexScanner();
    const result = scanner.scanFile("/tmp/nonexistent-rafter-file-99999.txt");
    expect(result.matches.length).toBe(0);
  });

  it("handles empty directory", () => {
    const scanner = new RegexScanner();
    const results = scanner.scanDirectory(tmpDir);
    expect(results.length).toBe(0);
  });
});

// ── Git --staged scanning ───────────────────────────────────────────

describe("E2E: git --staged scanning", () => {
  let tmpDir: string;

  function git(args: string, cwd?: string): string {
    return execSync(`git ${args}`, {
      cwd: cwd || tmpDir,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  }

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-e2e-git-staged-"));
    git("init");
    git('config user.email "test@example.com"');
    git('config user.name "Test"');

    // Initial clean commit
    fs.writeFileSync(path.join(tmpDir, "README.md"), "# Test repo\n");
    git("add README.md");
    git('commit -m "initial"');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("detects secrets in staged files via CLI --staged flag", () => {
    // Create and stage a file with a secret
    fs.writeFileSync(
      path.join(tmpDir, "config.ts"),
      "const key = 'AKIAIOSFODNN7EXAMPLE';\n",
    );
    git("add config.ts");

    const r = rafter(
      ["scan", "local", tmpDir, "--staged", "--engine", "patterns", "--json"],
      { cwd: tmpDir },
    );
    expect(r.exitCode).toBe(1);

    const parsed = JSON.parse(r.stdout);
    expect(parsed.length).toBeGreaterThan(0);
    expect(parsed[0].matches[0].pattern.name).toBe("AWS Access Key ID");
  });

  it("exits 0 when staged files are clean", () => {
    fs.writeFileSync(path.join(tmpDir, "clean.ts"), "const x = 42;\n");
    git("add clean.ts");

    const r = rafter(
      ["scan", "local", tmpDir, "--staged", "--engine", "patterns", "--quiet"],
      { cwd: tmpDir },
    );
    expect(r.exitCode).toBe(0);
  });

  it("only scans staged files, not unstaged changes", () => {
    // Stage a clean file
    fs.writeFileSync(path.join(tmpDir, "clean.ts"), "const x = 42;\n");
    git("add clean.ts");

    // Create (but don't stage) a file with a secret
    fs.writeFileSync(
      path.join(tmpDir, "secret.ts"),
      "const key = 'AKIAIOSFODNN7EXAMPLE';\n",
    );

    const r = rafter(
      ["scan", "local", tmpDir, "--staged", "--engine", "patterns", "--quiet"],
      { cwd: tmpDir },
    );
    expect(r.exitCode).toBe(0);
  });
});

// ── Git --diff scanning ──────────��──────────────────────────────────

describe("E2E: git --diff scanning", () => {
  let tmpDir: string;

  function git(args: string, cwd?: string): string {
    return execSync(`git ${args}`, {
      cwd: cwd || tmpDir,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  }

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-e2e-git-diff-"));
    git("init");
    git('config user.email "test@example.com"');
    git('config user.name "Test"');

    // Initial clean commit
    fs.writeFileSync(path.join(tmpDir, "README.md"), "# Test repo\n");
    git("add README.md");
    git('commit -m "initial"');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("detects secrets in files changed since a ref", () => {
    const initialCommit = git("rev-parse HEAD");

    // Add a file with a secret after the initial commit
    fs.writeFileSync(
      path.join(tmpDir, "secrets.ts"),
      "const key = 'AKIAIOSFODNN7EXAMPLE';\n",
    );
    git("add secrets.ts");
    git('commit -m "add secrets"');

    const r = rafter(
      ["scan", "local", tmpDir, "--diff", initialCommit, "--engine", "patterns", "--json"],
      { cwd: tmpDir },
    );
    expect(r.exitCode).toBe(1);

    const parsed = JSON.parse(r.stdout);
    expect(parsed.length).toBeGreaterThan(0);
    expect(parsed[0].matches[0].pattern.name).toBe("AWS Access Key ID");
  });

  it("exits 0 when changed files are clean", () => {
    const initialCommit = git("rev-parse HEAD");

    fs.writeFileSync(path.join(tmpDir, "feature.ts"), "export function add(a: number, b: number) { return a + b; }\n");
    git("add feature.ts");
    git('commit -m "add feature"');

    const r = rafter(
      ["scan", "local", tmpDir, "--diff", initialCommit, "--engine", "patterns", "--quiet"],
      { cwd: tmpDir },
    );
    expect(r.exitCode).toBe(0);
  });

  it("only scans changed files, not the entire repo", () => {
    // File with secret already committed
    fs.writeFileSync(
      path.join(tmpDir, "old-secret.ts"),
      "const old = 'AKIAIOSFODNN7EXAMPLE';\n",
    );
    git("add old-secret.ts");
    git('commit -m "old secret"');

    const ref = git("rev-parse HEAD");

    // New clean file
    fs.writeFileSync(path.join(tmpDir, "clean.ts"), "const x = 1;\n");
    git("add clean.ts");
    git('commit -m "add clean"');

    // --diff should only look at files changed since ref (clean.ts)
    const r = rafter(
      ["scan", "local", tmpDir, "--diff", ref, "--engine", "patterns", "--quiet"],
      { cwd: tmpDir },
    );
    expect(r.exitCode).toBe(0);
  });
});

// ── CLI JSON output structure ───────────────────────────────────────

describe("E2E: CLI JSON output structure", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-e2e-json-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("JSON output includes file path, pattern name, severity, and line number", () => {
    fs.writeFileSync(
      path.join(tmpDir, "test.ts"),
      "clean\nclean\nconst key = 'AKIAIOSFODNN7EXAMPLE';\n",
    );

    const r = rafter(`scan local ${tmpDir} --engine patterns --json`);
    expect(r.exitCode).toBe(1);

    const parsed = JSON.parse(r.stdout);
    expect(parsed).toHaveLength(1);

    const entry = parsed[0];
    expect(entry.file).toContain("test.ts");
    expect(entry.matches).toHaveLength(1);

    const match = entry.matches[0];
    expect(match.pattern.name).toBe("AWS Access Key ID");
    expect(match.pattern.severity).toBe("critical");
    expect(match.line).toBe(3);
    expect(typeof match.redacted).toBe("string");
    expect(match.redacted.length).toBeGreaterThan(0);
  });

  it("JSON output groups matches by file when scanning a directory", () => {
    const src = path.join(tmpDir, "src");
    fs.mkdirSync(src);
    fs.writeFileSync(
      path.join(src, "a.ts"),
      "AKIAIOSFODNN7EXAMPLE\n",
    );
    fs.writeFileSync(
      path.join(src, "b.ts"),
      "ghp_FAKEEFghijklmnopqrstuvwxyz0123456789\n",
    );
    fs.writeFileSync(
      path.join(src, "c.ts"),
      "clean code\n",
    );

    const r = rafter(`scan local ${tmpDir} --engine patterns --json`);
    expect(r.exitCode).toBe(1);

    const parsed = JSON.parse(r.stdout);
    expect(parsed).toHaveLength(2);

    const fileNames = parsed.map((e: any) => path.basename(e.file)).sort();
    expect(fileNames).toEqual(["a.ts", "b.ts"]);
  });
});

// ── SARIF output with real filesystem ───��───────────────────────────

describe("E2E: SARIF output with real files", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-e2e-sarif-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("produces valid SARIF with file locations from a directory scan", () => {
    const src = path.join(tmpDir, "src");
    fs.mkdirSync(src);
    fs.writeFileSync(
      path.join(src, "config.ts"),
      "line 1\nconst key = 'AKIAIOSFODNN7EXAMPLE';\n",
    );
    fs.writeFileSync(
      path.join(src, "auth.ts"),
      "const token = 'ghp_FAKEEFghijklmnopqrstuvwxyz0123456789';\n",
    );

    const r = rafter(`scan local ${tmpDir} --engine patterns --format sarif`);
    expect(r.exitCode).toBe(1);

    const sarif = JSON.parse(r.stdout);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);

    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("rafter");
    expect(run.results.length).toBeGreaterThanOrEqual(2);

    // Each result should have a physical location with a real file path
    for (const result of run.results) {
      expect(result.locations).toHaveLength(1);
      const loc = result.locations[0].physicalLocation;
      expect(loc.artifactLocation.uri).toContain("src/");
      expect(loc.region?.startLine).toBeGreaterThan(0);
    }
  });
});

// ── Baseline filtering ──────────────────────────────────────────────

describe("E2E: baseline filtering", () => {
  let tmpDir: string;
  let homeDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-e2e-baseline-"));
    homeDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-home-"));
    fs.mkdirSync(path.join(homeDir, ".rafter"), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(homeDir, { recursive: true, force: true });
  });

  it("filters known findings when --baseline flag is used", () => {
    const secretFile = path.join(tmpDir, "config.ts");
    fs.writeFileSync(
      secretFile,
      "const key = 'AKIAIOSFODNN7EXAMPLE';\nconst gh = 'ghp_FAKEEFghijklmnopqrstuvwxyz0123456789';\n",
    );

    // Create baseline that suppresses the AWS key but not the GitHub token
    const baseline = {
      entries: [
        { file: secretFile, line: 1, pattern: "AWS Access Key ID" },
      ],
    };
    fs.writeFileSync(
      path.join(homeDir, ".rafter", "baseline.json"),
      JSON.stringify(baseline),
    );

    const r = rafter(`scan local ${secretFile} --engine patterns --json --baseline`, {
      env: { HOME: homeDir },
    });
    expect(r.exitCode).toBe(1);

    const parsed = JSON.parse(r.stdout);
    expect(parsed).toHaveLength(1);

    // Only the GitHub token should remain (AWS key was baselined)
    const names = parsed[0].matches.map((m: any) => m.pattern.name);
    expect(names).toContain("GitHub Personal Access Token");
    expect(names).not.toContain("AWS Access Key ID");
  });

  it("returns all findings when --baseline is not set", () => {
    const secretFile = path.join(tmpDir, "config.ts");
    fs.writeFileSync(
      secretFile,
      "const key = 'AKIAIOSFODNN7EXAMPLE';\nconst gh = 'ghp_FAKEEFghijklmnopqrstuvwxyz0123456789';\n",
    );

    // Baseline file exists but --baseline flag is not passed
    const baseline = {
      entries: [
        { file: secretFile, line: 1, pattern: "AWS Access Key ID" },
      ],
    };
    fs.writeFileSync(
      path.join(homeDir, ".rafter", "baseline.json"),
      JSON.stringify(baseline),
    );

    const r = rafter(`scan local ${secretFile} --engine patterns --json`, {
      env: { HOME: homeDir },
    });
    expect(r.exitCode).toBe(1);

    const parsed = JSON.parse(r.stdout);
    const names = parsed[0].matches.map((m: any) => m.pattern.name);
    // Both should be present since --baseline was not passed
    expect(names).toContain("AWS Access Key ID");
    expect(names).toContain("GitHub Personal Access Token");
  });
});

// ── Scanner API (not CLI) with real filesystem ──────────────────────

describe("E2E: RegexScanner API with realistic files", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-e2e-api-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("scanFiles returns only files with findings", () => {
    const files = [
      { name: "clean1.ts", content: "const x = 1;" },
      { name: "dirty.ts", content: "const key = 'AKIAIOSFODNN7EXAMPLE';" },
      { name: "clean2.ts", content: "const y = 2;" },
      { name: "dirty2.ts", content: "-----BEGIN RSA PRIVATE KEY-----" },
    ];

    const paths: string[] = [];
    for (const f of files) {
      const p = path.join(tmpDir, f.name);
      fs.writeFileSync(p, f.content);
      paths.push(p);
    }

    const scanner = new RegexScanner();
    const results = scanner.scanFiles(paths);

    expect(results.length).toBe(2);
    const resultFiles = results.map((r) => path.basename(r.file)).sort();
    expect(resultFiles).toEqual(["dirty.ts", "dirty2.ts"]);
  });

  it("scanDirectory respects multiple excludePaths", () => {
    const dirs = ["vendor", "generated", "src"];
    for (const d of dirs) {
      fs.mkdirSync(path.join(tmpDir, d));
      fs.writeFileSync(
        path.join(tmpDir, d, "file.ts"),
        "AKIAIOSFODNN7EXAMPLE\n",
      );
    }

    const scanner = new RegexScanner();
    const results = scanner.scanDirectory(tmpDir, {
      excludePaths: ["generated"],
    });

    // "vendor" is in default excludes, "generated" in custom excludes
    // only "src" should be scanned
    expect(results.length).toBe(1);
    expect(results[0].file).toContain("src");
  });

  it("scanDirectory with maxDepth limits recursion", () => {
    // Create files at different depths
    fs.writeFileSync(path.join(tmpDir, "top.ts"), "AKIAIOSFODNN7EXAMPLE\n");

    const level1 = path.join(tmpDir, "level1");
    fs.mkdirSync(level1);
    fs.writeFileSync(path.join(level1, "l1.ts"), "AKIAIOSFODNN7EXAMPLE\n");

    const level2 = path.join(level1, "level2");
    fs.mkdirSync(level2);
    fs.writeFileSync(path.join(level2, "l2.ts"), "AKIAIOSFODNN7EXAMPLE\n");

    const scanner = new RegexScanner();

    const shallow = scanner.scanDirectory(tmpDir, { maxDepth: 1 });
    expect(shallow.length).toBe(1);
    expect(shallow[0].file).toContain("top.ts");

    const deeper = scanner.scanDirectory(tmpDir, { maxDepth: 3 });
    expect(deeper.length).toBe(3);
  });

  it("redact produces masked output for all secret types", () => {
    const secrets = [
      "AKIAIOSFODNN7EXAMPLE",
      "ghp_FAKEEFghijklmnopqrstuvwxyz0123456789",
      fakeSecret("sk_live", "_abcdefghijklmnopqrstuvwx"),
    ];

    const scanner = new RegexScanner();
    for (const secret of secrets) {
      const redacted = scanner.redact(`token is ${secret} here`);
      expect(redacted).not.toContain(secret);
      expect(redacted).toContain("token is");
    }
  });
});
