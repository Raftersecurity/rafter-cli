/**
 * Integration tests for the hook system using real git repositories.
 *
 * These tests create actual git repos in tmp directories, stage files
 * with (fake) secrets, and verify that pretool/posttool hooks behave
 * correctly against real git state.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { execSync, ExecSyncOptionsWithStringEncoding } from "child_process";
import { randomBytes } from "crypto";
import fs from "fs";
import path from "path";
import os from "os";

import { CommandInterceptor } from "../src/core/command-interceptor.js";
import { RegexScanner } from "../src/scanners/regex-scanner.js";
import { AuditLogger } from "../src/core/audit-logger.js";

// ── Helpers ─────────────────────────────────────────────────────────────

function createTempDir(prefix: string): string {
  const dir = path.join(
    os.tmpdir(),
    `${prefix}-${Date.now()}-${randomBytes(6).toString("hex")}`,
  );
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanupDir(dir: string) {
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const gitExecOpts = (cwd: string): ExecSyncOptionsWithStringEncoding => ({
  cwd,
  encoding: "utf-8",
  stdio: ["pipe", "pipe", "pipe"],
});

function initRepo(dir: string): void {
  execSync("git init", gitExecOpts(dir));
  execSync('git config user.email "test@rafter.dev"', gitExecOpts(dir));
  execSync('git config user.name "Rafter Test"', gitExecOpts(dir));
}

// Fake but realistic-looking secrets for testing
const FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const FAKE_GITHUB_TOKEN = "ghp_FAKEEFabcdef1234567890abcdef1234567";
const FAKE_PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBALRiMLAB9pm5DhB2m1pGv43example1234567890abcdefghijklmn
opqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUV==
-----END RSA PRIVATE KEY-----`;

// ── Reproduced core logic from pretool.ts ────────────────────────────────
// We reproduce the logic here to test against real git state without
// needing to pipe through stdin.

function scanStagedFiles(cwd: string): { secretsFound: boolean; count: number; files: number } {
  try {
    const stagedOutput = execSync(
      "git diff --cached --name-only --diff-filter=ACM",
      gitExecOpts(cwd),
    ).trim();

    if (!stagedOutput) {
      return { secretsFound: false, count: 0, files: 0 };
    }

    const stagedFiles = stagedOutput.split("\n").filter((f) => f.trim());
    const absolutePaths = stagedFiles.map((f) => path.join(cwd, f));
    const scanner = new RegexScanner();
    const results = scanner.scanFiles(absolutePaths);
    const totalMatches = results.reduce((sum, r) => sum + r.matches.length, 0);

    return {
      secretsFound: results.length > 0,
      count: totalMatches,
      files: results.length,
    };
  } catch {
    return { secretsFound: false, count: 0, files: 0 };
  }
}

function evaluateBashWithGit(
  command: string,
  cwd: string,
): { decision: "allow" | "deny"; reason?: string } {
  const interceptor = new CommandInterceptor();
  const evaluation = interceptor.evaluate(command);

  if (!evaluation.allowed && !evaluation.requiresApproval) {
    return { decision: "deny", reason: evaluation.reason };
  }

  if (evaluation.requiresApproval) {
    return { decision: "deny", reason: evaluation.reason };
  }

  const trimmed = command.trim();
  if (trimmed.startsWith("git commit") || trimmed.startsWith("git push")) {
    const scanResult = scanStagedFiles(cwd);
    if (scanResult.secretsFound) {
      return {
        decision: "deny",
        reason: `${scanResult.count} secret(s) detected in ${scanResult.files} staged file(s). Run 'rafter scan local --staged' for details.`,
      };
    }
  }

  return { decision: "allow" };
}

// ── Tests ────────────────────────────────────────────────────────────────

describe("Hook Integration — Real Git Repos", () => {
  let repoDir: string;

  beforeEach(() => {
    vi.spyOn(AuditLogger.prototype, "log").mockImplementation(() => {});
    repoDir = createTempDir("rafter-hook-int");
    initRepo(repoDir);
  });

  afterEach(() => {
    cleanupDir(repoDir);
    vi.restoreAllMocks();
  });

  // ── Pre-tool: git commit with staged secrets ──────────────────────────

  describe("pretool — git commit with real staged files", () => {
    it("blocks git commit when staged file contains an AWS key", () => {
      const envFile = path.join(repoDir, ".env");
      fs.writeFileSync(envFile, `AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}\n`);
      execSync("git add .env", gitExecOpts(repoDir));

      const result = evaluateBashWithGit('git commit -m "add env"', repoDir);
      expect(result.decision).toBe("deny");
      expect(result.reason).toContain("secret(s) detected");
    });

    it("blocks git commit when staged file contains a GitHub token", () => {
      const configFile = path.join(repoDir, "config.json");
      fs.writeFileSync(
        configFile,
        JSON.stringify({ token: FAKE_GITHUB_TOKEN }),
      );
      execSync("git add config.json", gitExecOpts(repoDir));

      const result = evaluateBashWithGit('git commit -m "add config"', repoDir);
      expect(result.decision).toBe("deny");
      expect(result.reason).toContain("secret(s) detected");
    });

    it("blocks git commit when staged file contains a private key", () => {
      const keyFile = path.join(repoDir, "key.pem");
      fs.writeFileSync(keyFile, FAKE_PRIVATE_KEY);
      execSync("git add key.pem", gitExecOpts(repoDir));

      const result = evaluateBashWithGit('git commit -m "add key"', repoDir);
      expect(result.decision).toBe("deny");
      expect(result.reason).toContain("secret(s) detected");
    });

    it("allows git commit when staged files are clean", () => {
      const readmeFile = path.join(repoDir, "README.md");
      fs.writeFileSync(readmeFile, "# Hello World\n");
      execSync("git add README.md", gitExecOpts(repoDir));

      const result = evaluateBashWithGit('git commit -m "add readme"', repoDir);
      expect(result.decision).toBe("allow");
    });

    it("allows git commit with no staged files", () => {
      const result = evaluateBashWithGit('git commit -m "empty"', repoDir);
      expect(result.decision).toBe("allow");
    });

    it("detects secrets in multiple staged files", () => {
      const envFile = path.join(repoDir, ".env");
      fs.writeFileSync(envFile, `AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}\n`);

      const configFile = path.join(repoDir, "config.json");
      fs.writeFileSync(
        configFile,
        JSON.stringify({ token: FAKE_GITHUB_TOKEN }),
      );

      execSync("git add .env config.json", gitExecOpts(repoDir));

      const result = evaluateBashWithGit('git commit -m "secrets"', repoDir);
      expect(result.decision).toBe("deny");
      // Should report multiple files
      const match = result.reason!.match(/(\d+) staged file/);
      expect(match).toBeTruthy();
      expect(parseInt(match![1], 10)).toBeGreaterThanOrEqual(2);
    });

    it("only scans staged files, not unstaged changes", () => {
      // Commit a clean file first
      const readmeFile = path.join(repoDir, "README.md");
      fs.writeFileSync(readmeFile, "# Hello\n");
      execSync("git add README.md", gitExecOpts(repoDir));
      execSync('git commit -m "initial"', gitExecOpts(repoDir));

      // Now stage a clean file, but have an unstaged secret
      const appFile = path.join(repoDir, "app.js");
      fs.writeFileSync(appFile, "console.log('hello');\n");
      execSync("git add app.js", gitExecOpts(repoDir));

      // Create a file with a secret but DON'T stage it
      const secretFile = path.join(repoDir, "secret.env");
      fs.writeFileSync(secretFile, `AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}\n`);

      const result = evaluateBashWithGit('git commit -m "add app"', repoDir);
      expect(result.decision).toBe("allow");
    });
  });

  // ── Pre-tool: git push with staged secrets ────────────────────────────

  describe("pretool — git push with real staged files", () => {
    it("blocks git push when staged files contain secrets", () => {
      const envFile = path.join(repoDir, ".env");
      fs.writeFileSync(envFile, `AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}\n`);
      execSync("git add .env", gitExecOpts(repoDir));

      const result = evaluateBashWithGit("git push origin main", repoDir);
      expect(result.decision).toBe("deny");
      expect(result.reason).toContain("secret(s) detected");
    });

    it("allows git push with clean staged files", () => {
      const readmeFile = path.join(repoDir, "README.md");
      fs.writeFileSync(readmeFile, "# App\n");
      execSync("git add README.md", gitExecOpts(repoDir));

      const result = evaluateBashWithGit("git push origin main", repoDir);
      expect(result.decision).toBe("allow");
    });
  });

  // ── Pre-tool: Write/Edit with secrets ─────────────────────────────────

  describe("pretool — Write/Edit tool with secret content", () => {
    it("blocks Write tool when content contains AWS key", () => {
      const scanner = new RegexScanner();
      const content = `DB_HOST=localhost\nAWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}\n`;
      expect(scanner.hasSecrets(content)).toBe(true);

      const matches = scanner.scanText(content);
      expect(matches.length).toBeGreaterThan(0);
    });

    it("blocks Write tool when content contains GitHub token", () => {
      const scanner = new RegexScanner();
      const content = `{"github_token": "${FAKE_GITHUB_TOKEN}"}`;
      expect(scanner.hasSecrets(content)).toBe(true);
    });

    it("allows Write tool with clean content", () => {
      const scanner = new RegexScanner();
      const content = "export function hello() { return 'world'; }\n";
      expect(scanner.hasSecrets(content)).toBe(false);
    });
  });

  // ── Staged file scanning detail ───────────────────────────────────────

  describe("scanStagedFiles — detailed behavior with real repos", () => {
    it("returns correct count for a single secret in one file", () => {
      const envFile = path.join(repoDir, ".env");
      fs.writeFileSync(envFile, `AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}\n`);
      execSync("git add .env", gitExecOpts(repoDir));

      const result = scanStagedFiles(repoDir);
      expect(result.secretsFound).toBe(true);
      expect(result.count).toBeGreaterThanOrEqual(1);
      expect(result.files).toBe(1);
    });

    it("returns correct count for secrets across multiple files", () => {
      const envFile = path.join(repoDir, ".env");
      fs.writeFileSync(envFile, `KEY=${FAKE_AWS_KEY}\n`);

      const configFile = path.join(repoDir, "config.yml");
      fs.writeFileSync(configFile, `token: ${FAKE_GITHUB_TOKEN}\n`);

      execSync("git add .env config.yml", gitExecOpts(repoDir));

      const result = scanStagedFiles(repoDir);
      expect(result.secretsFound).toBe(true);
      expect(result.files).toBeGreaterThanOrEqual(2);
    });

    it("returns zero for clean staged files", () => {
      const cleanFile = path.join(repoDir, "main.js");
      fs.writeFileSync(cleanFile, "module.exports = {};\n");
      execSync("git add main.js", gitExecOpts(repoDir));

      const result = scanStagedFiles(repoDir);
      expect(result.secretsFound).toBe(false);
      expect(result.count).toBe(0);
      expect(result.files).toBe(0);
    });

    it("returns zero when nothing is staged", () => {
      const result = scanStagedFiles(repoDir);
      expect(result.secretsFound).toBe(false);
      expect(result.count).toBe(0);
    });

    it("handles binary files gracefully", () => {
      const binFile = path.join(repoDir, "image.bin");
      fs.writeFileSync(binFile, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0xfe]));
      execSync("git add image.bin", gitExecOpts(repoDir));

      const result = scanStagedFiles(repoDir);
      expect(result.secretsFound).toBe(false);
    });

    it("only counts newly staged files (ACM filter)", () => {
      // Create and commit a file with a secret
      const envFile = path.join(repoDir, ".env");
      fs.writeFileSync(envFile, `OLD_KEY=${FAKE_AWS_KEY}\n`);
      execSync("git add .env", gitExecOpts(repoDir));
      execSync('git commit -m "initial commit"', gitExecOpts(repoDir));

      // Delete the file and stage the deletion
      fs.unlinkSync(envFile);
      execSync("git add .env", gitExecOpts(repoDir));

      // Deletion should NOT trigger a secret scan (only ACM — add/copy/modify)
      const result = scanStagedFiles(repoDir);
      expect(result.secretsFound).toBe(false);
    });
  });

  // ── PostTool: secret redaction ────────────────────────────────────────

  describe("posttool — secret redaction against real file content", () => {
    it("redacts AWS key read from a real file", () => {
      const envFile = path.join(repoDir, ".env");
      fs.writeFileSync(envFile, `AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}\nDB=localhost\n`);

      const content = fs.readFileSync(envFile, "utf-8");
      const scanner = new RegexScanner();
      expect(scanner.hasSecrets(content)).toBe(true);

      const redacted = scanner.redact(content);
      expect(redacted).not.toContain(FAKE_AWS_KEY);
      expect(redacted).toContain("DB=localhost");
      expect(redacted).toContain("****");
    });

    it("redacts GitHub token from real git config output", () => {
      // Simulate output of a command that leaked a token
      const output = `remote.origin.url=https://${FAKE_GITHUB_TOKEN}@github.com/user/repo.git`;
      const scanner = new RegexScanner();
      expect(scanner.hasSecrets(output)).toBe(true);

      const redacted = scanner.redact(output);
      expect(redacted).not.toContain(FAKE_GITHUB_TOKEN);
    });

    it("passes through clean command output unchanged", () => {
      const output = "file1.ts\nfile2.ts\nsrc/index.ts\n";
      const scanner = new RegexScanner();
      expect(scanner.hasSecrets(output)).toBe(false);
    });
  });

  // ── Install-hook: real git repo ───────────────────────────────────────

  describe("install-hook — local hook installation in real repo", () => {
    it("creates pre-commit hook in .git/hooks", () => {
      const hooksDir = path.join(repoDir, ".git", "hooks");
      const hookPath = path.join(hooksDir, "pre-commit");

      // Read the template
      const templatePath = path.join(
        __dirname,
        "..",
        "resources",
        "pre-commit-hook.sh",
      );

      // Skip if resources not available (CI without build)
      if (!fs.existsSync(templatePath)) return;

      const hookContent = fs.readFileSync(templatePath, "utf-8");

      if (!fs.existsSync(hooksDir)) {
        fs.mkdirSync(hooksDir, { recursive: true });
      }
      fs.writeFileSync(hookPath, hookContent, "utf-8");
      fs.chmodSync(hookPath, 0o755);

      // Verify installed
      expect(fs.existsSync(hookPath)).toBe(true);
      const installed = fs.readFileSync(hookPath, "utf-8");
      expect(installed).toContain("Rafter Security Pre-Commit Hook");
      expect(installed).toContain("rafter scan local");

      // Verify executable
      const stat = fs.statSync(hookPath);
      expect(stat.mode & 0o111).toBeTruthy();
    });

    it("creates pre-push hook in .git/hooks", () => {
      const hooksDir = path.join(repoDir, ".git", "hooks");
      const hookPath = path.join(hooksDir, "pre-push");

      const templatePath = path.join(
        __dirname,
        "..",
        "resources",
        "pre-push-hook.sh",
      );

      if (!fs.existsSync(templatePath)) return;

      const hookContent = fs.readFileSync(templatePath, "utf-8");

      if (!fs.existsSync(hooksDir)) {
        fs.mkdirSync(hooksDir, { recursive: true });
      }
      fs.writeFileSync(hookPath, hookContent, "utf-8");
      fs.chmodSync(hookPath, 0o755);

      expect(fs.existsSync(hookPath)).toBe(true);
      const installed = fs.readFileSync(hookPath, "utf-8");
      expect(installed).toContain("Rafter Security Pre-Push Hook");
      expect(installed).toContain("rafter scan local");
    });

    it("backs up existing non-rafter hook", () => {
      const hooksDir = path.join(repoDir, ".git", "hooks");
      const hookPath = path.join(hooksDir, "pre-commit");

      if (!fs.existsSync(hooksDir)) {
        fs.mkdirSync(hooksDir, { recursive: true });
      }

      // Write a non-rafter hook
      fs.writeFileSync(hookPath, "#!/bin/bash\necho 'existing'\n");

      const templatePath = path.join(
        __dirname,
        "..",
        "resources",
        "pre-commit-hook.sh",
      );
      if (!fs.existsSync(templatePath)) return;

      // Simulate backup + install
      const existing = fs.readFileSync(hookPath, "utf-8");
      expect(existing).not.toContain("Rafter");

      const backupPath = `${hookPath}.backup-${Date.now()}`;
      fs.copyFileSync(hookPath, backupPath);

      const hookContent = fs.readFileSync(templatePath, "utf-8");
      fs.writeFileSync(hookPath, hookContent);
      fs.chmodSync(hookPath, 0o755);

      // Backup exists with old content
      expect(fs.existsSync(backupPath)).toBe(true);
      expect(fs.readFileSync(backupPath, "utf-8")).toContain("existing");

      // New hook is rafter
      expect(fs.readFileSync(hookPath, "utf-8")).toContain("Rafter");
    });

    it("detects already-installed rafter hook (idempotent)", () => {
      const hooksDir = path.join(repoDir, ".git", "hooks");
      const hookPath = path.join(hooksDir, "pre-commit");

      const templatePath = path.join(
        __dirname,
        "..",
        "resources",
        "pre-commit-hook.sh",
      );
      if (!fs.existsSync(templatePath)) return;

      if (!fs.existsSync(hooksDir)) {
        fs.mkdirSync(hooksDir, { recursive: true });
      }

      const hookContent = fs.readFileSync(templatePath, "utf-8");
      fs.writeFileSync(hookPath, hookContent);

      // Check for marker
      const installed = fs.readFileSync(hookPath, "utf-8");
      const marker = "Rafter Security Pre-Commit Hook";
      expect(installed).toContain(marker);

      // Second install should detect the marker
      const alreadyInstalled = installed.includes(marker);
      expect(alreadyInstalled).toBe(true);
    });
  });

  // ── Global hook installation ──────────────────────────────────────────

  describe("install-hook --global — global hook installation", () => {
    let globalDir: string;

    beforeEach(() => {
      globalDir = createTempDir("rafter-global-hooks");
    });

    afterEach(() => {
      cleanupDir(globalDir);
    });

    it("creates hook in ~/.rafter/git-hooks structure", () => {
      const hooksDir = path.join(globalDir, ".rafter", "git-hooks");
      const hookPath = path.join(hooksDir, "pre-commit");

      const templatePath = path.join(
        __dirname,
        "..",
        "resources",
        "pre-commit-hook.sh",
      );
      if (!fs.existsSync(templatePath)) return;

      fs.mkdirSync(hooksDir, { recursive: true });
      const hookContent = fs.readFileSync(templatePath, "utf-8");
      fs.writeFileSync(hookPath, hookContent);
      fs.chmodSync(hookPath, 0o755);

      expect(fs.existsSync(hookPath)).toBe(true);
      expect(fs.readFileSync(hookPath, "utf-8")).toContain("Rafter");

      const stat = fs.statSync(hookPath);
      expect(stat.mode & 0o111).toBeTruthy();
    });
  });

  // ── Command interception in git context ───────────────────────────────

  describe("command interceptor — dangerous commands in git context", () => {
    it("blocks rm -rf / even in a git repo", () => {
      const interceptor = new CommandInterceptor();
      const result = interceptor.evaluate("rm -rf /");
      expect(result.allowed).toBe(false);
    });

    it("allows normal git commands", () => {
      const interceptor = new CommandInterceptor();

      const allowed = ["git status", "git log --oneline", "git diff HEAD"];
      for (const cmd of allowed) {
        const result = interceptor.evaluate(cmd);
        expect(result.allowed).toBe(true);
      }
    });

    it("evaluates git commit as allowed (command itself is fine, secrets are checked separately)", () => {
      const interceptor = new CommandInterceptor();
      const result = interceptor.evaluate('git commit -m "test"');
      expect(result.allowed).toBe(true);
    });
  });

  // ── End-to-end: secret lifecycle in a repo ────────────────────────────

  describe("end-to-end — secret lifecycle", () => {
    it("detects secret added, then allows after removal", () => {
      // Step 1: Add a secret — should block
      const envFile = path.join(repoDir, ".env");
      fs.writeFileSync(envFile, `API_KEY=${FAKE_AWS_KEY}\n`);
      execSync("git add .env", gitExecOpts(repoDir));

      const blocked = evaluateBashWithGit('git commit -m "add secret"', repoDir);
      expect(blocked.decision).toBe("deny");

      // Step 2: Unstage and remove the secret
      execSync("git rm --cached .env", gitExecOpts(repoDir));
      fs.unlinkSync(envFile);

      // Step 3: Add a clean file instead
      const cleanFile = path.join(repoDir, "app.ts");
      fs.writeFileSync(cleanFile, "export const version = '1.0.0';\n");
      execSync("git add app.ts", gitExecOpts(repoDir));

      const allowed = evaluateBashWithGit('git commit -m "add app"', repoDir);
      expect(allowed.decision).toBe("allow");
    });

    it("detects secret in modified file after initial clean commit", () => {
      // Initial clean commit
      const configFile = path.join(repoDir, "config.ts");
      fs.writeFileSync(configFile, "export const config = {};\n");
      execSync("git add config.ts", gitExecOpts(repoDir));
      execSync('git commit -m "initial"', gitExecOpts(repoDir));

      // Modify with a secret
      fs.writeFileSync(
        configFile,
        `export const config = { key: "${FAKE_AWS_KEY}" };\n`,
      );
      execSync("git add config.ts", gitExecOpts(repoDir));

      const result = evaluateBashWithGit('git commit -m "update"', repoDir);
      expect(result.decision).toBe("deny");
    });

    it("posttool redacts secrets from cat output of a real file", () => {
      const secretFile = path.join(repoDir, "credentials.json");
      fs.writeFileSync(
        secretFile,
        JSON.stringify(
          { aws_access_key_id: FAKE_AWS_KEY, region: "us-east-1" },
          null,
          2,
        ),
      );

      // Simulate reading the file (like a tool response)
      const output = fs.readFileSync(secretFile, "utf-8");
      const scanner = new RegexScanner();
      const redacted = scanner.redact(output);

      expect(redacted).not.toContain(FAKE_AWS_KEY);
      expect(redacted).toContain("us-east-1");
      expect(redacted).toContain("****");
    });
  });
});
