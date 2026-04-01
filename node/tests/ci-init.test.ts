import { describe, it, expect, beforeEach, afterEach, beforeAll } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

const CLI = path.resolve(__dirname, "../dist/index.js");

function rafter(
  args: string | string[],
  opts?: { cwd?: string },
): { stdout: string; stderr: string; exitCode: number } {
  const argList = Array.isArray(args) ? args : args.split(/\s+/);
  try {
    const result = execFileSync("node", [CLI, ...argList], {
      encoding: "utf-8",
      cwd: opts?.cwd,
      env: { ...process.env },
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

let tmpDir: string;

beforeAll(() => {
  try {
    execFileSync("pnpm", ["run", "build"], {
      cwd: path.resolve(__dirname, ".."),
      stdio: "ignore",
      timeout: 30000,
    });
  } catch {
    // dist may already exist
  }
}, 60000);

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-ci-test-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("ci init — platform detection", () => {
  it("auto-detects GitHub when .github exists", () => {
    fs.mkdirSync(path.join(tmpDir, ".github"));
    const r = rafter("ci init", { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("github");
    expect(fs.existsSync(path.join(tmpDir, ".github/workflows/rafter-security.yml"))).toBe(true);
  });

  it("auto-detects GitLab when .gitlab-ci.yml exists", () => {
    fs.writeFileSync(path.join(tmpDir, ".gitlab-ci.yml"), "stages:\n  - test\n");
    const r = rafter("ci init", { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("gitlab");
    expect(fs.existsSync(path.join(tmpDir, ".gitlab-ci-rafter.yml"))).toBe(true);
  });

  it("auto-detects CircleCI when .circleci exists", () => {
    fs.mkdirSync(path.join(tmpDir, ".circleci"));
    const r = rafter("ci init", { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("circleci");
    expect(fs.existsSync(path.join(tmpDir, ".circleci/rafter-security.yml"))).toBe(true);
  });

  it("exits 1 when no platform detected and none specified", () => {
    const r = rafter("ci init", { cwd: tmpDir });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("auto-detect");
  });
});

describe("ci init — explicit platform", () => {
  it("--platform github generates GitHub Actions config", () => {
    const r = rafter("ci init --platform github", { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    const content = fs.readFileSync(
      path.join(tmpDir, ".github/workflows/rafter-security.yml"),
      "utf-8",
    );
    expect(content).toContain("actions/checkout@v4");
    expect(content).toContain("npm install -g @rafter-security/cli");
    expect(content).toContain("rafter scan local . --quiet");
    expect(content).not.toContain("security-audit");
  });

  it("--platform gitlab generates GitLab CI config", () => {
    const r = rafter("ci init --platform gitlab", { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    const content = fs.readFileSync(path.join(tmpDir, ".gitlab-ci-rafter.yml"), "utf-8");
    expect(content).toContain("image: node:20");
    expect(content).toContain("stages:");
    expect(content).not.toContain("security-audit");
  });

  it("--platform circleci generates CircleCI config", () => {
    const r = rafter("ci init --platform circleci", { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    const content = fs.readFileSync(path.join(tmpDir, ".circleci/rafter-security.yml"), "utf-8");
    expect(content).toContain("cimg/node:20.0");
    expect(content).toContain("version: 2.1");
    expect(content).toContain("workflows:");
    expect(content).not.toContain("security-audit");
  });

  it("rejects invalid platform", () => {
    const r = rafter("ci init --platform jenkins", { cwd: tmpDir });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("Unknown platform");
  });
});

describe("ci init — --with-backend", () => {
  it("GitHub template includes security-audit job", () => {
    const r = rafter("ci init --platform github --with-backend", { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    const content = fs.readFileSync(
      path.join(tmpDir, ".github/workflows/rafter-security.yml"),
      "utf-8",
    );
    expect(content).toContain("security-audit");
    expect(content).toContain("needs: secret-scan");
    expect(content).toContain("RAFTER_API_KEY");
    expect(content).toContain("rafter run --format json --quiet");
    expect(r.stdout).toContain("Secrets");
  });

  it("GitLab template includes security-audit job", () => {
    const r = rafter("ci init --platform gitlab --with-backend", { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    const content = fs.readFileSync(path.join(tmpDir, ".gitlab-ci-rafter.yml"), "utf-8");
    expect(content).toContain("security-audit");
    expect(content).toContain("needs: [secret-scan]");
    expect(content).toContain("RAFTER_API_KEY");
  });

  it("CircleCI template includes security-audit job with requires", () => {
    const r = rafter("ci init --platform circleci --with-backend", { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    const content = fs.readFileSync(path.join(tmpDir, ".circleci/rafter-security.yml"), "utf-8");
    expect(content).toContain("security-audit");
    expect(content).toContain("requires:");
    expect(content).toContain("- secret-scan");
  });
});

describe("ci init — --output", () => {
  it("writes to custom output path", () => {
    const customPath = path.join(tmpDir, "custom/ci.yml");
    const r = rafter(["ci", "init", "--platform", "github", "--output", customPath], { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    expect(fs.existsSync(customPath)).toBe(true);
    const content = fs.readFileSync(customPath, "utf-8");
    expect(content).toContain("rafter scan local");
  });
});
