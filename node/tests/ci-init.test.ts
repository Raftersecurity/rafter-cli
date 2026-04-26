import { describe, it, expect, beforeEach, afterEach, beforeAll } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import yaml from "js-yaml";

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
    expect(content).toContain("rafter secrets . --quiet");
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
    expect(content).toContain("rafter secrets");
  });
});

describe("ci init — generated workflow YAML validation", () => {
  function readAndParse(filePath: string): any {
    const content = fs.readFileSync(filePath, "utf-8");
    return yaml.load(content);
  }

  describe("GitHub Actions", () => {
    it("generates valid YAML with required structure", () => {
      rafter("ci init --platform github", { cwd: tmpDir });
      const doc = readAndParse(path.join(tmpDir, ".github/workflows/rafter-security.yml"));
      expect(doc.name).toBe("Rafter Security");
      expect(doc.on).toBeDefined();
      expect(doc.on.push.branches).toContain("main");
      expect(doc.on.pull_request.branches).toContain("main");
      expect(doc.permissions).toEqual({ contents: "read" });
      expect(doc.jobs["secret-scan"]).toBeDefined();
      expect(doc.jobs["secret-scan"]["runs-on"]).toBe("ubuntu-latest");
    });

    it("secret-scan steps include checkout and scan", () => {
      rafter("ci init --platform github", { cwd: tmpDir });
      const doc = readAndParse(path.join(tmpDir, ".github/workflows/rafter-security.yml"));
      const steps = doc.jobs["secret-scan"].steps;
      expect(steps).toHaveLength(3);
      expect(steps[0].uses).toBe("actions/checkout@v4");
      expect(steps[1].run).toContain("@rafter-security/cli");
      expect(steps[2].run).toBe("rafter secrets . --quiet");
    });

    it("--with-backend adds security-audit job with correct dependency", () => {
      rafter("ci init --platform github --with-backend", { cwd: tmpDir });
      const doc = readAndParse(path.join(tmpDir, ".github/workflows/rafter-security.yml"));
      expect(doc.jobs["security-audit"]).toBeDefined();
      expect(doc.jobs["security-audit"].needs).toBe("secret-scan");
      expect(doc.jobs["security-audit"]["runs-on"]).toBe("ubuntu-latest");
      const auditSteps = doc.jobs["security-audit"].steps;
      const runStep = auditSteps.find((s: any) => s.run?.includes("rafter run"));
      expect(runStep).toBeDefined();
      expect(runStep.env.RAFTER_API_KEY).toContain("secrets.RAFTER_API_KEY");
    });

    it("without --with-backend has no security-audit job", () => {
      rafter("ci init --platform github", { cwd: tmpDir });
      const doc = readAndParse(path.join(tmpDir, ".github/workflows/rafter-security.yml"));
      expect(Object.keys(doc.jobs)).toEqual(["secret-scan"]);
    });
  });

  describe("GitLab CI", () => {
    it("generates valid YAML with required structure", () => {
      rafter("ci init --platform gitlab", { cwd: tmpDir });
      const doc = readAndParse(path.join(tmpDir, ".gitlab-ci-rafter.yml"));
      expect(doc.stages).toContain("security");
      expect(doc["secret-scan"]).toBeDefined();
      expect(doc["secret-scan"].stage).toBe("security");
      expect(doc["secret-scan"].image).toBe("node:20");
    });

    it("secret-scan has script and rules", () => {
      rafter("ci init --platform gitlab", { cwd: tmpDir });
      const doc = readAndParse(path.join(tmpDir, ".gitlab-ci-rafter.yml"));
      const job = doc["secret-scan"];
      expect(job.script).toBeInstanceOf(Array);
      expect(job.script).toContain("rafter secrets . --quiet");
      expect(job.rules).toBeInstanceOf(Array);
      expect(job.rules.length).toBeGreaterThanOrEqual(2);
    });

    it("--with-backend adds security-audit with needs", () => {
      rafter("ci init --platform gitlab --with-backend", { cwd: tmpDir });
      const doc = readAndParse(path.join(tmpDir, ".gitlab-ci-rafter.yml"));
      expect(doc["security-audit"]).toBeDefined();
      expect(doc["security-audit"].needs).toEqual(["secret-scan"]);
      expect(doc["security-audit"].variables.RAFTER_API_KEY).toBeDefined();
    });
  });

  describe("CircleCI", () => {
    it("generates valid YAML with required structure", () => {
      rafter("ci init --platform circleci", { cwd: tmpDir });
      const doc = readAndParse(path.join(tmpDir, ".circleci/rafter-security.yml"));
      expect(doc.version).toBe(2.1);
      expect(doc.jobs["secret-scan"]).toBeDefined();
      expect(doc.jobs["secret-scan"].docker[0].image).toBe("cimg/node:20.0");
      expect(doc.workflows).toBeDefined();
      expect(doc.workflows.security.jobs).toContain("secret-scan");
    });

    it("secret-scan steps include checkout and commands", () => {
      rafter("ci init --platform circleci", { cwd: tmpDir });
      const doc = readAndParse(path.join(tmpDir, ".circleci/rafter-security.yml"));
      const steps = doc.jobs["secret-scan"].steps;
      expect(steps[0]).toBe("checkout");
      expect(steps[1].run.command).toContain("@rafter-security/cli");
      expect(steps[2].run.command).toBe("rafter secrets . --quiet");
    });

    it("--with-backend adds security-audit with requires in workflow", () => {
      rafter("ci init --platform circleci --with-backend", { cwd: tmpDir });
      const doc = readAndParse(path.join(tmpDir, ".circleci/rafter-security.yml"));
      expect(doc.jobs["security-audit"]).toBeDefined();
      const workflowJobs = doc.workflows.security.jobs;
      const auditEntry = workflowJobs.find((j: any) => typeof j === "object" && j["security-audit"]);
      expect(auditEntry).toBeDefined();
      expect(auditEntry["security-audit"].requires).toContain("secret-scan");
    });
  });
});

describe("ci init — edge cases", () => {
  it("idempotent: running twice overwrites without error", () => {
    rafter("ci init --platform github", { cwd: tmpDir });
    const r = rafter("ci init --platform github", { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    const doc = yaml.load(
      fs.readFileSync(path.join(tmpDir, ".github/workflows/rafter-security.yml"), "utf-8"),
    ) as any;
    expect(doc.jobs["secret-scan"]).toBeDefined();
  });

  it("auto-detect prefers github when both .github and .circleci exist", () => {
    fs.mkdirSync(path.join(tmpDir, ".github"));
    fs.mkdirSync(path.join(tmpDir, ".circleci"));
    const r = rafter("ci init", { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("github");
    expect(fs.existsSync(path.join(tmpDir, ".github/workflows/rafter-security.yml"))).toBe(true);
  });

  it("creates nested output directories", () => {
    const deep = path.join(tmpDir, "a/b/c/d/workflow.yml");
    const r = rafter(["ci", "init", "--platform", "github", "--output", deep], { cwd: tmpDir });
    expect(r.exitCode).toBe(0);
    expect(fs.existsSync(deep)).toBe(true);
  });
});
