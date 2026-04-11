import { describe, it, expect, beforeEach, afterEach, beforeAll } from "vitest";
import { execFileSync, execSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import yaml from "js-yaml";

const ROOT = path.resolve(__dirname, "../..");
const ACTION_YML = path.join(ROOT, "action.yml");
const WORKFLOWS_DIR = path.join(ROOT, ".github/workflows");
const FIXTURES_DIR = path.join(ROOT, ".github/fixtures");
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

// ── action.yml structure validation ────────────────────────────────────

describe("action.yml — structure", () => {
  let action: any;

  beforeAll(() => {
    action = yaml.load(fs.readFileSync(ACTION_YML, "utf-8"));
  });

  it("is a valid composite action", () => {
    expect(action.runs.using).toBe("composite");
    expect(action.runs.steps).toBeDefined();
    expect(action.runs.steps.length).toBeGreaterThan(0);
  });

  it("has required metadata fields", () => {
    expect(action.name).toBeTruthy();
    expect(action.description).toBeTruthy();
    expect(action.branding).toBeDefined();
    expect(action.branding.icon).toBeTruthy();
    expect(action.branding.color).toBeTruthy();
  });

  it("defines all expected inputs", () => {
    const inputNames = Object.keys(action.inputs);
    expect(inputNames).toContain("scan-path");
    expect(inputNames).toContain("args");
    expect(inputNames).toContain("version");
    expect(inputNames).toContain("install-method");
    expect(inputNames).toContain("format");
  });

  it("has sensible input defaults", () => {
    expect(action.inputs["scan-path"].default).toBe(".");
    expect(action.inputs["install-method"].default).toBe("npm");
    expect(action.inputs.format.default).toBe("json");
    expect(action.inputs.version.default).toBe("latest");
  });

  it("no inputs are required (all have defaults)", () => {
    for (const [name, input] of Object.entries<any>(action.inputs)) {
      expect(input.default, `input '${name}' should have a default`).toBeDefined();
    }
  });

  it("defines all expected outputs", () => {
    const outputNames = Object.keys(action.outputs);
    expect(outputNames).toContain("finding-count");
    expect(outputNames).toContain("report");
    expect(outputNames).toContain("exit-code");
  });

  it("outputs reference the scan step", () => {
    for (const [name, output] of Object.entries<any>(action.outputs)) {
      expect(
        output.value,
        `output '${name}' should reference steps.scan`,
      ).toContain("steps.scan.outputs");
    }
  });

  it("all composite steps have shell: bash", () => {
    for (const step of action.runs.steps) {
      if (step.run) {
        expect(step.shell, `step '${step.name}' must specify shell`).toBe("bash");
      }
    }
  });

  it("has conditional steps for npm vs pip install", () => {
    const npmStep = action.runs.steps.find(
      (s: any) => s.name && s.name.toLowerCase().includes("npm"),
    );
    const pipStep = action.runs.steps.find(
      (s: any) => s.name && s.name.toLowerCase().includes("pip"),
    );
    expect(npmStep).toBeDefined();
    expect(pipStep).toBeDefined();
    expect(npmStep.if).toContain("npm");
    expect(pipStep.if).toContain("pip");
  });

  it("scan step has id 'scan'", () => {
    const scanStep = action.runs.steps.find((s: any) => s.id === "scan");
    expect(scanStep).toBeDefined();
    expect(scanStep.run).toContain("rafter scan local");
  });
});

// ── action.yml shell script logic ──────────────────────────────────────

describe("action.yml — scan script logic", () => {
  let scanScript: string;

  beforeAll(() => {
    const action: any = yaml.load(fs.readFileSync(ACTION_YML, "utf-8"));
    const scanStep = action.runs.steps.find((s: any) => s.id === "scan");
    scanScript = scanStep.run;
  });

  it("captures exit code with set +e", () => {
    expect(scanScript).toContain("set +e");
  });

  it("writes exit-code to GITHUB_OUTPUT", () => {
    expect(scanScript).toContain('exit-code=');
    expect(scanScript).toContain("GITHUB_OUTPUT");
  });

  it("writes finding-count to GITHUB_OUTPUT", () => {
    expect(scanScript).toContain("finding-count=");
  });

  it("writes report with heredoc delimiter to GITHUB_OUTPUT", () => {
    expect(scanScript).toContain("report<<");
    expect(scanScript).toContain("RAFTER_EOF");
  });

  it("uses jq for JSON finding count extraction", () => {
    expect(scanScript).toContain("jq");
  });

  it("exits with the scanner exit code", () => {
    expect(scanScript).toContain("exit ${EXIT_CODE}");
  });

  it("invokes rafter scan local with inputs", () => {
    expect(scanScript).toContain("rafter scan local");
    expect(scanScript).toContain("inputs.scan-path");
    expect(scanScript).toContain("inputs.format");
  });
});

// ── Workflow file validation ───────────────────────────────────────────

describe("workflow files — YAML validity", () => {
  const workflowFiles = fs
    .readdirSync(WORKFLOWS_DIR)
    .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"));

  it("workflows directory contains workflow files", () => {
    expect(workflowFiles.length).toBeGreaterThan(0);
  });

  for (const file of workflowFiles) {
    it(`${file} is valid YAML`, () => {
      const content = fs.readFileSync(path.join(WORKFLOWS_DIR, file), "utf-8");
      const parsed = yaml.load(content);
      expect(parsed).toBeDefined();
      expect(parsed).not.toBeNull();
    });

    it(`${file} has a name field`, () => {
      const content = fs.readFileSync(path.join(WORKFLOWS_DIR, file), "utf-8");
      const parsed: any = yaml.load(content);
      expect(parsed.name).toBeTruthy();
    });

    it(`${file} has an 'on' trigger`, () => {
      const content = fs.readFileSync(path.join(WORKFLOWS_DIR, file), "utf-8");
      const parsed: any = yaml.load(content);
      expect(parsed.on || parsed.true).toBeDefined();
    });

    it(`${file} has at least one job`, () => {
      const content = fs.readFileSync(path.join(WORKFLOWS_DIR, file), "utf-8");
      const parsed: any = yaml.load(content);
      expect(parsed.jobs).toBeDefined();
      expect(Object.keys(parsed.jobs).length).toBeGreaterThan(0);
    });

    it(`${file} — all jobs specify runs-on`, () => {
      const content = fs.readFileSync(path.join(WORKFLOWS_DIR, file), "utf-8");
      const parsed: any = yaml.load(content);
      for (const [jobName, job] of Object.entries<any>(parsed.jobs)) {
        // strategy.matrix.os counts as runs-on via ${{ matrix.os }}
        if (job["runs-on"]) {
          expect(job["runs-on"]).toBeTruthy();
        } else {
          expect(
            job.strategy?.matrix?.os,
            `job '${jobName}' in ${file} needs runs-on or matrix.os`,
          ).toBeDefined();
        }
      }
    });
  }
});

// ── test-action.yml — specific validation ──────────────────────────────

describe("test-action.yml — composite action tests", () => {
  let workflow: any;

  beforeAll(() => {
    workflow = yaml.load(
      fs.readFileSync(path.join(WORKFLOWS_DIR, "test-action.yml"), "utf-8"),
    );
  });

  it("triggers on action.yml changes", () => {
    const paths = workflow.on.push?.paths || [];
    expect(paths).toContain("action.yml");
  });

  it("triggers on fixture changes", () => {
    const pushPaths = workflow.on.push?.paths || [];
    const prPaths = workflow.on.pull_request?.paths || [];
    const allPaths = [...pushPaths, ...prPaths];
    expect(allPaths.some((p: string) => p.includes("fixtures"))).toBe(true);
  });

  it("supports manual dispatch", () => {
    expect(workflow.on.workflow_dispatch).toBeDefined();
  });

  it("has a job that tests secret detection", () => {
    const jobNames = Object.keys(workflow.jobs);
    const detectJob = jobNames.find((n) => n.includes("detect") || n.includes("secret"));
    expect(detectJob).toBeDefined();
  });

  it("has a job that tests clean scan", () => {
    const jobNames = Object.keys(workflow.jobs);
    const cleanJob = jobNames.find((n) => n.includes("clean"));
    expect(cleanJob).toBeDefined();
  });

  it("has a job that tests pip install method", () => {
    const jobNames = Object.keys(workflow.jobs);
    const pipJob = jobNames.find((n) => n.includes("pip"));
    expect(pipJob).toBeDefined();
  });

  it("uses local action reference (./) for testing", () => {
    const jobs = Object.values<any>(workflow.jobs);
    const usesLocal = jobs.some((job) =>
      job.steps?.some((step: any) => step.uses === "./"),
    );
    expect(usesLocal).toBe(true);
  });

  it("detection job uses continue-on-error for scan step", () => {
    const detectJob =
      workflow.jobs["test-action-detects-secrets"];
    const scanStep = detectJob.steps.find(
      (s: any) => s.id === "scan",
    );
    expect(scanStep["continue-on-error"]).toBe(true);
  });

  it("detection job verifies exit code 1", () => {
    const detectJob =
      workflow.jobs["test-action-detects-secrets"];
    const verifyStep = detectJob.steps.find(
      (s: any) => s.name && s.name.toLowerCase().includes("verify"),
    );
    expect(verifyStep).toBeDefined();
    expect(verifyStep.run).toContain("exit-code");
  });
});

// ── test-comprehensive.yml — specific validation ───────────────────────

describe("test-comprehensive.yml — CI matrix", () => {
  let workflow: any;

  beforeAll(() => {
    workflow = yaml.load(
      fs.readFileSync(
        path.join(WORKFLOWS_DIR, "test-comprehensive.yml"),
        "utf-8",
      ),
    );
  });

  it("has both node and python test jobs", () => {
    const jobNames = Object.keys(workflow.jobs);
    expect(jobNames.some((n) => n.includes("node"))).toBe(true);
    expect(jobNames.some((n) => n.includes("python"))).toBe(true);
  });

  it("has cross-platform job with OS matrix", () => {
    const crossPlatform = workflow.jobs["cross-platform"];
    expect(crossPlatform).toBeDefined();
    expect(crossPlatform.strategy.matrix.os).toContain("ubuntu-latest");
    expect(crossPlatform.strategy.matrix.os).toContain("macos-latest");
  });

  it("cross-platform job tests multiple Node versions", () => {
    const matrix = workflow.jobs["cross-platform"].strategy.matrix;
    expect(matrix.node.length).toBeGreaterThanOrEqual(2);
    expect(matrix.node).toContain("20");
  });

  it("test-node job uses pnpm", () => {
    const nodeJob = workflow.jobs["test-node"];
    const pnpmStep = nodeJob.steps.find(
      (s: any) => s.run && s.run.includes("pnpm"),
    );
    expect(pnpmStep).toBeDefined();
  });

  it("test-python job installs pytest", () => {
    const pyJob = workflow.jobs["test-python"];
    const installStep = pyJob.steps.find(
      (s: any) => s.run && s.run.includes("pytest"),
    );
    expect(installStep).toBeDefined();
  });

  it("backend-api job gates test step on API key", () => {
    const apiJob = workflow.jobs["backend-api"];
    expect(apiJob).toBeDefined();
    expect(apiJob.env.RAFTER_API_KEY).toBeDefined();
    const testStep = apiJob.steps.find((s: any) => s.run?.includes("vitest"));
    expect(testStep).toBeDefined();
    expect(testStep.if).toContain("RAFTER_API_KEY");
  });

  it("SARIF validation job exists", () => {
    expect(workflow.jobs["sarif-validation"]).toBeDefined();
  });

  it("package-integrity job tests npm pack and install", () => {
    const pkgJob = workflow.jobs["package-integrity"];
    expect(pkgJob).toBeDefined();
    const packStep = pkgJob.steps.find(
      (s: any) => s.run && s.run.includes("npm pack"),
    );
    expect(packStep).toBeDefined();
  });
});

// ── publish.yml — release pipeline validation ──────────────────────────

describe("publish.yml — release pipeline", () => {
  let workflow: any;

  beforeAll(() => {
    workflow = yaml.load(
      fs.readFileSync(path.join(WORKFLOWS_DIR, "publish.yml"), "utf-8"),
    );
  });

  it("triggers only on push to prod branch", () => {
    expect(workflow.on.push.branches).toContain("prod");
    expect(workflow.on.push.branches).not.toContain("main");
  });

  it("publish-node depends on test jobs", () => {
    const pubNode = workflow.jobs["publish-node"];
    expect(pubNode.needs).toBeDefined();
    expect(pubNode.needs).toContain("test-node");
  });

  it("publish-node uses npm registry", () => {
    const pubNode = workflow.jobs["publish-node"];
    const setupStep = pubNode.steps.find(
      (s: any) => s.uses && s.uses.includes("setup-node"),
    );
    expect(setupStep.with["registry-url"]).toContain("registry.npmjs.org");
  });

  it("publish-python uses twine", () => {
    const pubPy = workflow.jobs["publish-python"];
    const publishStep = pubPy.steps.find(
      (s: any) => s.run && s.run.includes("twine upload"),
    );
    expect(publishStep).toBeDefined();
  });

  it("create-release depends on both publish jobs", () => {
    const release = workflow.jobs["create-release"];
    expect(release.needs).toContain("publish-node");
    expect(release.needs).toContain("publish-python");
  });

  it("smoke tests run after publish and release", () => {
    const smokeNode = workflow.jobs["smoke-test-node"];
    const smokePy = workflow.jobs["smoke-test-python"];
    expect(smokeNode.needs).toContain("publish-node");
    expect(smokePy.needs).toContain("publish-python");
  });

  it("smoke tests verify rafter --version", () => {
    const smokeNode = workflow.jobs["smoke-test-node"];
    const versionStep = smokeNode.steps.find(
      (s: any) => s.run && s.run.includes("rafter --version"),
    );
    expect(versionStep).toBeDefined();
  });
});

// ── validate-release.yml — version sync ────────────────────────────────

describe("validate-release.yml — version enforcement", () => {
  let workflow: any;

  beforeAll(() => {
    workflow = yaml.load(
      fs.readFileSync(
        path.join(WORKFLOWS_DIR, "validate-release.yml"),
        "utf-8",
      ),
    );
  });

  it("triggers on PRs to prod and pushes to main", () => {
    expect(workflow.on.pull_request.branches).toContain("prod");
    expect(workflow.on.push.branches).toContain("main");
  });

  it("has a job that validates version sync", () => {
    expect(workflow.jobs["validate-versions"]).toBeDefined();
  });

  it("extracts both Node and Python versions", () => {
    const job = workflow.jobs["validate-versions"];
    const steps = job.steps.map((s: any) => s.name || "");
    expect(steps.some((n: string) => n.toLowerCase().includes("node version"))).toBe(true);
    expect(steps.some((n: string) => n.toLowerCase().includes("python version"))).toBe(true);
  });

  it("has a step that compares versions", () => {
    const job = workflow.jobs["validate-versions"];
    const matchStep = job.steps.find(
      (s: any) => s.run && s.run.includes("NODE_VERSION") && s.run.includes("PYTHON_VERSION"),
    );
    expect(matchStep).toBeDefined();
  });
});

// ── Cross-workflow consistency ──────────────────────────────────────────

describe("cross-workflow consistency", () => {
  const workflows: Record<string, any> = {};

  beforeAll(() => {
    const files = fs
      .readdirSync(WORKFLOWS_DIR)
      .filter((f) => f.endsWith(".yml"));
    for (const file of files) {
      workflows[file] = yaml.load(
        fs.readFileSync(path.join(WORKFLOWS_DIR, file), "utf-8"),
      );
    }
  });

  it("all workflows use actions/checkout@v4", () => {
    for (const [file, wf] of Object.entries<any>(workflows)) {
      for (const [jobName, job] of Object.entries<any>(wf.jobs)) {
        const checkoutStep = job.steps?.find(
          (s: any) => s.uses && s.uses.startsWith("actions/checkout"),
        );
        if (checkoutStep) {
          expect(
            checkoutStep.uses,
            `${file}/${jobName} should use checkout@v4`,
          ).toBe("actions/checkout@v4");
        }
      }
    }
  });

  it("all Node setup steps use consistent version", () => {
    const nodeVersions = new Set<string>();
    for (const wf of Object.values<any>(workflows)) {
      for (const job of Object.values<any>(wf.jobs)) {
        const setupNode = job.steps?.find(
          (s: any) => s.uses && s.uses.includes("setup-node"),
        );
        if (setupNode?.with?.["node-version"]) {
          nodeVersions.add(String(setupNode.with["node-version"]));
        }
      }
    }
    // Primary node version should be consistent (cross-platform matrix may differ)
    expect(nodeVersions.has("20")).toBe(true);
  });

  it("all workflows checking out code use actions/checkout", () => {
    for (const [file, wf] of Object.entries<any>(workflows)) {
      for (const [jobName, job] of Object.entries<any>(wf.jobs)) {
        if (!job.steps || job.steps.length === 0) continue;
        const firstStep = job.steps[0];
        // First step should be checkout in most cases
        if (firstStep.uses) {
          expect(
            firstStep.uses,
            `${file}/${jobName} first step should be checkout`,
          ).toContain("checkout");
        }
      }
    }
  });
});

// ── Fixture files ──────────────────────────────────────────────────────

describe("fixture files for action testing", () => {
  it("fake-secret.txt fixture exists", () => {
    expect(fs.existsSync(path.join(FIXTURES_DIR, "fake-secret.txt"))).toBe(true);
  });

  it("fake-secret.txt contains a detectable secret pattern", () => {
    const content = fs.readFileSync(
      path.join(FIXTURES_DIR, "fake-secret.txt"),
      "utf-8",
    );
    // Should contain something matching AWS key pattern
    expect(content).toMatch(/AKIA[A-Z0-9]{16}/);
  });

  it("CLI detects secrets in fixture file", () => {
    const r = rafter(
      ["scan", "local", FIXTURES_DIR, "--engine", "patterns", "--format", "json"],
    );
    expect(r.exitCode).toBe(1);
    // stdout or stderr should contain JSON scan results with findings
    const combined = r.stdout + r.stderr;
    expect(combined).toContain("AWS");
    expect(combined).toContain("matches");
  }, 15000);
});

// ── action.yml — install method scripts ────────────────────────────────

describe("action.yml — install scripts", () => {
  let action: any;

  beforeAll(() => {
    action = yaml.load(fs.readFileSync(ACTION_YML, "utf-8"));
  });

  it("npm install supports version pinning", () => {
    const npmStep = action.runs.steps.find(
      (s: any) => s.name && s.name.toLowerCase().includes("npm"),
    );
    expect(npmStep.run).toContain("@rafter-security/cli@");
    expect(npmStep.run).toContain("inputs.version");
  });

  it("pip install supports version pinning", () => {
    const pipStep = action.runs.steps.find(
      (s: any) => s.name && s.name.toLowerCase().includes("pip"),
    );
    expect(pipStep.run).toContain("rafter-cli==");
    expect(pipStep.run).toContain("inputs.version");
  });

  it("npm install handles 'latest' without version suffix", () => {
    const npmStep = action.runs.steps.find(
      (s: any) => s.name && s.name.toLowerCase().includes("npm"),
    );
    // Should have conditional logic for latest vs specific version
    expect(npmStep.run).toContain("latest");
    expect(npmStep.run).toContain("@rafter-security/cli\n");
  });

  it("pip install handles 'latest' without version suffix", () => {
    const pipStep = action.runs.steps.find(
      (s: any) => s.name && s.name.toLowerCase().includes("pip"),
    );
    expect(pipStep.run).toContain("latest");
    // When latest, should install without ==version
    expect(pipStep.run).toMatch(/pip install rafter-cli\n/);
  });
});
