import { describe, it, expect, beforeAll, afterEach } from "vitest";
import { execFileSync, execSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

const CLI = path.resolve(__dirname, "../dist/index.js");

function rafter(
  args: string | string[],
  opts?: { cwd?: string; env?: Record<string, string>; input?: string },
): { stdout: string; stderr: string; exitCode: number } {
  const argList = Array.isArray(args) ? args : args.split(/\s+/);
  try {
    const result = execFileSync("node", [CLI, ...argList], {
      encoding: "utf-8",
      cwd: opts?.cwd,
      env: { ...process.env, ...opts?.env },
      stdio: ["pipe", "pipe", "pipe"],
      input: opts?.input,
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
    execSync("pnpm run build", {
      cwd: path.resolve(__dirname, ".."),
      stdio: "ignore",
      timeout: 30000,
    });
  } catch {
    // Build may have already been done
  }
}, 60000);

const sampleResults = JSON.stringify([
  {
    file: "/app/src/config.ts",
    matches: [
      {
        pattern: {
          name: "AWS Access Key",
          severity: "critical",
          description: "Detects AWS access key IDs",
        },
        line: 42,
        column: 7,
        redacted: "AKIA****MPLE",
      },
    ],
  },
  {
    file: "/app/src/utils.ts",
    matches: [
      {
        pattern: {
          name: "Generic API Key",
          severity: "medium",
          description: "Generic API key pattern",
        },
        line: 10,
        column: 1,
        redacted: "api_****_key",
      },
      {
        pattern: {
          name: "GitHub Token",
          severity: "high",
          description: "GitHub personal access token",
        },
        line: 25,
        column: 3,
        redacted: "ghp_****xxxx",
      },
    ],
  },
]);

const emptyResults = JSON.stringify([]);

describe("rafter report", () => {
  let tmpDir: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-report-test-"));
  });

  afterEach(() => {
    // Clean up any output files
    for (const f of fs.readdirSync(tmpDir)) {
      fs.unlinkSync(path.join(tmpDir, f));
    }
  });

  it("generates HTML from piped JSON input", () => {
    const r = rafter(["report"], { input: sampleResults });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("<!DOCTYPE html>");
    expect(r.stdout).toContain("Rafter Security Report");
    expect(r.stdout).toContain("Executive Summary");
    expect(r.stdout).toContain("AWS Access Key");
    expect(r.stdout).toContain("3"); // total findings
  });

  it("generates HTML from a JSON file argument", () => {
    const inputFile = path.join(tmpDir, "scan.json");
    fs.writeFileSync(inputFile, sampleResults, "utf-8");

    const r = rafter(["report", inputFile]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("<!DOCTYPE html>");
    expect(r.stdout).toContain("AWS Access Key");
  });

  it("writes to output file with -o flag", () => {
    const inputFile = path.join(tmpDir, "scan.json");
    const outputFile = path.join(tmpDir, "report.html");
    fs.writeFileSync(inputFile, sampleResults, "utf-8");

    const r = rafter(["report", inputFile, "-o", outputFile]);
    expect(r.exitCode).toBe(0);
    expect(fs.existsSync(outputFile)).toBe(true);

    const html = fs.readFileSync(outputFile, "utf-8");
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("Executive Summary");
  });

  it("supports custom title", () => {
    const r = rafter(["report", "--title", "My Audit Report"], {
      input: sampleResults,
    });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("My Audit Report");
  });

  it("shows severity breakdown correctly", () => {
    const r = rafter(["report"], { input: sampleResults });
    expect(r.exitCode).toBe(0);
    // Should contain severity section
    expect(r.stdout).toContain("Severity Breakdown");
    expect(r.stdout).toContain("Critical");
    expect(r.stdout).toContain("High");
    expect(r.stdout).toContain("Medium");
  });

  it("handles empty results gracefully", () => {
    const r = rafter(["report"], { input: emptyResults });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("<!DOCTYPE html>");
    expect(r.stdout).toContain("No Security Findings");
  });

  it("shows risk level as Critical when critical findings exist", () => {
    const r = rafter(["report"], { input: sampleResults });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("Critical");
    expect(r.stdout).toContain("Overall Risk");
  });

  it("includes detailed findings table", () => {
    const r = rafter(["report"], { input: sampleResults });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("Detailed Findings");
    expect(r.stdout).toContain("/app/src/config.ts");
    expect(r.stdout).toContain("/app/src/utils.ts");
    expect(r.stdout).toContain("AKIA****MPLE");
  });

  it("errors on invalid JSON input", () => {
    const r = rafter(["report"], { input: "not valid json" });
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("Invalid JSON");
  });

  it("errors on non-existent input file", () => {
    const r = rafter(["report", "/nonexistent/path.json"]);
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("File not found");
  });

  it("escapes HTML in file paths and patterns", () => {
    const xssResults = JSON.stringify([
      {
        file: '/app/<script>alert("xss")</script>.ts',
        matches: [
          {
            pattern: {
              name: '<img onerror="alert(1)">',
              severity: "high",
              description: 'Test "injection"',
            },
            line: 1,
            redacted: "secret",
          },
        ],
      },
    ]);

    const r = rafter(["report"], { input: xssResults });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).not.toContain("<script>");
    expect(r.stdout).toContain("&lt;script&gt;");
  });

  it("report help shows usage", () => {
    const r = rafter(["report", "--help"]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("Generate a standalone HTML security report");
  });
});
