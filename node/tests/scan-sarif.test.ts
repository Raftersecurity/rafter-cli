import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { execSync } from "child_process";
import path from "path";
import fs from "fs";
import os from "os";

const CLI_PATH = path.resolve(__dirname, "../src/index.ts");

/**
 * Helper to run the CLI scan command via tsx and return parsed output.
 */
function runScan(args: string, cwd?: string): { stdout: string; stderr: string; exitCode: number } {
  try {
    const stdout = execSync(`npx tsx ${CLI_PATH} agent scan ${args}`, {
      encoding: "utf-8",
      cwd: cwd || process.cwd(),
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, NO_COLOR: "1" },
    });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (e: any) {
    return {
      stdout: e.stdout || "",
      stderr: e.stderr || "",
      exitCode: e.status ?? 1,
    };
  }
}

describe("scan --format sarif", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-sarif-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should output valid SARIF 2.1.0 structure with no findings", () => {
    // Create a clean file with no secrets
    fs.writeFileSync(path.join(tmpDir, "clean.ts"), 'const x = "hello world";\n');

    const result = runScan(`${tmpDir} --format sarif`);
    const sarif = JSON.parse(result.stdout);

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("rafter");
    expect(sarif.runs[0].results).toHaveLength(0);
    expect(result.exitCode).toBe(0);
  });

  it("should output SARIF results for files with secrets", () => {
    // Create a file with a known secret pattern
    fs.writeFileSync(
      path.join(tmpDir, "secrets.ts"),
      'const key = "AKIAIOSFODNN7EXAMPLE";\n',
    );

    const result = runScan(`${tmpDir} --format sarif --engine patterns`);
    const sarif = JSON.parse(result.stdout);

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);

    const finding = sarif.runs[0].results[0];
    expect(finding.ruleId).toBeTruthy();
    expect(finding.level).toBe("error"); // critical/high -> error
    expect(finding.message).toHaveProperty("text");
    expect(finding.locations).toHaveLength(1);
    expect(finding.locations[0].physicalLocation).toHaveProperty("artifactLocation");
    expect(finding.locations[0].physicalLocation).toHaveProperty("region");
    expect(finding.locations[0].physicalLocation.region.startLine).toBeGreaterThanOrEqual(1);

    // Rules should be populated
    expect(sarif.runs[0].tool.driver.rules.length).toBeGreaterThan(0);

    expect(result.exitCode).toBe(1);
  });

  it("should map severity levels correctly", () => {
    // Create file with a secret
    fs.writeFileSync(
      path.join(tmpDir, "test.env"),
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n',
    );

    const result = runScan(`${tmpDir} --format sarif --engine patterns`);
    const sarif = JSON.parse(result.stdout);

    // All results should have valid SARIF levels
    for (const r of sarif.runs[0].results) {
      expect(["error", "warning", "note"]).toContain(r.level);
    }
  });

  it("should support --format json as equivalent to --json", () => {
    fs.writeFileSync(path.join(tmpDir, "clean.ts"), 'const x = 42;\n');

    const jsonResult = runScan(`${tmpDir} --json`);
    const formatResult = runScan(`${tmpDir} --format json`);

    // Both should produce valid JSON arrays
    const jsonParsed = JSON.parse(jsonResult.stdout);
    const formatParsed = JSON.parse(formatResult.stdout);

    expect(Array.isArray(jsonParsed)).toBe(true);
    expect(Array.isArray(formatParsed)).toBe(true);
  });

  it("should reject invalid format values", () => {
    const result = runScan(`${tmpDir} --format xml`);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("Invalid format");
  });

  it("should include tool version in SARIF output", () => {
    fs.writeFileSync(path.join(tmpDir, "clean.ts"), 'const x = 1;\n');

    const result = runScan(`${tmpDir} --format sarif`);
    const sarif = JSON.parse(result.stdout);

    expect(sarif.runs[0].tool.driver.version).toBeTruthy();
    expect(sarif.runs[0].tool.driver.informationUri).toBeTruthy();
  });
});
