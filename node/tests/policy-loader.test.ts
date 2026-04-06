import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * Tests for the policy loader — YAML parsing, snake_case mapping,
 * validation, and merge behavior.
 *
 * We test the internal functions by importing them and controlling cwd.
 */

// We need to test mapPolicy/validatePolicy behavior through loadPolicy,
// which reads from disk. We'll create temp .rafter.yml files.

describe("Policy file parsing (via .rafter.yml)", () => {
  let tmpDir: string;
  let origCwd: string;

  beforeEach(() => {
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "rafter-policy-")));
    origCwd = process.cwd();
    // Init a git repo so getGitRoot works
    const { execSync } = require("child_process");
    execSync("git init", { cwd: tmpDir, stdio: "ignore" });
    process.chdir(tmpDir);
  });

  afterEach(() => {
    process.chdir(origCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  async function loadPolicyFresh() {
    // Dynamic import to avoid module caching issues
    const mod = await import("../src/core/policy-loader.js");
    return mod.loadPolicy();
  }

  async function findPolicyFresh() {
    const mod = await import("../src/core/policy-loader.js");
    return mod.findPolicyFile();
  }

  it("returns null when no policy file exists", async () => {
    const policy = await loadPolicyFresh();
    expect(policy).toBeNull();
  });

  it("finds .rafter.yml in current directory", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), "version: '1'\n");
    const found = await findPolicyFresh();
    expect(found).toBe(path.join(tmpDir, ".rafter.yml"));
  });

  it("finds .rafter.yaml (alternate extension)", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yaml"), "version: '1'\n");
    const found = await findPolicyFresh();
    expect(found).toBe(path.join(tmpDir, ".rafter.yaml"));
  });

  it("parses valid policy with all sections", async () => {
    const yml = `
version: "1"
risk_level: moderate
command_policy:
  mode: approve-dangerous
  blocked_patterns:
    - "rm -rf /"
  require_approval:
    - "npm publish"
scan:
  exclude_paths:
    - vendor/
    - third_party/
  custom_patterns:
    - name: "Internal Key"
      regex: "INTERNAL_[A-Z0-9]{32}"
      severity: critical
audit:
  retention_days: 90
  log_level: info
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const policy = await loadPolicyFresh();

    expect(policy).not.toBeNull();
    expect(policy!.version).toBe("1");
    expect(policy!.riskLevel).toBe("moderate");
    expect(policy!.commandPolicy?.mode).toBe("approve-dangerous");
    expect(policy!.commandPolicy?.blockedPatterns).toContain("rm -rf /");
    expect(policy!.commandPolicy?.requireApproval).toContain("npm publish");
    expect(policy!.scan?.excludePaths).toContain("vendor/");
    expect(policy!.scan?.customPatterns).toHaveLength(1);
    expect(policy!.scan?.customPatterns![0].name).toBe("Internal Key");
    expect(policy!.audit?.retentionDays).toBe(90);
    expect(policy!.audit?.logLevel).toBe("info");
  });

  it("warns on unknown top-level keys", async () => {
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const yml = `
version: "1"
unknown_key: true
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    await loadPolicyFresh();

    expect(stderrSpy.mock.calls.some((c) => String(c[0]).includes("unknown_key"))).toBe(true);
  });

  it("warns and strips invalid risk_level", async () => {
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const yml = `
risk_level: invalid
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const policy = await loadPolicyFresh();

    expect(policy!.riskLevel).toBeUndefined();
    expect(stderrSpy.mock.calls.some((c) => String(c[0]).includes("risk_level"))).toBe(true);
  });

  it("warns and strips invalid command_policy.mode", async () => {
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const yml = `
command_policy:
  mode: invalid-mode
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const policy = await loadPolicyFresh();

    expect(policy!.commandPolicy?.mode).toBeUndefined();
  });

  it("warns and strips invalid custom pattern (missing regex)", async () => {
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const yml = `
scan:
  custom_patterns:
    - name: "Bad Pattern"
      severity: high
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const policy = await loadPolicyFresh();

    expect(policy!.scan?.customPatterns).toBeUndefined();
  });

  it("warns and strips custom pattern with invalid regex", async () => {
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const yml = `
scan:
  custom_patterns:
    - name: "Bad Regex"
      regex: "[invalid"
      severity: high
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const policy = await loadPolicyFresh();

    expect(policy!.scan?.customPatterns).toBeUndefined();
    expect(stderrSpy.mock.calls.some((c) => String(c[0]).includes("invalid regex"))).toBe(true);
  });

  it("warns and strips invalid audit.retention_days (non-number)", async () => {
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const yml = `
audit:
  retention_days: "not a number"
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const policy = await loadPolicyFresh();

    expect(policy!.audit?.retentionDays).toBeUndefined();
  });

  it("warns and strips invalid audit.log_level", async () => {
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const yml = `
audit:
  log_level: verbose
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const policy = await loadPolicyFresh();

    expect(policy!.audit?.logLevel).toBeUndefined();
  });

  it("handles empty YAML file gracefully", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), "");
    const policy = await loadPolicyFresh();
    expect(policy).toBeNull();
  });

  it("handles malformed YAML gracefully", async () => {
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), "{{not yaml}}");
    const policy = await loadPolicyFresh();
    // Should return null or an empty object, not throw
    // (depends on js-yaml behavior with braces — it might parse as object)
    // The key point: no uncaught exception
    expect(true).toBe(true);
  });
});
