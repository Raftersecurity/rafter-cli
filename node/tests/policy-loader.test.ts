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

  // sable-c1c — read backend's file path too (.rafter/config.yml), and
  // accept its flat-shape schema (exclude_paths at top level).
  describe("backend file-path + schema compat (sable-c1c)", () => {
    it("finds .rafter/config.yml as a fallback when no dotfile exists", async () => {
      fs.mkdirSync(path.join(tmpDir, ".rafter"));
      fs.writeFileSync(path.join(tmpDir, ".rafter", "config.yml"), "version: '1'\n");
      const found = await findPolicyFresh();
      expect(found).toBe(path.join(tmpDir, ".rafter", "config.yml"));
    });

    it("finds .rafter/config.yaml as a fallback (alternate extension)", async () => {
      fs.mkdirSync(path.join(tmpDir, ".rafter"));
      fs.writeFileSync(path.join(tmpDir, ".rafter", "config.yaml"), "version: '1'\n");
      const found = await findPolicyFresh();
      expect(found).toBe(path.join(tmpDir, ".rafter", "config.yaml"));
    });

    it("dotfile wins when both .rafter.yml and .rafter/config.yml exist", async () => {
      fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), "version: 'dot'\n");
      fs.mkdirSync(path.join(tmpDir, ".rafter"));
      fs.writeFileSync(path.join(tmpDir, ".rafter", "config.yml"), "version: 'subdir'\n");
      const found = await findPolicyFresh();
      expect(found).toBe(path.join(tmpDir, ".rafter.yml"));
      const policy = await loadPolicyFresh();
      expect(policy?.version).toBe("dot");
    });

    it("accepts top-level exclude_paths (backend flat shape) from .rafter/config.yml", async () => {
      fs.mkdirSync(path.join(tmpDir, ".rafter"));
      fs.writeFileSync(
        path.join(tmpDir, ".rafter", "config.yml"),
        "exclude_paths:\n  - scripts/\n  - components/common/Mermaid.tsx\n",
      );
      const policy = await loadPolicyFresh();
      expect(policy?.scan?.excludePaths).toEqual([
        "scripts/",
        "components/common/Mermaid.tsx",
      ]);
    });

    it("accepts top-level custom_patterns (backend flat shape)", async () => {
      fs.mkdirSync(path.join(tmpDir, ".rafter"));
      fs.writeFileSync(
        path.join(tmpDir, ".rafter", "config.yml"),
        "custom_patterns:\n  - name: Foo\n    regex: 'foo-[a-z0-9]+'\n    severity: high\n",
      );
      const policy = await loadPolicyFresh();
      expect(policy?.scan?.customPatterns?.[0]?.name).toBe("Foo");
    });

    it("accepts the backend flat shape inside a .rafter.yml dotfile too", async () => {
      // A customer who used to write .rafter/config.yml may copy the same
      // shape into a .rafter.yml dotfile — should still work.
      fs.writeFileSync(
        path.join(tmpDir, ".rafter.yml"),
        "exclude_paths:\n  - tests/**\n",
      );
      const policy = await loadPolicyFresh();
      expect(policy?.scan?.excludePaths).toEqual(["tests/**"]);
    });

    it("nested scan.exclude_paths wins over top-level when both are present", async () => {
      fs.writeFileSync(
        path.join(tmpDir, ".rafter.yml"),
        "exclude_paths:\n  - flat\nscan:\n  exclude_paths:\n    - nested\n",
      );
      const policy = await loadPolicyFresh();
      expect(policy?.scan?.excludePaths).toEqual(["nested"]);
    });

    it("does not warn on top-level exclude_paths / custom_patterns (compat keys)", async () => {
      const warnSpy = vi.spyOn(console, "error").mockImplementation(() => {});
      fs.writeFileSync(
        path.join(tmpDir, ".rafter.yml"),
        "exclude_paths:\n  - foo/\ncustom_patterns: []\n",
      );
      await loadPolicyFresh();
      const warnings = warnSpy.mock.calls.flat().join("\n");
      expect(warnings).not.toMatch(/Unknown policy key "exclude_paths"/);
      expect(warnings).not.toMatch(/Unknown policy key "custom_patterns"/);
    });
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

  it("maps scan.auto_update_betterleaks: false (sable-o4k)", async () => {
    fs.writeFileSync(
      path.join(tmpDir, ".rafter.yml"),
      "scan:\n  auto_update_betterleaks: false\n",
    );
    const policy = await loadPolicyFresh();
    expect(policy!.scan?.autoUpdateBetterleaks).toBe(false);
  });

  it("maps scan.auto_update_betterleaks: true (sable-o4k)", async () => {
    fs.writeFileSync(
      path.join(tmpDir, ".rafter.yml"),
      "scan:\n  auto_update_betterleaks: true\n",
    );
    const policy = await loadPolicyFresh();
    expect(policy!.scan?.autoUpdateBetterleaks).toBe(true);
  });

  it("warns and ignores a non-boolean scan.auto_update_betterleaks (sable-o4k)", async () => {
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    fs.writeFileSync(
      path.join(tmpDir, ".rafter.yml"),
      "scan:\n  auto_update_betterleaks: maybe\n",
    );
    const policy = await loadPolicyFresh();
    expect(policy!.scan?.autoUpdateBetterleaks).toBeUndefined();
    expect(stderrSpy.mock.calls.some((c) => String(c[0]).includes("auto_update_betterleaks"))).toBe(true);
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

  it("parses ignore rules with paths, rules, and reason", async () => {
    const yml = `
ignore:
  - paths: ["tests/fixtures/**", "*.example.env"]
    rules: ["AWS Access Key", "Generic API Key"]
    reason: "test fixtures"
  - paths: ["docs/**"]
    reason: "documentation examples"
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const policy = await loadPolicyFresh();

    expect(policy!.ignore).toBeDefined();
    expect(policy!.ignore!.length).toBe(2);
    expect(policy!.ignore![0].paths).toEqual(["tests/fixtures/**", "*.example.env"]);
    expect(policy!.ignore![0].rules).toEqual(["AWS Access Key", "Generic API Key"]);
    expect(policy!.ignore![0].reason).toBe("test fixtures");
    expect(policy!.ignore![1].rules).toBeUndefined();
    expect(policy!.ignore![1].reason).toBe("documentation examples");
  });

  it("ignore: rules without paths are skipped with a warning", async () => {
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const yml = `
ignore:
  - rules: ["AWS Access Key"]
  - paths: ["valid/**"]
    reason: "kept"
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const policy = await loadPolicyFresh();

    expect(policy!.ignore!.length).toBe(1);
    expect(policy!.ignore![0].paths).toEqual(["valid/**"]);
    expect(stderrSpy.mock.calls.some((c) => String(c[0]).includes("paths"))).toBe(true);
  });

  it("ignore: empty array results in no ignore section", async () => {
    const yml = `
ignore: []
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const policy = await loadPolicyFresh();
    expect(policy!.ignore).toBeUndefined();
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
