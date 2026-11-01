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

  // `rules` that is present but not a list used to be dropped silently, which
  // turned a rule meant for one pattern into one that suppresses every pattern.
  it("ignore: an entry whose rules is not a list is skipped, not widened", async () => {
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), 'ignore:\n  - paths: ["**"]\n    rules: "AWS Access Key"\n');
    const policy = await loadPolicyFresh();

    expect(policy?.ignore).toBeUndefined();
    expect(stderrSpy.mock.calls.some((c) => String(c[0]).includes("rules"))).toBe(true);
  });

  it("ignore: empty array results in no ignore section", async () => {
    const yml = `
ignore: []
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const policy = await loadPolicyFresh();
    expect(policy!.ignore).toBeUndefined();
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

// sable-req5 — every multi-word key the loader reads, in its camelCase spelling.
// Each case: [YAML body, path into the loaded policy, expected value].
const CAMEL_CASES: [string, (string | number)[], unknown][] = [
  ["riskLevel: aggressive", ["riskLevel"], "aggressive"],
  ["commandPolicy:\n  mode: deny-list", ["commandPolicy", "mode"], "deny-list"],
  ["command_policy:\n  blockedPatterns: ['rm -rf /']", ["commandPolicy", "blockedPatterns"], ["rm -rf /"]],
  ["command_policy:\n  requireApproval: ['git push']", ["commandPolicy", "requireApproval"], ["git push"]],
  ["command_policy:\n  allowedPatterns: ['ls']", ["commandPolicy", "allowedPatterns"], ["ls"]],
  ["excludePaths: ['top/**']", ["scan", "excludePaths"], ["top/**"]],
  ["customPatterns: [{name: T, regex: 't_[0-9]+', severity: high}]", ["scan", "customPatterns", 0, "name"], "T"],
  ["scan:\n  excludePaths: ['dist/**']", ["scan", "excludePaths"], ["dist/**"]],
  ["scan:\n  customPatterns: [{name: N, regex: 'n_[0-9]+', severity: low}]", ["scan", "customPatterns", 0, "name"], "N"],
  ["scan:\n  autoUpdateBetterleaks: false", ["scan", "autoUpdateBetterleaks"], false],
  ["scan:\n  plusRequiresApproval: true", ["scan", "plusRequiresApproval"], true],
  ["audit:\n  retentionDays: 7", ["audit", "retentionDays"], 7],
  ["audit:\n  logLevel: debug", ["audit", "logLevel"], "debug"],
  ["audit:\n  logPath: .rafter/a.jsonl", ["audit", "logPath"], ".rafter/a.jsonl"],
  ["docs:\n  - url: https://example.com/d.md\n    cache: {ttlSeconds: 60}", ["docs", 0, "cache", "ttlSeconds"], 60],
];

describe(".rafter.yml camelCase keys (sable-req5)", () => {
  let tmpDir: string;
  let origCwd: string;

  beforeEach(() => {
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "rafter-policy-camel-")));
    origCwd = process.cwd();
    require("child_process").execSync("git init -q", { cwd: tmpDir, stdio: "ignore" });
    process.chdir(tmpDir);
  });

  afterEach(() => {
    process.chdir(origCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  async function load(body: string) {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), body + "\n");
    const mod = await import("../src/core/policy-loader.js");
    return mod.loadPolicy();
  }

  it.each(CAMEL_CASES)("honors %j", async (body, keyPath, expected) => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    let value: any = await load(body);
    for (const step of keyPath) value = value?.[step];
    expect(value).toEqual(expected);
    expect(errSpy.mock.calls.flat().join("\n")).not.toContain("Unknown policy key");
  });

  it("snake_case wins when both spellings are present", async () => {
    const policy = await load(
      "risk_level: minimal\nriskLevel: aggressive\n" +
      "scan:\n  exclude_paths: ['snake/**']\n  excludePaths: ['camel/**']\n" +
      "audit:\n  logLevel: debug\n  log_level: error",
    );
    expect(policy?.riskLevel).toBe("minimal");
    expect(policy?.scan?.excludePaths).toEqual(["snake/**"]);
    expect(policy?.audit?.logLevel).toBe("error");
  });
});
