import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * Tests for ConfigManager.loadWithPolicy() — the merge behavior where
 * .rafter.yml policy values override config.json values.
 */
describe("ConfigManager.loadWithPolicy()", () => {
  let tmpDir: string;
  let origCwd: string;
  let configPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-merge-"));
    origCwd = process.cwd();
    // Init git repo so policy loader's getGitRoot works
    const { execSync } = require("child_process");
    execSync("git init", { cwd: tmpDir, stdio: "ignore" });
    process.chdir(tmpDir);
    configPath = path.join(tmpDir, "config.json");
  });

  afterEach(() => {
    process.chdir(origCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
    vi.resetModules();
  });

  async function getManager() {
    const { ConfigManager } = await import("../src/core/config-manager.js");
    return new ConfigManager(configPath);
  }

  it("returns config unchanged when no policy file exists", async () => {
    const manager = await getManager();
    const plain = manager.load();
    const merged = manager.loadWithPolicy();

    expect(merged.agent?.riskLevel).toBe(plain.agent?.riskLevel);
    expect(merged.agent?.commandPolicy.mode).toBe(plain.agent?.commandPolicy.mode);
    expect(merged.agent?.audit.retentionDays).toBe(plain.agent?.audit.retentionDays);
  });

  it("policy risk_level overrides config", async () => {
    fs.writeFileSync(
      path.join(tmpDir, ".rafter.yml"),
      "risk_level: aggressive\n"
    );
    const manager = await getManager();
    const config = manager.loadWithPolicy();

    expect(config.agent?.riskLevel).toBe("aggressive");
  });

  // sable-nz4y — was "policy command_policy REPLACES config (not merges arrays)".
  // The policy file is discovered by walking up from cwd to the git root, so it
  // is a file in the repo being worked on and is untrusted on a repo the agent
  // did not write. The global config is now a floor: a project may add rules and
  // tighten the mode, but cannot drop a rule or loosen the mode.
  it("policy command_policy raises the config floor (never lowers it)", async () => {
    const yml = `
command_policy:
  mode: deny-list
  blocked_patterns:
    - "custom-block"
  require_approval:
    - "custom-approve"
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const manager = await getManager();
    const config = manager.loadWithPolicy();

    // deny-list is looser than the default approve-dangerous — refused.
    expect(config.agent?.commandPolicy.mode).toBe("approve-dangerous");
    // The project's entries are added; the defaults it omitted are kept.
    expect(config.agent?.commandPolicy.blockedPatterns).toContain("custom-block");
    expect(config.agent?.commandPolicy.requireApproval).toContain("custom-approve");
    expect(config.agent?.commandPolicy.requireApproval).toContain("rm -rf");
    expect(config.agent?.commandPolicy.blockedPatterns.length).toBeGreaterThan(1);
  });

  it("policy scan.excludePaths overrides config", async () => {
    const yml = `
scan:
  exclude_paths:
    - "vendor/"
    - "third_party/"
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const manager = await getManager();
    const config = manager.loadWithPolicy();

    expect(config.agent?.scan?.excludePaths).toEqual(["vendor/", "third_party/"]);
  });

  it("policy scan.customPatterns overrides config", async () => {
    const yml = `
scan:
  custom_patterns:
    - name: "Policy Key"
      regex: "POLICY_[A-Z]{16}"
      severity: critical
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const manager = await getManager();
    const config = manager.loadWithPolicy();

    expect(config.agent?.scan?.customPatterns).toHaveLength(1);
    expect(config.agent?.scan?.customPatterns![0].name).toBe("Policy Key");
    expect(config.agent?.scan?.customPatterns![0].severity).toBe("critical");
  });

  it("policy audit.retentionDays overrides config", async () => {
    const yml = `
audit:
  retention_days: 180
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const manager = await getManager();
    const config = manager.loadWithPolicy();

    expect(config.agent?.audit.retentionDays).toBe(180);
  });

  it("policy audit.logLevel overrides config", async () => {
    const yml = `
audit:
  log_level: debug
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const manager = await getManager();
    const config = manager.loadWithPolicy();

    expect(config.agent?.audit.logLevel).toBe("debug");
  });

  it("partial policy only overrides specified fields", async () => {
    const yml = `
risk_level: minimal
`;
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
    const manager = await getManager();
    const plain = manager.load();
    const merged = manager.loadWithPolicy();

    // risk_level overridden
    expect(merged.agent?.riskLevel).toBe("minimal");
    // Everything else unchanged
    expect(merged.agent?.commandPolicy.mode).toBe(plain.agent?.commandPolicy.mode);
    expect(merged.agent?.audit.retentionDays).toBe(plain.agent?.audit.retentionDays);
    expect(merged.agent?.audit.logLevel).toBe(plain.agent?.audit.logLevel);
  });
});
