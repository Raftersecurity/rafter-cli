import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "fs";
import { execSync } from "child_process";
import yaml from "js-yaml";

vi.mock("fs");
vi.mock("child_process");

const mockedFs = vi.mocked(fs);
const mockedExecSync = vi.mocked(execSync);

/**
 * Helper: configure mocks so loadPolicy() finds and parses controlled YAML.
 * We mock getGitRoot via execSync, existsSync to find .rafter.yml,
 * and readFileSync to return the YAML content.
 */
function setupMocks(yamlContent: Record<string, any>) {
  mockedExecSync.mockReturnValue("/fake/repo\n");
  mockedFs.existsSync.mockImplementation((p: any) => {
    return String(p).endsWith(".rafter.yml");
  });
  mockedFs.readFileSync.mockReturnValue(yaml.dump(yamlContent));
}

describe("policy-loader validatePolicy (via loadPolicy)", () => {
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  async function callLoadPolicy() {
    const mod = await import("../src/core/policy-loader.js");
    return mod.loadPolicy();
  }

  it("should warn and strip unknown top-level keys", async () => {
    setupMocks({ version: "1", unknown_key: true });

    const policy = await callLoadPolicy();

    expect(policy).not.toBeNull();
    expect(policy!.version).toBe("1");
    expect((policy as any).unknown_key).toBeUndefined();
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining('Unknown policy key "unknown_key"')
    );
  });

  it("should strip invalid risk_level", async () => {
    setupMocks({ version: "1", risk_level: "extreme" });

    const policy = await callLoadPolicy();

    expect(policy).not.toBeNull();
    expect(policy!.riskLevel).toBeUndefined();
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining("risk_level")
    );
  });

  it("should strip invalid command_policy.mode", async () => {
    setupMocks({
      version: "1",
      command_policy: { mode: "yolo" },
    });

    const policy = await callLoadPolicy();

    expect(policy).not.toBeNull();
    expect(policy!.commandPolicy).toBeDefined();
    expect(policy!.commandPolicy!.mode).toBeUndefined();
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining("command_policy.mode")
    );
  });

  it("should strip non-string blocked_patterns", async () => {
    setupMocks({
      version: "1",
      command_policy: { blocked_patterns: [1, 2] },
    });

    const policy = await callLoadPolicy();

    expect(policy).not.toBeNull();
    expect(policy!.commandPolicy!.blockedPatterns).toBeUndefined();
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining("blocked_patterns")
    );
  });

  it("should pass through a fully valid policy", async () => {
    setupMocks({
      version: "1",
      risk_level: "moderate",
      command_policy: {
        mode: "deny-list",
        blocked_patterns: ["rm -rf /"],
        require_approval: ["sudo"],
      },
      scan: {
        exclude_paths: ["node_modules"],
        custom_patterns: [
          { name: "AWS Key", regex: "AKIA[A-Z0-9]{16}", severity: "critical" },
        ],
      },
      audit: {
        retention_days: 90,
        log_level: "info",
      },
    });

    const policy = await callLoadPolicy();

    expect(policy).not.toBeNull();
    expect(policy!.version).toBe("1");
    expect(policy!.riskLevel).toBe("moderate");
    expect(policy!.commandPolicy!.mode).toBe("deny-list");
    expect(policy!.commandPolicy!.blockedPatterns).toEqual(["rm -rf /"]);
    expect(policy!.commandPolicy!.requireApproval).toEqual(["sudo"]);
    expect(policy!.scan!.excludePaths).toEqual(["node_modules"]);
    expect(policy!.scan!.customPatterns).toEqual([
      { name: "AWS Key", regex: "AKIA[A-Z0-9]{16}", severity: "critical" },
    ]);
    expect(policy!.audit!.retentionDays).toBe(90);
    expect(policy!.audit!.logLevel).toBe("info");
    expect(stderrSpy).not.toHaveBeenCalled();
  });

  it("should strip custom_patterns with empty name or regex", async () => {
    setupMocks({
      version: "1",
      scan: {
        custom_patterns: [{ name: "", regex: "", severity: "high" }],
      },
    });

    const policy = await callLoadPolicy();

    expect(policy).not.toBeNull();
    expect(policy!.scan!.customPatterns).toBeUndefined();
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining("custom_patterns")
    );
  });

  it("should strip non-numeric retention_days", async () => {
    setupMocks({
      version: "1",
      audit: { retention_days: "thirty" },
    });

    const policy = await callLoadPolicy();

    expect(policy).not.toBeNull();
    expect(policy!.audit!.retentionDays).toBeUndefined();
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining("retention_days")
    );
  });

  it("should strip invalid log_level", async () => {
    setupMocks({
      version: "1",
      audit: { log_level: "verbose" },
    });

    const policy = await callLoadPolicy();

    expect(policy).not.toBeNull();
    expect(policy!.audit!.logLevel).toBeUndefined();
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining("log_level")
    );
  });
});
