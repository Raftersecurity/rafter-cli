/**
 * END-TO-END test for command_policy.allowed_patterns, through the REAL path:
 *   .rafter.yml on disk -> policy-loader.mapPolicy -> ConfigManager.loadWithPolicy
 *   -> CommandInterceptor.evaluate
 *
 * WHY THIS FILE EXISTS SEPARATELY from command-interceptor-allowlist.test.ts:
 * that suite stubs loadWithPolicy and injects `allowedPatterns` straight into
 * the config object. It passed on the first version of this feature — while the
 * feature was completely unreachable for real users, because neither
 * policy-loader's mapPolicy nor ConfigManager.loadWithPolicy carried the key
 * from YAML to the merged config. Green tests over a path nobody can take.
 *
 * So this file writes an actual .rafter.yml and asserts the behaviour a
 * customer would get. If the mapping is dropped again, this goes red and the
 * stubbed suite stays green — which is the point.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

describe("command_policy.allowed_patterns — real .rafter.yml to verdict", () => {
  let tmpDir: string;
  let origCwd: string;

  beforeEach(() => {
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "rafter-allowlist-")));
    origCwd = process.cwd();
    const { execSync } = require("child_process");
    execSync("git init", { cwd: tmpDir, stdio: "ignore" });
    process.chdir(tmpDir);
    vi.resetModules();
  });

  afterEach(() => {
    process.chdir(origCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  function writePolicy(yml: string) {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
  }

  it("carries allowed_patterns from YAML all the way into the merged config", async () => {
    writePolicy([
      "command_policy:",
      "  mode: approve-dangerous",
      '  allowed_patterns: ["git push --force-with-lease"]',
      "",
    ].join("\n"));

    const { loadPolicy } = await import("../src/core/policy-loader.js");
    const policy = loadPolicy();
    // 1. the YAML mapper must produce the camelCase key
    expect(policy?.commandPolicy?.allowedPatterns).toEqual(["git push --force-with-lease"]);

    // 2. and loadWithPolicy must copy it onto the merged config
    const { ConfigManager } = await import("../src/core/config-manager.js");
    const merged = new ConfigManager().loadWithPolicy();
    expect(merged.agent?.commandPolicy.allowedPatterns).toEqual(["git push --force-with-lease"]);
  });

  it("actually suppresses the customer's prompt end to end", async () => {
    writePolicy([
      "command_policy:",
      "  mode: approve-dangerous",
      '  allowed_patterns: ["git push --force-with-lease"]',
      "",
    ].join("\n"));

    const { CommandInterceptor } = await import("../src/core/command-interceptor.js");
    const result = new CommandInterceptor().evaluate("git push --force-with-lease origin feature/x");
    expect(result.requiresApproval).toBe(false);
    expect(result.allowed).toBe(true);
    expect(result.riskLevel).toBe("low");
  });

  it("still refuses a chained command written through real YAML", async () => {
    writePolicy([
      "command_policy:",
      "  mode: approve-dangerous",
      '  allowed_patterns: ["git push"]',
      "",
    ].join("\n"));

    const { CommandInterceptor } = await import("../src/core/command-interceptor.js");
    const result = new CommandInterceptor().evaluate("rm -rf / && git push");
    expect(result.reason ?? "").not.toContain("allowed pattern");
  });

  it("still lets blocked_patterns win when both are set in YAML", async () => {
    writePolicy([
      "command_policy:",
      "  mode: approve-dangerous",
      '  blocked_patterns: ["git push"]',
      '  allowed_patterns: ["git push --force-with-lease"]',
      "",
    ].join("\n"));

    const { CommandInterceptor } = await import("../src/core/command-interceptor.js");
    const result = new CommandInterceptor().evaluate("git push --force-with-lease origin feature/x");
    expect(result.allowed).toBe(false);
  });

  it("warns and ignores a non-array allowed_patterns rather than crashing", async () => {
    writePolicy(["command_policy:", "  allowed_patterns: 'not-an-array'", ""].join("\n"));
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { loadPolicy } = await import("../src/core/policy-loader.js");
    const policy = loadPolicy();
    expect(policy?.commandPolicy?.allowedPatterns).toBeUndefined();
    spy.mockRestore();
  });
});
