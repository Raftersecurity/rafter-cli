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

  let origHome: string | undefined;

  beforeEach(() => {
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "rafter-allowlist-")));
    origCwd = process.cwd();
    // getRafterDir() is os.homedir()-relative, so without this the "global
    // config" these tests read is the DEVELOPER'S — the result would depend on
    // whose machine ran the suite.
    origHome = process.env.HOME;
    process.env.HOME = tmpDir;
    const { execSync } = require("child_process");
    execSync("git init", { cwd: tmpDir, stdio: "ignore" });
    process.chdir(tmpDir);
    vi.resetModules();
  });

  afterEach(() => {
    process.chdir(origCwd);
    if (origHome === undefined) delete process.env.HOME;
    else process.env.HOME = origHome;
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  /**
   * Owner's global config. `allowProjectOverride` opts out of the floor.
   *
   * Built from getDefaultConfig() rather than hand-rolled: a partial
   * commandPolicy (no blockedPatterns / requireApproval) makes evaluate()
   * throw `policy.blockedPatterns is not iterable`, so a hand-written stub
   * would test a shape no real install has.
   */
  async function writeGlobalConfig(allowProjectOverride: boolean) {
    const { getDefaultConfig } = await import("../src/core/config-defaults.js");
    const cfg: any = getDefaultConfig();
    cfg.agent.commandPolicy.mode = "approve-dangerous";
    cfg.agent.commandPolicy.allowProjectOverride = allowProjectOverride;
    const dir = path.join(tmpDir, ".rafter");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify(cfg));
  }

  function writePolicy(yml: string) {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), yml);
  }

  it("maps allowed_patterns from YAML, but the FLOOR refuses a project's grant", async () => {
    // rf-3n1i / sable-nz4y. An allowlist is a GRANT, so unlike blocked_patterns
    // it is never contributed by a project policy: a cloned repo shipping
    // allowed_patterns would otherwise wave its own commands through.
    await writeGlobalConfig(false);
    writePolicy([
      "command_policy:",
      "  mode: approve-dangerous",
      '  allowed_patterns: ["git push --force-with-lease"]',
      "",
    ].join("\n"));

    // The YAML mapper still produces the camelCase key — dropping the mapping
    // is what made this unreachable before, and that must not regress.
    const { loadPolicy } = await import("../src/core/policy-loader.js");
    expect(loadPolicy()?.commandPolicy?.allowedPatterns).toEqual([
      "git push --force-with-lease",
    ]);

    // ...and the merge refuses it, because the owner did not opt in.
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { ConfigManager } = await import("../src/core/config-manager.js");
    const merged = new ConfigManager().loadWithPolicy();
    expect(merged.agent?.commandPolicy.allowedPatterns ?? []).toEqual([]);
    spy.mockRestore();
  });

  it("applies the project allowlist once the owner sets allowProjectOverride", async () => {
    await writeGlobalConfig(true);
    writePolicy([
      "command_policy:",
      "  mode: approve-dangerous",
      '  allowed_patterns: ["git push --force-with-lease"]',
      "",
    ].join("\n"));

    const { ConfigManager } = await import("../src/core/config-manager.js");
    const merged = new ConfigManager().loadWithPolicy();
    expect(merged.agent?.commandPolicy.allowedPatterns).toEqual([
      "git push --force-with-lease",
    ]);
  });

  it("actually suppresses the customer's prompt end to end", async () => {
    await writeGlobalConfig(true);
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
    await writeGlobalConfig(true);
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
    await writeGlobalConfig(true);
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
