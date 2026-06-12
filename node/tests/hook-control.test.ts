import { describe, it, expect } from "vitest";
import { resolveHookControl } from "../src/core/hook-control.js";
import type { RafterConfig } from "../src/core/config-schema.js";

// Build a minimal RafterConfig with an optional hooks block.
function cfg(hooks?: RafterConfig["agent"] extends infer A ? any : never): RafterConfig {
  return { version: "1", initialized: "", agent: { hooks } } as unknown as RafterConfig;
}

describe("resolveHookControl — defaults (fail-safe)", () => {
  it("no config, no env → everything enabled, source=default", () => {
    const c = resolveHookControl({ config: cfg(undefined), env: {} });
    expect(c.hookEnabled).toBe(true);
    expect(c.secretScanEnabled).toBe(true);
    expect(c.commandPolicyEnabled).toBe(true);
    expect(c.source).toEqual({ hook: "default", secretScan: "default", commandPolicy: "default" });
  });

  it("unrecognized env value does NOT disable (fails safe to enabled)", () => {
    const c = resolveHookControl({ config: cfg(undefined), env: { RAFTER_DISABLE_HOOKS: "maybe" } });
    expect(c.hookEnabled).toBe(true);
    expect(c.source.hook).toBe("default");
  });
});

describe("resolveHookControl — env disable", () => {
  for (const v of ["1", "true", "yes", "on", "TRUE", " On "]) {
    it(`RAFTER_DISABLE_HOOKS=${JSON.stringify(v)} disables the whole hook`, () => {
      const c = resolveHookControl({ config: cfg(undefined), env: { RAFTER_DISABLE_HOOKS: v } });
      expect(c.hookEnabled).toBe(false);
      expect(c.secretScanEnabled).toBe(false);
      expect(c.commandPolicyEnabled).toBe(false);
      expect(c.source.hook).toBe("env");
    });
  }

  it("RAFTER_DISABLE_SECRET_SCAN only disables the secret scan", () => {
    const c = resolveHookControl({ config: cfg(undefined), env: { RAFTER_DISABLE_SECRET_SCAN: "1" } });
    expect(c.hookEnabled).toBe(true);
    expect(c.secretScanEnabled).toBe(false);
    expect(c.commandPolicyEnabled).toBe(true);
    expect(c.source.secretScan).toBe("env");
  });

  it("RAFTER_DISABLE_COMMAND_POLICY only disables command policy", () => {
    const c = resolveHookControl({ config: cfg(undefined), env: { RAFTER_DISABLE_COMMAND_POLICY: "1" } });
    expect(c.hookEnabled).toBe(true);
    expect(c.commandPolicyEnabled).toBe(false);
    expect(c.secretScanEnabled).toBe(true);
  });
});

describe("resolveHookControl — global config disable", () => {
  it("agent.hooks.enabled=false disables the whole hook (source=global-config)", () => {
    const c = resolveHookControl({ config: cfg({ enabled: false }), env: {} });
    expect(c.hookEnabled).toBe(false);
    expect(c.source.hook).toBe("global-config");
  });

  it("agent.hooks.secretScan=false disables only the secret scan", () => {
    const c = resolveHookControl({ config: cfg({ secretScan: false }), env: {} });
    expect(c.hookEnabled).toBe(true);
    expect(c.secretScanEnabled).toBe(false);
    expect(c.commandPolicyEnabled).toBe(true);
    expect(c.source.secretScan).toBe("global-config");
  });

  it("enabled=true (explicit) is treated as on, not a disable signal", () => {
    const c = resolveHookControl({ config: cfg({ enabled: true }), env: {} });
    expect(c.hookEnabled).toBe(true);
  });
});

describe("resolveHookControl — precedence (env wins over global)", () => {
  it("env force-enable (0/false) overrides a global disable", () => {
    const c = resolveHookControl({ config: cfg({ enabled: false }), env: { RAFTER_DISABLE_HOOKS: "0" } });
    expect(c.hookEnabled).toBe(true);
    expect(c.source.hook).toBe("env");
  });

  it("env disable overrides a global enable", () => {
    const c = resolveHookControl({ config: cfg({ enabled: true }), env: { RAFTER_DISABLE_HOOKS: "1" } });
    expect(c.hookEnabled).toBe(false);
    expect(c.source.hook).toBe("env");
  });
});
