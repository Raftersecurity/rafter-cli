import { describe, it, expect } from "vitest";
import { guardSecurityEnvFromDotenv } from "../src/utils/env-guard.js";
import { resolveHookControl } from "../src/core/hook-control.js";

// A config with no global hooks disable, so the env var is the sole deciding factor.
const CONFIG = { agent: { hooks: undefined } } as any;
// Faithful emulation of dotenv's default: set only keys not already present.
const applyDotenv = (parsed: Record<string, string>, env: any) => {
  for (const [k, v] of Object.entries(parsed)) if (!(k in env)) env[k] = v;
};
const hookEnabled = (env: any) => resolveHookControl({ env, config: CONFIG }).hookEnabled;

describe("guardSecurityEnvFromDotenv (rf-7dda)", () => {
  it("WITHOUT the guard, a repo .env RAFTER_DISABLE_HOOKS disables the hook (the bug)", () => {
    const env: any = {};
    applyDotenv({ RAFTER_DISABLE_HOOKS: "1" }, env);
    expect(hookEnabled(env)).toBe(false);
  });

  it("drops a repo-.env-injected RAFTER_DISABLE_HOOKS; hook stays enabled", () => {
    const env: any = {};
    guardSecurityEnvFromDotenv(() => applyDotenv({ RAFTER_DISABLE_HOOKS: "1" }, env), env);
    expect(hookEnabled(env)).toBe(true);
  });

  it("preserves the machine owner's REAL RAFTER_DISABLE_HOOKS", () => {
    const env: any = { RAFTER_DISABLE_HOOKS: "1" };
    guardSecurityEnvFromDotenv(() => applyDotenv({ RAFTER_DISABLE_HOOKS: "1" }, env), env);
    expect(hookEnabled(env)).toBe(false);
  });

  it("preserves a legitimate non-security .env key (RAFTER_API_KEY)", () => {
    const env: any = {};
    guardSecurityEnvFromDotenv(
      () => applyDotenv({ RAFTER_API_KEY: "sk-legit", RAFTER_DISABLE_HOOKS: "1" }, env),
      env,
    );
    expect(env.RAFTER_API_KEY).toBe("sk-legit");
    expect(hookEnabled(env)).toBe(true);
  });

  it("drops the fail-open RAFTER_HOOK_STDIN_TIMEOUT_MS and every sub-part disable", () => {
    const env: any = {};
    guardSecurityEnvFromDotenv(
      () => applyDotenv({ RAFTER_HOOK_STDIN_TIMEOUT_MS: "1", RAFTER_DISABLE_SECRET_SCAN: "1", RAFTER_DISABLE_COMMAND_POLICY: "1" }, env),
      env,
    );
    expect(env.RAFTER_HOOK_STDIN_TIMEOUT_MS).toBeUndefined();
    expect(env.RAFTER_DISABLE_SECRET_SCAN).toBeUndefined();
    expect(env.RAFTER_DISABLE_COMMAND_POLICY).toBeUndefined();
  });
});
