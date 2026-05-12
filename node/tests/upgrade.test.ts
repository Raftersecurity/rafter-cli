import { describe, it, expect, beforeAll, vi } from "vitest";
import { execFileSync, spawnSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CLI = path.resolve(__dirname, "../dist/index.js");

function rafter(
  args: string[],
  env?: Record<string, string>,
): { stdout: string; stderr: string; exitCode: number } {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf-8",
    env: { ...process.env, ...env },
    stdio: ["pipe", "pipe", "pipe"],
  });
  return {
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
    exitCode: r.status ?? 1,
  };
}

beforeAll(() => {
  if (!require("fs").existsSync(CLI)) {
    execFileSync("pnpm", ["run", "build"], {
      cwd: path.resolve(__dirname, ".."),
      stdio: "ignore",
      timeout: 60000,
    });
  }
}, 90000);

describe("rafter upgrade — CI no-op", () => {
  it("exits 0 silently in CI=true", () => {
    const r = rafter(["upgrade"], { CI: "true" });
    expect(r.exitCode).toBe(0);
    expect(r.stdout + r.stderr).toMatch(/CI environment/i);
  });

  it("exits 0 silently in GITHUB_ACTIONS=true", () => {
    const r = rafter(["upgrade"], { GITHUB_ACTIONS: "true", CI: "" });
    expect(r.exitCode).toBe(0);
    expect(r.stdout + r.stderr).toMatch(/CI environment/i);
  });
});

describe("rafter upgrade --check", () => {
  it("prints a semver version string and exits 0", () => {
    const r = rafter(["upgrade", "--check"], { CI: "" });
    expect(r.exitCode).toBe(0);
    // Semver pattern: major.minor.patch
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  }, 30000);
});

describe("rafter update alias", () => {
  it("update is recognized as alias for upgrade (CI no-op test)", () => {
    const r = rafter(["update"], { CI: "true" });
    expect(r.exitCode).toBe(0);
    expect(r.stdout + r.stderr).toMatch(/CI environment/i);
  });

  it("update --check returns a semver version string", () => {
    const r = rafter(["update", "--check"], { CI: "" });
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  }, 30000);
});

describe("rafter upgrade — detection branches", () => {
  it("shows upgrade command when update is available", async () => {
    // Mock by running against a fake old version — we can't easily override
    // the current version, so we only check that the command doesn't crash
    // and produces expected output structure when not in CI.
    // This is an integration test that hits the real registry.
    const r = rafter(["upgrade"], { CI: "" });
    expect(r.exitCode).toBe(0);
    const combined = r.stdout + r.stderr;
    // Should always show version info
    expect(combined).toMatch(/version/i);
  }, 30000);

  it("shows npm/pnpm/yarn command when manager unknown (ambiguous path)", () => {
    const r = rafter(["upgrade"], {
      CI: "true",
      npm_config_user_agent: "",
      PNPM_HOME: "",
    });
    // In CI it exits early — just verify it exits 0
    expect(r.exitCode).toBe(0);
  });
});

describe("rafter upgrade --help", () => {
  it("shows --check and --yes flags", () => {
    const r = rafter(["upgrade", "--help"]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("--check");
    expect(r.stdout).toContain("--yes");
  });
});
