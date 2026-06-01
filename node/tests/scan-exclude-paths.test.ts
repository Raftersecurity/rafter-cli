/**
 * Regression tests for sable-yz0 — `rafter secrets` must honor
 * `.rafter.yml scan.exclude_paths` on both the betterleaks and patterns
 * engines, and across all entry shapes (bare dir name, dir with trailing
 * slash, full file path, glob).
 *
 * Mirrors the customer's exact repro: plant a fake Stripe key in three
 * excluded paths AND one non-excluded path, expect only the non-excluded
 * one to fire (exit 1, single finding).
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { execSync, spawnSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { randomBytes } from "crypto";

const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_DIST = path.join(PROJECT_ROOT, "dist", "index.js");

// Stripe-style key, split so this file doesn't trip its own scanner.
const FAKE_STRIPE = "sk" + "_live_" + "1234567890abcdefghijklmn";

beforeAll(() => {
  if (!fs.existsSync(CLI_DIST)) {
    execSync("pnpm run build", { cwd: PROJECT_ROOT, stdio: "inherit" });
  }
});

function setupRepro(): string {
  const dir = path.join(
    os.tmpdir(),
    `rafter-exclude-test-${Date.now()}-${randomBytes(4).toString("hex")}`,
  );
  fs.mkdirSync(dir, { recursive: true });
  execSync("git init -q", { cwd: dir });
  fs.mkdirSync(path.join(dir, "scripts"), { recursive: true });
  fs.mkdirSync(path.join(dir, "components", "common"), { recursive: true });
  fs.mkdirSync(path.join(dir, "supabase", "migrations"), { recursive: true });
  fs.mkdirSync(path.join(dir, "safe"), { recursive: true });
  fs.writeFileSync(path.join(dir, "scripts", "dev.ts"), `// ${FAKE_STRIPE}\n`);
  fs.writeFileSync(path.join(dir, "components", "common", "Mermaid.tsx"), `// ${FAKE_STRIPE}\n`);
  fs.writeFileSync(
    path.join(dir, "supabase", "migrations", "20250215000000_resend_setup.sql"),
    `-- ${FAKE_STRIPE}\n`,
  );
  fs.writeFileSync(path.join(dir, "safe", "leaky.ts"), `// ${FAKE_STRIPE}\n`);
  fs.writeFileSync(
    path.join(dir, ".rafter.yml"),
    [
      "scan:",
      "  exclude_paths:",
      "    - scripts/",
      "    - components/common/Mermaid.tsx",
      "    - supabase/migrations/20250215000000_resend_setup.sql",
      "",
    ].join("\n"),
  );
  return dir;
}

function runCli(args: string[], cwd: string, homeDir: string) {
  const r = spawnSync(process.execPath, [CLI_DIST, ...args], {
    cwd,
    encoding: "utf-8",
    timeout: 60_000,
    env: { ...process.env, HOME: homeDir, XDG_CONFIG_HOME: path.join(homeDir, ".config"), CI: "1" },
  });
  return { stdout: r.stdout || "", stderr: r.stderr || "", exitCode: r.status ?? 1 };
}

describe("rafter secrets — scan.exclude_paths (sable-yz0)", () => {
  let repo: string;
  let home: string;

  beforeEach(() => {
    repo = setupRepro();
    home = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-exclude-home-"));
  });

  afterEach(() => {
    fs.rmSync(repo, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("patterns engine flags only the non-excluded path (the customer's repro)", () => {
    const r = runCli(["secrets", ".", "--engine", "patterns", "--format", "json"], repo, home);
    expect(r.exitCode).toBe(1);
    const out = JSON.parse(r.stdout);
    const files = (out.results || []).map((x: any) => x.file).sort();
    // Exactly one file fires — safe/leaky.ts. None of the excluded paths.
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/safe\/leaky\.ts$/);
    expect(files.some((f: string) => f.includes("scripts/dev.ts"))).toBe(false);
    expect(files.some((f: string) => f.includes("Mermaid.tsx"))).toBe(false);
    expect(files.some((f: string) => f.includes("resend_setup.sql"))).toBe(false);
  });

  it("auto engine matches patterns-engine output (regardless of which engine wins)", () => {
    const r = runCli(["secrets", ".", "--format", "json"], repo, home);
    expect(r.exitCode).toBe(1);
    const out = JSON.parse(r.stdout);
    const files = (out.results || []).map((x: any) => x.file).sort();
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/safe\/leaky\.ts$/);
  });

  it("dropping the exclude_paths block re-surfaces all four findings", () => {
    fs.writeFileSync(path.join(repo, ".rafter.yml"), "");
    const r = runCli(["secrets", ".", "--engine", "patterns", "--format", "json"], repo, home);
    expect(r.exitCode).toBe(1);
    const out = JSON.parse(r.stdout);
    const files = (out.results || []).map((x: any) => x.file).sort();
    expect(files).toHaveLength(4);
  });

  it("dir-name-anywhere semantics: bare `node_modules` excludes nested copies", () => {
    fs.mkdirSync(path.join(repo, "pkg", "node_modules", "foo"), { recursive: true });
    fs.writeFileSync(path.join(repo, "pkg", "node_modules", "foo", "leak.ts"), `// ${FAKE_STRIPE}\n`);
    fs.writeFileSync(
      path.join(repo, ".rafter.yml"),
      "scan:\n  exclude_paths:\n    - node_modules\n",
    );

    const r = runCli(["secrets", ".", "--engine", "patterns", "--format", "json"], repo, home);
    const out = JSON.parse(r.stdout);
    const files = (out.results || []).map((x: any) => x.file);
    expect(files.some((f: string) => f.includes("node_modules"))).toBe(false);
    // safe/leaky.ts still fires since exclude_paths only has node_modules now
    expect(files.some((f: string) => f.includes("safe/leaky.ts"))).toBe(true);
  });

  it("glob semantics: `**/*.sql` excludes every SQL file at any depth", () => {
    fs.writeFileSync(
      path.join(repo, ".rafter.yml"),
      "scan:\n  exclude_paths:\n    - '**/*.sql'\n",
    );
    const r = runCli(["secrets", ".", "--engine", "patterns", "--format", "json"], repo, home);
    const out = JSON.parse(r.stdout);
    const files = (out.results || []).map((x: any) => x.file);
    expect(files.some((f: string) => f.endsWith(".sql"))).toBe(false);
  });
});
