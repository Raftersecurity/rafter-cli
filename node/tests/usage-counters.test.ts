import { describe, it, expect, beforeEach } from "vitest";
import { execFileSync, spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";
import {
  USAGE_ALLOWLIST,
  countError,
  countHook,
  countScan,
  countUnknownCommand,
  countUnknownOption,
  flush,
  resetPending,
  setCommandPath,
  writeCounts,
} from "../src/core/usage-counters.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(__dirname, "../dist/index.js");
const SHARED = path.resolve(__dirname, "../../shared-docs/usage-counters.json");

// Built at runtime so no key-shaped literal sits in the repo.
const FAKE_KEY = "AKIA" + "Z".repeat(16);
// Each input carries the repo name "secret-repo" inside a path, URL or slug. A
// bare lowercase token is the one documented exception: the unknown-command
// counter keeps it locally (shared-docs/CLI_SPEC.md), so it is not fed here.
const LEAKS = ["/home/x/secret-repo", "https://github.com/acme/secret-repo.git", `${FAKE_KEY}`, "acme/secret-repo", `secret-repo ${FAKE_KEY}`];

function tmpHome(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "rafter-usage-"));
}

function usageFiles(home: string): string[] {
  const dir = path.join(home, ".rafter", "usage");
  return fs.existsSync(dir) ? fs.readdirSync(dir).map((f) => path.join(dir, f)) : [];
}

function cliEnv(home: string, extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, CI: "1", ...extra };
  if (!("DO_NOT_TRACK" in extra)) delete env.DO_NOT_TRACK;
  if (!("RAFTER_TELEMETRY" in extra)) delete env.RAFTER_TELEMETRY;
  return env;
}

function rafter(home: string, args: string[], opts: { input?: string; cwd?: string; env?: Record<string, string> } = {}) {
  return spawnSync("node", [CLI, ...args], {
    cwd: opts.cwd ?? home,
    env: cliEnv(home, opts.env),
    input: opts.input ?? "",
    encoding: "utf-8",
    timeout: 30_000,
  });
}

const BASH_LS = JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls /home/x/secret-repo" } });

describe("usage counters", () => {
  beforeEach(() => resetPending());

  // Fails if the Node allowlist drifts from the shared file Python also embeds.
  it("embeds the allowlist from shared-docs/usage-counters.json", () => {
    const shared = JSON.parse(fs.readFileSync(SHARED, "utf-8"));
    delete shared.description;
    expect(USAGE_ALLOWLIST).toEqual(shared);
  });

  // Fails if any recorder lets a path, URL, secret or repo name reach the store.
  it("never stores paths, URLs, secrets or repo names", () => {
    const home = tmpHome();
    const saved = process.env.HOME;
    process.env.HOME = home;
    try {
      for (const s of LEAKS) {
        countUnknownCommand(s);
        countUnknownOption(`--${s}`);
        countUnknownOption(`--engine=${s}`);
        setCommandPath(["secrets", s]);
        countHook(s, s, s);
        countScan({ requested: s, used: s, degraded: true, reason: s }, 10);
        const Named = class extends Error {};
        Object.defineProperty(Named, "name", { value: s });
        countError(new Named(s));
        countError(new TypeError(s));
        writeCounts({ [`unknown_command:${s}`]: 1, [`command:${s}:exit:0`]: 1, [s]: 1 });
      }
      flush(LEAKS[0]);
      const files = usageFiles(home);
      expect(files.length).toBe(1);
      const stored = fs.readFileSync(files[0], "utf-8");
      // Positive control: the recorders ran and wrote their fall-back values.
      expect(stored).toContain('"unknown_command:other"');
      expect(stored).toContain('"error_class:other:TypeError"');
      for (const s of [...LEAKS, "secret-repo", FAKE_KEY]) expect(stored).not.toContain(s);
    } finally {
      process.env.HOME = saved;
    }
  });

  // Fails if `rafter` stops counting a real session: unknown command, hook decision, scan, command result.
  it("counts a real CLI session and reports it", () => {
    const home = tmpHome();
    const proj = path.join(home, "proj");
    fs.mkdirSync(proj);
    fs.writeFileSync(path.join(proj, "a.py"), "x = 1\n");
    rafter(home, ["acme-payroll"]);
    expect(rafter(home, ["hook", "pretool"], { input: BASH_LS }).status).toBe(0);
    rafter(home, ["secrets", "--json", "--engine", "patterns", proj]);
    const out = execFileSync("node", [CLI, "telemetry", "show", "--json"], { env: cliEnv(home), encoding: "utf-8" });
    const report = JSON.parse(out);
    expect(report.store).toBe("~/.rafter/usage");
    expect(report.enabled).toBe(true);
    expect(report.counters.unknown_command["unknown_command:acme-payroll"]).toBe(1);
    expect(report.counters.hook["hook:shell:allow:low"]).toBe(1);
    expect(report.counters.command["command:hook.pretool:exit:0"]).toBe(1);
    expect(report.counters.scan_engine["scan_engine:patterns:patterns"]).toBe(1);
    expect(fs.readFileSync(usageFiles(home)[0], "utf-8")).not.toContain("secret-repo");
  });

  // Fails if a kill switch or the global setting stops working, or a project .rafter.yml can turn counting on.
  it("writes nothing when disabled, whatever .rafter.yml says", () => {
    const home = tmpHome();
    rafter(home, ["hook", "pretool"], { input: BASH_LS, env: { DO_NOT_TRACK: "1" } });
    rafter(home, ["hook", "pretool"], { input: BASH_LS, env: { RAFTER_TELEMETRY: "off" } });
    expect(usageFiles(home)).toEqual([]);

    fs.mkdirSync(path.join(home, ".rafter"), { recursive: true });
    fs.writeFileSync(path.join(home, ".rafter", "config.json"), JSON.stringify({ agent: { usage: { enabled: false } } }));
    const proj = path.join(home, "proj");
    fs.mkdirSync(proj);
    fs.writeFileSync(path.join(proj, ".rafter.yml"), "usage:\n  enabled: true\nagent:\n  usage:\n    enabled: true\n");
    rafter(home, ["hook", "pretool"], { input: BASH_LS, cwd: proj });
    expect(usageFiles(home)).toEqual([]);

    // Positive control: the same call with the setting removed does write.
    fs.writeFileSync(path.join(home, ".rafter", "config.json"), "{}");
    rafter(home, ["hook", "pretool"], { input: BASH_LS, cwd: proj });
    expect(usageFiles(home).length).toBe(1);
  });
});
