import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";

const CLI_ENTRY = path.resolve(__dirname, "../dist/index.js");
const haveBuild = fs.existsSync(CLI_ENTRY);

let tmpRoot: string;

beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-gateway-dispatch-"));
});

afterEach(() => {
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* ignore */ }
});

/**
 * Run the gateway-dispatch hook with a Hermes-shaped event.
 *
 * Hermes contract (verified from NousResearch/hermes-agent gateway/run.py:3402-3441):
 *   stdin: { event: { text: string, channel?: string, sender_id?: string, ... }, cwd?: string }
 *   stdout: one of:
 *     {"action": "allow"}                       — pass through unmodified
 *     {"action": "rewrite", "text": "..."}      — replace event.text
 *     {"action": "skip", "reason": "..."}       — drop the message
 */
function runHook(opts: {
  event: any;
  cwd: string;
  env?: Record<string, string>;
}) {
  const proc = spawnSync(process.execPath, [CLI_ENTRY, "hook", "gateway-dispatch"], {
    input: JSON.stringify({ event: opts.event, cwd: opts.cwd }),
    env: { ...process.env, ...(opts.env || {}) },
    encoding: "utf-8",
    timeout: 10000,
  });
  return {
    stdout: proc.stdout,
    stderr: proc.stderr,
    status: proc.status,
    json: parseHookOutput(proc.stdout),
  };
}

function parseHookOutput(stdout: string): any {
  const trimmed = (stdout || "").trim();
  if (!trimmed) return null;
  try { return JSON.parse(trimmed); } catch { return null; }
}

const e2e = haveBuild ? describe : describe.skip;

e2e("rafter hook gateway-dispatch (Hermes)", () => {
  it("returns allow when no secrets present", () => {
    const r = runHook({
      event: { text: "Hey Hermes can you summarize my last commit", channel: "telegram" },
      cwd: tmpRoot,
    });
    expect(r.status).toBe(0);
    expect(r.json).toEqual({ action: "allow" });
    expect(fs.existsSync(path.join(tmpRoot, ".env"))).toBe(false);
  });

  it("returns rewrite with redacted text when secrets present", () => {
    const r = runHook({
      event: {
        text: "Hermes please connect with DB_PASSWORD=hunter2andmore and check status",
        channel: "telegram",
        sender_id: "user42",
      },
      cwd: tmpRoot,
    });
    expect(r.status).toBe(0);
    expect(r.json?.action).toBe("rewrite");
    expect(r.json?.text).toBeTruthy();
    expect(r.json.text).not.toContain("hunter2andmore");
    expect(r.json.text).toContain("$DB_PASSWORD");
    // .env + .gitignore side-effects.
    const env = fs.readFileSync(path.join(tmpRoot, ".env"), "utf-8");
    expect(env).toMatch(/DB_PASSWORD=hunter2andmore/);
    expect(fs.readFileSync(path.join(tmpRoot, ".gitignore"), "utf-8")).toContain(".env");
  });

  it("kill switch RAFTER_PROMPT_SHIELD=0 always returns allow", () => {
    const r = runHook({
      event: { text: "DB_PASSWORD=letmein123" },
      cwd: tmpRoot,
      env: { RAFTER_PROMPT_SHIELD: "0" },
    });
    expect(r.json).toEqual({ action: "allow" });
    expect(fs.existsSync(path.join(tmpRoot, ".env"))).toBe(false);
  });

  it("malformed JSON fails open with allow", () => {
    const proc = spawnSync(process.execPath, [CLI_ENTRY, "hook", "gateway-dispatch"], {
      input: "not json",
      encoding: "utf-8",
      timeout: 10000,
    });
    const json = parseHookOutput(proc.stdout);
    expect(json).toEqual({ action: "allow" });
  });

  it("missing event.text returns allow", () => {
    const r = runHook({
      event: { channel: "telegram", sender_id: "user42" },
      cwd: tmpRoot,
    });
    expect(r.json).toEqual({ action: "allow" });
  });

  it("non-string event.text returns allow", () => {
    const r = runHook({
      event: { text: 12345 },
      cwd: tmpRoot,
    });
    expect(r.json).toEqual({ action: "allow" });
  });
});

/* ---------------- Hermes plugin installer ---------------- */

const installerE2E = haveBuild ? describe : describe.skip;

installerE2E("agent init --with-hermes installs gateway plugin", () => {
  function realRafterEnv(): { home: string; bin: string } {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-hermes-install-"));
    const bin = path.join(home, "_bin");
    fs.mkdirSync(bin, { recursive: true });
    fs.symlinkSync(process.execPath, path.join(bin, "node"));
    fs.writeFileSync(
      path.join(bin, "rafter"),
      `#!/bin/sh\nexec ${process.execPath} ${CLI_ENTRY} "$@"\n`,
      { mode: 0o755 }
    );
    return { home, bin };
  }

  it("copies hermes_rafter_plugin.py to ~/.hermes/plugins/ when supported", () => {
    const { home, bin } = realRafterEnv();
    fs.mkdirSync(path.join(home, ".hermes"), { recursive: true });

    const result = spawnSync(
      process.execPath,
      [CLI_ENTRY, "agent", "init", "--with-hermes"],
      {
        cwd: home,
        encoding: "utf-8",
        timeout: 30000,
        env: { ...process.env, HOME: home, PATH: bin },
      }
    );
    expect(result.status, `installer crashed: ${result.stderr}`).toBe(0);

    const pluginPath = path.join(home, ".hermes", "plugins", "hermes_rafter_plugin.py");
    expect(fs.existsSync(pluginPath), `plugin should be installed at ${pluginPath}`).toBe(true);
    const pluginContent = fs.readFileSync(pluginPath, "utf-8");
    expect(pluginContent).toContain("pre_gateway_dispatch");
    expect(pluginContent).toContain("rafter hook gateway-dispatch");

    fs.rmSync(home, { recursive: true, force: true });
  });

  it("skips plugin install when rafter on PATH lacks gateway-dispatch subcommand", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-hermes-install-skip-"));
    const bin = path.join(home, "_bin");
    fs.mkdirSync(bin, { recursive: true });
    fs.symlinkSync(process.execPath, path.join(bin, "node"));
    fs.writeFileSync(
      path.join(bin, "rafter"),
      `#!/bin/sh\nfor a in "$@"; do [ "$a" = "gateway-dispatch" ] && exit 1; done\nexit 0\n`,
      { mode: 0o755 }
    );
    fs.mkdirSync(path.join(home, ".hermes"), { recursive: true });

    const result = spawnSync(
      process.execPath,
      [CLI_ENTRY, "agent", "init", "--with-hermes"],
      {
        cwd: home,
        encoding: "utf-8",
        timeout: 30000,
        env: { ...process.env, HOME: home, PATH: bin },
      }
    );
    expect(result.status).toBe(0);

    const pluginPath = path.join(home, ".hermes", "plugins", "hermes_rafter_plugin.py");
    expect(fs.existsSync(pluginPath)).toBe(false);

    fs.rmSync(home, { recursive: true, force: true });
  });
});
