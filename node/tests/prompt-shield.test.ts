import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";
import { persistSecrets, ensureGitignored } from "../src/core/env-writer.js";

let tmpRoot: string;

beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-prompt-shield-"));
});

afterEach(() => {
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* ignore */ }
});

describe("env-writer", () => {
  it("creates .env and .gitignore on first call", () => {
    const result = persistSecrets(
      [{ baseName: "DB_PASSWORD", value: "hunter2" }],
      tmpRoot
    );

    expect(result.envFileCreated).toBe(true);
    expect(result.gitignoreCreated).toBe(true);
    expect(result.gitignoreUpdated).toBe(true);
    expect(result.written).toEqual([
      { name: "DB_PASSWORD", value: "hunter2", alreadyPresent: false },
    ]);

    expect(fs.readFileSync(result.envFilePath, "utf-8")).toContain("DB_PASSWORD=hunter2");
    expect(fs.readFileSync(result.gitignorePath, "utf-8")).toContain(".env");
  });

  it("reuses existing entry when same value already present", () => {
    fs.writeFileSync(path.join(tmpRoot, ".env"), "EXISTING_KEY=hunter2\n");
    fs.writeFileSync(path.join(tmpRoot, ".gitignore"), ".env\n");

    const result = persistSecrets(
      [{ baseName: "DB_PASSWORD", value: "hunter2" }],
      tmpRoot
    );

    expect(result.written).toEqual([
      { name: "EXISTING_KEY", value: "hunter2", alreadyPresent: true },
    ]);
    expect(result.envFileCreated).toBe(false);
    expect(result.gitignoreUpdated).toBe(false);
    // .env unchanged — no duplicate appended
    expect(fs.readFileSync(result.envFilePath, "utf-8")).toBe("EXISTING_KEY=hunter2\n");
  });

  it("suffixes name on collision", () => {
    fs.writeFileSync(path.join(tmpRoot, ".env"), "DB_PASSWORD=existing\n");

    const result = persistSecrets(
      [{ baseName: "DB_PASSWORD", value: "different-value" }],
      tmpRoot
    );

    expect(result.written[0].name).toBe("DB_PASSWORD_1");
    expect(fs.readFileSync(result.envFilePath, "utf-8")).toContain("DB_PASSWORD_1=different-value");
  });

  it("quotes values containing whitespace or special chars", () => {
    const result = persistSecrets(
      [{ baseName: "FUNKY", value: "has spaces" }],
      tmpRoot
    );
    expect(fs.readFileSync(result.envFilePath, "utf-8")).toContain('FUNKY="has spaces"');
    expect(result.written[0].name).toBe("FUNKY");
  });

  it("does not duplicate the same value within one call", () => {
    const result = persistSecrets(
      [
        { baseName: "FOO", value: "samevalue" },
        { baseName: "BAR", value: "samevalue" },
      ],
      tmpRoot
    );
    expect(result.written).toHaveLength(2);
    expect(result.written[0]).toEqual({ name: "FOO", value: "samevalue", alreadyPresent: false });
    expect(result.written[1]).toEqual({ name: "FOO", value: "samevalue", alreadyPresent: true });
    const content = fs.readFileSync(result.envFilePath, "utf-8");
    expect(content.match(/^FOO=/gm)?.length).toBe(1);
  });

  it("sanitizes invalid characters in basename", () => {
    const result = persistSecrets(
      [{ baseName: "weird.name with-stuff!", value: "abc123def" }],
      tmpRoot
    );
    expect(result.written[0].name).toBe("WEIRD_NAME_WITH_STUFF");
  });
});

describe("ensureGitignored", () => {
  it("creates .gitignore if missing", () => {
    const gi = path.join(tmpRoot, ".gitignore");
    const r = ensureGitignored(gi, ".env");
    expect(r).toEqual({ created: true, updated: true });
    expect(fs.readFileSync(gi, "utf-8")).toBe(".env\n");
  });

  it("appends if .env not already covered", () => {
    const gi = path.join(tmpRoot, ".gitignore");
    fs.writeFileSync(gi, "node_modules/\ndist/\n");
    const r = ensureGitignored(gi, ".env");
    expect(r).toEqual({ created: false, updated: true });
    expect(fs.readFileSync(gi, "utf-8")).toContain(".env");
  });

  it("is a no-op if .env already present", () => {
    const gi = path.join(tmpRoot, ".gitignore");
    fs.writeFileSync(gi, ".env\nnode_modules/\n");
    const r = ensureGitignored(gi, ".env");
    expect(r).toEqual({ created: false, updated: false });
  });

  it("treats /env-style entries as covered", () => {
    const gi = path.join(tmpRoot, ".gitignore");
    fs.writeFileSync(gi, "/.env\n");
    const r = ensureGitignored(gi, ".env");
    expect(r.updated).toBe(false);
  });

  it("appends correctly when file lacks trailing newline", () => {
    const gi = path.join(tmpRoot, ".gitignore");
    fs.writeFileSync(gi, "node_modules/");
    ensureGitignored(gi, ".env");
    const content = fs.readFileSync(gi, "utf-8");
    expect(content.split("\n").filter(Boolean)).toEqual(["node_modules/", ".env"]);
  });
});

/* ---------------- end-to-end via spawned CLI ---------------- */

const CLI_ENTRY = path.resolve(__dirname, "../dist/index.js");

function runHook(opts: {
  prompt: string;
  cwd: string;
  mode?: "warn" | "block";
  env?: Record<string, string>;
}) {
  const args = ["hook", "user-prompt-submit"];
  if (opts.mode) args.push("--mode", opts.mode);
  const proc = spawnSync(process.execPath, [CLI_ENTRY, ...args], {
    input: JSON.stringify({
      session_id: "test",
      hook_event_name: "UserPromptSubmit",
      cwd: opts.cwd,
      prompt: opts.prompt,
    }),
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

const haveBuild = fs.existsSync(CLI_ENTRY);
const e2e = haveBuild ? describe : describe.skip;

e2e("user-prompt-submit hook (e2e)", () => {
  it("emits no-op envelope when no secrets", () => {
    const r = runHook({
      prompt: "Refactor the function in foo.ts to use async/await",
      cwd: tmpRoot,
    });
    expect(r.json).toBeTruthy();
    expect(r.json.hookSpecificOutput).toEqual({ hookEventName: "UserPromptSubmit" });
    expect(fs.existsSync(path.join(tmpRoot, ".env"))).toBe(false);
  });

  it("detects assignment-style password, writes to .env, ensures .gitignore", () => {
    const r = runHook({
      prompt: "Connect with DB_PASSWORD=hunter2andmore",
      cwd: tmpRoot,
    });
    expect(r.json?.hookSpecificOutput?.hookEventName).toBe("UserPromptSubmit");
    expect(r.json?.hookSpecificOutput?.additionalContext).toMatch(/Rafter prompt-shield/);
    expect(r.json?.hookSpecificOutput?.additionalContext).toMatch(/DB_PASSWORD/);
    const env = fs.readFileSync(path.join(tmpRoot, ".env"), "utf-8");
    expect(env).toMatch(/DB_PASSWORD=hunter2andmore/);
    const gi = fs.readFileSync(path.join(tmpRoot, ".gitignore"), "utf-8");
    expect(gi).toContain(".env");
  });

  it("blocks in block mode", () => {
    // Construct fake stripe-shaped key from parts so secret-scanners on this
    // repo don't flag the test source itself.
    const fakeKey = "sk_" + "live_" + "a".repeat(24);
    const r = runHook({
      prompt: `Use the api_key=${fakeKey} for stripe`,
      cwd: tmpRoot,
      mode: "block",
    });
    expect(r.json?.decision).toBe("block");
    expect(r.json?.reason).toMatch(/Re-submit/);
  });

  it("hard kill switch via RAFTER_PROMPT_SHIELD=0", () => {
    const r = runHook({
      prompt: "Connect with password=letmein123",
      cwd: tmpRoot,
      env: { RAFTER_PROMPT_SHIELD: "0" },
    });
    expect(r.json?.hookSpecificOutput?.additionalContext).toBeUndefined();
    expect(fs.existsSync(path.join(tmpRoot, ".env"))).toBe(false);
  });

  it("ignores obvious placeholders", () => {
    const r = runHook({
      prompt: "Set api_key=<your-key-here> in your config",
      cwd: tmpRoot,
    });
    expect(r.json?.hookSpecificOutput?.additionalContext).toBeUndefined();
  });

  it("malformed JSON fails open with no-op", () => {
    const proc = spawnSync(process.execPath, [CLI_ENTRY, "hook", "user-prompt-submit"], {
      input: "not json at all",
      encoding: "utf-8",
      timeout: 10000,
    });
    const json = parseHookOutput(proc.stdout);
    expect(json?.hookSpecificOutput?.hookEventName).toBe("UserPromptSubmit");
    expect(json?.decision).toBeUndefined();
  });
});

/* ---------------- installer probe regression (rc-txf) ---------------- */

const installerE2E = haveBuild ? describe : describe.skip;

installerE2E("agent init UserPromptSubmit installer (rc-txf regression)", () => {
  it("skips installing the hook when rafter on PATH lacks the subcommand", () => {
    // Build a scrubbed PATH containing only `node` and a fake `rafter` that
    // exits non-zero for `hook user-prompt-submit --help`. This simulates a
    // user with the published rafter older than this dev branch.
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-installer-probe-"));
    const isolatedBin = path.join(home, "_bin");
    fs.mkdirSync(isolatedBin, { recursive: true });
    fs.symlinkSync(process.execPath, path.join(isolatedBin, "node"));
    // Fake rafter: returns 0 for any subcommand EXCEPT user-prompt-submit
    const fakeRafter = path.join(isolatedBin, "rafter");
    fs.writeFileSync(
      fakeRafter,
      `#!/bin/sh\nfor a in "$@"; do [ "$a" = "user-prompt-submit" ] && exit 1; done\nexit 0\n`,
      { mode: 0o755 }
    );

    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });

    const result = spawnSync(
      process.execPath,
      [CLI_ENTRY, "agent", "init", "--with-claude-code"],
      {
        cwd: home,
        encoding: "utf-8",
        timeout: 30000,
        env: { ...process.env, HOME: home, PATH: isolatedBin },
      }
    );

    expect(result.status, `installer should not crash: ${result.stderr}`).toBe(0);

    const settingsPath = path.join(home, ".claude", "settings.json");
    expect(fs.existsSync(settingsPath)).toBe(true);
    const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    // The installer should NOT have wired UserPromptSubmit to a command the
    // resolved rafter can't run. Either the key is absent, or it has no
    // rafter entry.
    const ups = settings.hooks?.UserPromptSubmit ?? [];
    const rafterEntries = ups.filter((entry: any) =>
      (entry.hooks || []).some((h: any) =>
        typeof h.command === "string" && h.command.includes("rafter hook user-prompt-submit")
      )
    );
    expect(rafterEntries.length).toBe(0);

    // And the user-facing output should warn so the user knows they need to upgrade.
    expect(result.stdout + result.stderr).toMatch(/Skipped UserPromptSubmit hook/i);

    fs.rmSync(home, { recursive: true, force: true });
  });

  it("when rafter on PATH supports the subcommand, the installed command actually runs", () => {
    // PATH includes the dev rafter (this dist), which DOES support the subcommand.
    // Round-trip: install → read settings → execute the exact command string.
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-installer-roundtrip-"));
    const isolatedBin = path.join(home, "_bin");
    fs.mkdirSync(isolatedBin, { recursive: true });
    fs.symlinkSync(process.execPath, path.join(isolatedBin, "node"));
    // Real rafter shim: invokes our dist via node.
    const realRafter = path.join(isolatedBin, "rafter");
    fs.writeFileSync(
      realRafter,
      `#!/bin/sh\nexec ${process.execPath} ${CLI_ENTRY} "$@"\n`,
      { mode: 0o755 }
    );

    fs.mkdirSync(path.join(home, ".claude"), { recursive: true });

    const installResult = spawnSync(
      process.execPath,
      [CLI_ENTRY, "agent", "init", "--with-claude-code"],
      {
        cwd: home,
        encoding: "utf-8",
        timeout: 30000,
        env: { ...process.env, HOME: home, PATH: isolatedBin },
      }
    );
    expect(installResult.status).toBe(0);

    const settings = JSON.parse(fs.readFileSync(path.join(home, ".claude", "settings.json"), "utf-8"));
    const ups = settings.hooks?.UserPromptSubmit ?? [];
    const cmd = ups[0]?.hooks?.[0]?.command as string | undefined;
    expect(cmd, "installer should write a UserPromptSubmit hook command").toBeTruthy();

    // Execute the exact command string the installer wrote — it MUST succeed.
    const execResult = spawnSync(cmd!, {
      input: '{"prompt":"hello world","cwd":"' + home + '"}',
      encoding: "utf-8",
      timeout: 10000,
      shell: true,
      env: { ...process.env, HOME: home, PATH: isolatedBin },
    });
    expect(execResult.status, `hook must execute successfully: stderr=${execResult.stderr}`).toBe(0);
    const out = parseHookOutput(execResult.stdout);
    expect(out?.hookSpecificOutput?.hookEventName).toBe("UserPromptSubmit");

    fs.rmSync(home, { recursive: true, force: true });
  });
});

/* ---------------- Codex installer (UserPromptSubmit) ---------------- */

const codexE2E = haveBuild ? describe : describe.skip;

codexE2E("agent init --with-codex installs UserPromptSubmit", () => {
  function setupRealRafterEnv(): { home: string; bin: string } {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-codex-install-"));
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

  it("wires user-prompt-submit into ~/.codex/hooks.json when supported", () => {
    const { home, bin } = setupRealRafterEnv();
    fs.mkdirSync(path.join(home, ".codex"), { recursive: true });

    const result = spawnSync(
      process.execPath,
      [CLI_ENTRY, "agent", "init", "--with-codex"],
      {
        cwd: home,
        encoding: "utf-8",
        timeout: 30000,
        env: { ...process.env, HOME: home, PATH: bin },
      }
    );
    expect(result.status, `installer crashed: ${result.stderr}`).toBe(0);

    const config = JSON.parse(fs.readFileSync(path.join(home, ".codex", "hooks.json"), "utf-8"));
    const ups = config.hooks?.UserPromptSubmit ?? [];
    expect(ups.length).toBeGreaterThan(0);
    const cmd = ups[0]?.hooks?.[0]?.command as string | undefined;
    expect(cmd).toMatch(/rafter hook user-prompt-submit/);

    // Round-trip: the wired command must actually execute end-to-end.
    const execResult = spawnSync(cmd!, {
      input: JSON.stringify({ prompt: "no secrets here", cwd: home }),
      encoding: "utf-8",
      timeout: 10000,
      shell: true,
      env: { ...process.env, HOME: home, PATH: bin },
    });
    expect(execResult.status, `hook must execute: ${execResult.stderr}`).toBe(0);
    const out = parseHookOutput(execResult.stdout);
    expect(out?.hookSpecificOutput?.hookEventName).toBe("UserPromptSubmit");

    fs.rmSync(home, { recursive: true, force: true });
  });

  it("skips UserPromptSubmit when rafter on PATH lacks the subcommand", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-codex-install-skip-"));
    const bin = path.join(home, "_bin");
    fs.mkdirSync(bin, { recursive: true });
    fs.symlinkSync(process.execPath, path.join(bin, "node"));
    // Fake rafter: fails for user-prompt-submit, succeeds for everything else.
    fs.writeFileSync(
      path.join(bin, "rafter"),
      `#!/bin/sh\nfor a in "$@"; do [ "$a" = "user-prompt-submit" ] && exit 1; done\nexit 0\n`,
      { mode: 0o755 }
    );
    fs.mkdirSync(path.join(home, ".codex"), { recursive: true });

    const result = spawnSync(
      process.execPath,
      [CLI_ENTRY, "agent", "init", "--with-codex"],
      {
        cwd: home,
        encoding: "utf-8",
        timeout: 30000,
        env: { ...process.env, HOME: home, PATH: bin },
      }
    );
    expect(result.status).toBe(0);

    const config = JSON.parse(fs.readFileSync(path.join(home, ".codex", "hooks.json"), "utf-8"));
    const ups = config.hooks?.UserPromptSubmit ?? [];
    const rafterEntries = ups.filter((entry: any) =>
      (entry.hooks || []).some((h: any) =>
        typeof h.command === "string" && h.command.includes("rafter hook user-prompt-submit")
      )
    );
    expect(rafterEntries.length).toBe(0);

    fs.rmSync(home, { recursive: true, force: true });
  });
});
