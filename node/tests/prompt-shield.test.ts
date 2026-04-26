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
