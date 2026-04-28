import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";

const CLI_ENTRY = path.resolve(__dirname, "../dist/index.js");
const haveBuild = fs.existsSync(CLI_ENTRY);

let tmpRoot: string;

beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-before-model-"));
});

afterEach(() => {
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* ignore */ }
});

/**
 * Run the before-model hook with a Gemini-shaped llm_request.
 * The contract (verified from gemini-cli main):
 *
 *   stdin: { llm_request: { model, messages: [{role, content}], config? } }
 *   stdout: { hookSpecificOutput: { hookEventName: "BeforeModel", llm_request?: { messages?: [...] } } }
 */
function runHook(opts: {
  llm_request: any;
  cwd: string;
  env?: Record<string, string>;
}) {
  const proc = spawnSync(process.execPath, [CLI_ENTRY, "hook", "before-model"], {
    input: JSON.stringify({
      session_id: "test",
      hook_event_name: "BeforeModel",
      cwd: opts.cwd,
      llm_request: opts.llm_request,
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

const e2e = haveBuild ? describe : describe.skip;

e2e("rafter hook before-model (Gemini)", () => {
  it("emits no-op envelope when llm_request has no secrets", () => {
    const r = runHook({
      llm_request: {
        model: "gemini-2.0-flash",
        messages: [{ role: "user", content: "Refactor foo.ts to use async" }],
      },
      cwd: tmpRoot,
    });
    expect(r.json?.hookSpecificOutput?.hookEventName).toBe("BeforeModel");
    // No-op: must NOT include llm_request override (would clobber the original).
    expect(r.json?.hookSpecificOutput?.llm_request).toBeUndefined();
    expect(fs.existsSync(path.join(tmpRoot, ".env"))).toBe(false);
  });

  it("rewrites the user message body when a secret is detected", () => {
    const r = runHook({
      llm_request: {
        model: "gemini-2.0-flash",
        messages: [
          { role: "system", content: "You are a coding agent." },
          { role: "user", content: "Connect with DB_PASSWORD=hunter2andmore please" },
        ],
      },
      cwd: tmpRoot,
    });
    expect(r.status).toBe(0);
    expect(r.json?.hookSpecificOutput?.hookEventName).toBe("BeforeModel");

    const overridden = r.json?.hookSpecificOutput?.llm_request;
    expect(overridden, "must return llm_request override").toBeTruthy();
    expect(Array.isArray(overridden.messages)).toBe(true);
    expect(overridden.messages.length).toBe(2);

    // System message preserved unchanged.
    expect(overridden.messages[0]).toEqual({ role: "system", content: "You are a coding agent." });

    // User message rewritten — literal removed, $VAR placeholder substituted.
    const rewrittenUser = overridden.messages[1];
    expect(rewrittenUser.role).toBe("user");
    expect(rewrittenUser.content).not.toContain("hunter2andmore");
    expect(rewrittenUser.content).toContain("$DB_PASSWORD");

    // .env + .gitignore side-effects.
    const env = fs.readFileSync(path.join(tmpRoot, ".env"), "utf-8");
    expect(env).toMatch(/DB_PASSWORD=hunter2andmore/);
    const gi = fs.readFileSync(path.join(tmpRoot, ".gitignore"), "utf-8");
    expect(gi).toContain(".env");
  });

  it("preserves non-user roles untouched even if their content matches a pattern", () => {
    const r = runHook({
      llm_request: {
        model: "gemini-2.0-flash",
        messages: [
          // model reply containing a secret-shaped string — must not be rewritten
          // (would corrupt history and the model never sent it to itself).
          { role: "model", content: "Earlier you said password=abc123def" },
          { role: "user", content: "no secrets in this turn" },
        ],
      },
      cwd: tmpRoot,
    });
    expect(r.status).toBe(0);
    // No rewrite: only user-role messages are scanned.
    expect(r.json?.hookSpecificOutput?.llm_request).toBeUndefined();
  });

  it("handles parts-array content shape (Gemini SDK native)", () => {
    const r = runHook({
      llm_request: {
        model: "gemini-2.0-flash",
        messages: [{
          role: "user",
          content: [
            { type: "text", text: "Use api_key=sk_test_secretvalue1234" },
          ],
        }],
      },
      cwd: tmpRoot,
    });
    expect(r.status).toBe(0);
    const overridden = r.json?.hookSpecificOutput?.llm_request;
    expect(overridden, "must return override for parts-array content").toBeTruthy();
    const userMsg = overridden.messages[0];
    expect(Array.isArray(userMsg.content)).toBe(true);
    const partText = userMsg.content[0].text;
    expect(partText).not.toContain("sk_test_secretvalue1234");
    expect(partText).toMatch(/\$/);
  });

  it("kill switch RAFTER_PROMPT_SHIELD=0 disables", () => {
    const r = runHook({
      llm_request: {
        model: "gemini-2.0-flash",
        messages: [{ role: "user", content: "DB_PASSWORD=letmein123" }],
      },
      cwd: tmpRoot,
      env: { RAFTER_PROMPT_SHIELD: "0" },
    });
    expect(r.json?.hookSpecificOutput?.llm_request).toBeUndefined();
    expect(fs.existsSync(path.join(tmpRoot, ".env"))).toBe(false);
  });

  it("malformed JSON fails open with no-op envelope", () => {
    const proc = spawnSync(process.execPath, [CLI_ENTRY, "hook", "before-model"], {
      input: "not json",
      encoding: "utf-8",
      timeout: 10000,
    });
    const json = parseHookOutput(proc.stdout);
    expect(json?.hookSpecificOutput?.hookEventName).toBe("BeforeModel");
    expect(json?.hookSpecificOutput?.llm_request).toBeUndefined();
  });

  it("missing llm_request fails open", () => {
    const proc = spawnSync(process.execPath, [CLI_ENTRY, "hook", "before-model"], {
      input: JSON.stringify({ session_id: "x" }),
      encoding: "utf-8",
      timeout: 10000,
    });
    const json = parseHookOutput(proc.stdout);
    expect(json?.hookSpecificOutput?.hookEventName).toBe("BeforeModel");
    expect(json?.hookSpecificOutput?.llm_request).toBeUndefined();
  });
});

/* ---------------- Gemini installer (BeforeModel) ---------------- */

const installerE2E = haveBuild ? describe : describe.skip;

installerE2E("agent init --with-gemini installs BeforeModel", () => {
  function realRafterEnv(): { home: string; bin: string } {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-gemini-install-"));
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

  it("wires before-model into ~/.gemini/settings.json when supported", () => {
    const { home, bin } = realRafterEnv();
    fs.mkdirSync(path.join(home, ".gemini"), { recursive: true });

    const result = spawnSync(
      process.execPath,
      [CLI_ENTRY, "agent", "init", "--with-gemini"],
      {
        cwd: home,
        encoding: "utf-8",
        timeout: 30000,
        env: { ...process.env, HOME: home, PATH: bin },
      }
    );
    expect(result.status, `installer crashed: ${result.stderr}`).toBe(0);

    const settings = JSON.parse(fs.readFileSync(path.join(home, ".gemini", "settings.json"), "utf-8"));
    const bm = settings.hooks?.BeforeModel ?? [];
    expect(bm.length).toBeGreaterThan(0);
    const cmd = bm[0]?.hooks?.[0]?.command as string | undefined;
    expect(cmd).toMatch(/rafter hook before-model/);

    // Round-trip: feed an actual Gemini-shaped llm_request through the wired
    // command and assert it returns a valid BeforeModel envelope.
    const payload = JSON.stringify({
      llm_request: {
        model: "gemini-2.0-flash",
        messages: [{ role: "user", content: "no secrets here, just a test" }],
      },
      cwd: home,
    });
    const exec = spawnSync(cmd!, {
      input: payload,
      encoding: "utf-8",
      timeout: 10000,
      shell: true,
      env: { ...process.env, HOME: home, PATH: bin },
    });
    expect(exec.status, `wired hook must execute: ${exec.stderr}`).toBe(0);
    const out = parseHookOutput(exec.stdout);
    expect(out?.hookSpecificOutput?.hookEventName).toBe("BeforeModel");

    fs.rmSync(home, { recursive: true, force: true });
  });

  it("skips BeforeModel when rafter on PATH lacks the subcommand", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-gemini-install-skip-"));
    const bin = path.join(home, "_bin");
    fs.mkdirSync(bin, { recursive: true });
    fs.symlinkSync(process.execPath, path.join(bin, "node"));
    fs.writeFileSync(
      path.join(bin, "rafter"),
      `#!/bin/sh\nfor a in "$@"; do [ "$a" = "before-model" ] && exit 1; done\nexit 0\n`,
      { mode: 0o755 }
    );
    fs.mkdirSync(path.join(home, ".gemini"), { recursive: true });

    const result = spawnSync(
      process.execPath,
      [CLI_ENTRY, "agent", "init", "--with-gemini"],
      {
        cwd: home,
        encoding: "utf-8",
        timeout: 30000,
        env: { ...process.env, HOME: home, PATH: bin },
      }
    );
    expect(result.status).toBe(0);

    const settings = JSON.parse(fs.readFileSync(path.join(home, ".gemini", "settings.json"), "utf-8"));
    const bm = settings.hooks?.BeforeModel ?? [];
    const rafterEntries = bm.filter((entry: any) =>
      (entry.hooks || []).some((h: any) =>
        typeof h.command === "string" && h.command.includes("rafter hook before-model")
      )
    );
    expect(rafterEntries.length).toBe(0);

    fs.rmSync(home, { recursive: true, force: true });
  });
});
