import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { spawnSync, execSync } from "child_process";
import { randomBytes } from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";
import {
  InstallSession,
  manifestPath,
  resourcesDir,
  sha256,
  type FileArtifact,
} from "../src/commands/agent/install-files.js";
import { autoUpdateLine, autoUpdateStampPath, maybeAutoUpdate } from "../src/commands/agent/auto-update.js";

/**
 * A file the user modified is kept with the new version beside it as
 * <file>.rafter-new; rafter flags it until the user reconciles, then notices
 * that they did. The pretool hook applies updates to unmodified files on its
 * own, once a day. Fixture: fixtures/install-0.11.2/home, the real state of a
 * published 0.11.2 `agent init --all`. Mirrors python/tests/test_install_reconcile.py.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");
const FIXTURE = path.resolve(PROJECT_ROOT, "..", "fixtures", "install-0.11.2", "home");
const CLI_DIST = path.join(PROJECT_ROOT, "dist", "index.js");
const DAY = 24 * 60 * 60 * 1000;

let home: string;

beforeEach(() => {
  home = path.join(fs.realpathSync(os.tmpdir()), `rafter-reconcile-${Date.now()}-${randomBytes(4).toString("hex")}`);
  fs.mkdirSync(home, { recursive: true });
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

function copyFixture(): void {
  fs.cpSync(FIXTURE, home, { recursive: true });
  for (const rel of [".claude/settings.json", ".codex/hooks.json", ".cursor/hooks.json", ".gemini/settings.json"]) {
    const p = path.join(home, rel);
    fs.writeFileSync(p, fs.readFileSync(p, "utf-8").replaceAll("__RAFTER_BIN__", "/usr/local/bin/rafter"));
  }
}

const silent = { info: () => {}, warn: () => {} };

describe("reconciling a modified file", () => {
  const f = () => path.join(home, "f.md");
  const pending = () => f() + ".rafter-new";
  const artifact = (content: string): FileArtifact => ({
    dest: f(), content: Buffer.from(content), resourceKey: "not-shipped", component: "c", platform: "p",
  });
  const run = (content: string) => {
    const s = new InstallSession({ root: home, out: silent, version: "test" });
    const outcome = s.apply(artifact(content));
    s.save();
    return outcome;
  };
  const entry = () => JSON.parse(fs.readFileSync(manifestPath(home), "utf-8")).files["f.md"];

  it("kept until the user acts, reconciled once when they keep theirs, then quiet until a new version", () => {
    expect(run("v1")).toBe("added");
    fs.writeFileSync(f(), "v1 + mine");

    expect(run("v2")).toBe("kept");
    expect(fs.readFileSync(pending(), "utf-8")).toBe("v2");
    expect(run("v2")).toBe("kept"); // still flagged while .rafter-new waits

    fs.rmSync(pending()); // "keep mine"
    expect(run("v2")).toBe("reconciled");
    expect(entry().reconciledWith).toBe(sha256("v2"));
    expect(run("v2")).toBe("unchanged");
    expect(fs.existsSync(pending())).toBe(false);
    expect(fs.readFileSync(f(), "utf-8")).toBe("v1 + mine");

    expect(run("v3")).toBe("kept"); // a new release flags it again
    expect(fs.readFileSync(pending(), "utf-8")).toBe("v3");
  });

  it("merging into .rafter-new and moving it over the file reconciles it", () => {
    run("v1");
    fs.writeFileSync(f(), "v1 + mine");
    expect(run("v2")).toBe("kept");
    fs.writeFileSync(pending(), "v2 + mine");
    expect(run("v2")).toBe("kept"); // the merge in progress is not overwritten
    expect(fs.readFileSync(pending(), "utf-8")).toBe("v2 + mine");

    fs.renameSync(pending(), f());
    expect(run("v2")).toBe("reconciled");
    expect(run("v2")).toBe("unchanged");
    expect(fs.readFileSync(f(), "utf-8")).toBe("v2 + mine");
  });

  it("taking rafter's version as is clears the reconcile state", () => {
    run("v1");
    fs.writeFileSync(f(), "v1 + mine");
    run("v2");
    fs.copyFileSync(pending(), f()); // copied, not moved: the leftover goes too
    expect(run("v2")).toBe("unchanged");
    expect(fs.existsSync(pending())).toBe(false);
    expect(entry().pendingSha).toBeUndefined();
    expect(run("v3")).toBe("updated");
  });
});

describe("hook auto-update over the 0.11.2 fixture", () => {
  const skill = () => path.join(home, ".claude", "skills", "rafter", "SKILL.md");
  const edited = () => path.join(home, ".cursor", "rules", "rafter.mdc");
  const shipped = (rel: string) => fs.readFileSync(path.join(resourcesDir(), rel));

  it("updates unmodified files, keeps and flags an edited one, and runs once per day", () => {
    copyFixture();
    fs.appendFileSync(edited(), "\nmy local note\n");
    const mine = fs.readFileSync(edited());
    const now = Date.now();

    const r = maybeAutoUpdate({ home, now, version: "99.0.0" });
    expect(r?.updated).toBeGreaterThan(0);
    expect(r?.needsReconcile).toEqual([edited()]);
    expect(fs.readFileSync(skill()).equals(shipped("skills/rafter/SKILL.md"))).toBe(true);
    expect(fs.readFileSync(edited()).equals(mine)).toBe(true);
    expect(fs.readFileSync(edited() + ".rafter-new").equals(shipped("cursor-rules/rafter.mdc"))).toBe(true);
    expect(autoUpdateLine(r)).toContain(`${edited()}.rafter-new`);
    // Only files: the manifest does not claim the whole install is current.
    expect(JSON.parse(fs.readFileSync(manifestPath(home), "utf-8")).cliVersion).toBeNull();

    expect(maybeAutoUpdate({ home, now: now + 60_000, version: "99.0.0" })).toBeNull();
    const nextDay = maybeAutoUpdate({ home, now: now + DAY + 1, version: "99.0.0" });
    expect(nextDay?.updated).toBe(0);
    expect(nextDay?.needsReconcile).toEqual([edited()]);
  });

  it("does not bring back a skill the user removed", () => {
    copyFixture();
    fs.rmSync(path.join(home, ".claude", "skills", "rafter-code-review"), { recursive: true });
    maybeAutoUpdate({ home, version: "99.0.0" });
    expect(fs.existsSync(path.join(home, ".claude", "skills", "rafter-code-review"))).toBe(false);
  });

  it("does not write through a symlink at a file or its .rafter-new", () => {
    copyFixture();
    const outside = path.join(home, "outside");
    fs.mkdirSync(outside);
    fs.rmSync(skill());
    fs.symlinkSync(path.join(outside, "dangling"), skill());
    const rule = path.join(home, ".cursor", "rules", "rafter.mdc");
    fs.appendFileSync(rule, "\nmine\n");
    fs.writeFileSync(path.join(outside, "victim"), "keep me");
    fs.symlinkSync(path.join(outside, "victim"), rule + ".rafter-new");
    maybeAutoUpdate({ home, version: "99.0.0" });
    expect(fs.existsSync(path.join(outside, "dangling"))).toBe(false);
    expect(fs.readFileSync(path.join(outside, "victim"), "utf-8")).toBe("keep me");
  });

  it("does nothing when the install is current, when nothing is installed, or when disabled", () => {
    expect(maybeAutoUpdate({ home, version: "99.0.0" })).toBeNull(); // empty home
    expect(fs.existsSync(autoUpdateStampPath(home))).toBe(true);

    copyFixture();
    fs.rmSync(autoUpdateStampPath(home));
    fs.writeFileSync(manifestPath(home), JSON.stringify({ schema: 1, cliVersion: "99.0.0", files: {} }));
    expect(maybeAutoUpdate({ home, version: "99.0.0" })).toBeNull();

    fs.rmSync(autoUpdateStampPath(home));
    fs.rmSync(manifestPath(home));
    process.env.RAFTER_DISABLE_AUTO_UPDATE = "1";
    try {
      expect(maybeAutoUpdate({ home, version: "99.0.0" })).toBeNull();
    } finally {
      delete process.env.RAFTER_DISABLE_AUTO_UPDATE;
    }
    expect(fs.readFileSync(skill()).equals(fs.readFileSync(path.join(FIXTURE, ".claude", "skills", "rafter", "SKILL.md")))).toBe(true);
  });
});

describe("built CLI: hook, status and update agree on reconcile state", () => {
  beforeAll(() => {
    if (!fs.existsSync(CLI_DIST)) execSync("pnpm run build", { cwd: PROJECT_ROOT, stdio: "inherit" });
  });

  function cli(args: string[], input?: string) {
    const r = spawnSync(process.execPath, [CLI_DIST, ...args], {
      cwd: home,
      input,
      encoding: "utf-8",
      timeout: 60_000,
      env: { ...process.env, HOME: home, XDG_CONFIG_HOME: path.join(home, ".config"), CI: "1", PATH: "/usr/bin:/bin" },
    });
    return { stdout: r.stdout, stderr: r.stderr, status: r.status ?? 1 };
  }

  it("the hook updates and flags without touching its decision; update notices the reconcile", () => {
    copyFixture();
    const skill = path.join(home, ".claude", "skills", "rafter", "SKILL.md");
    fs.appendFileSync(skill, "\nmy local note\n");

    const hook = cli(["hook", "pretool"], JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" } }));
    expect(hook.stdout).toBe("{}\n");
    expect(hook.status).toBe(0);
    expect(hook.stderr).toMatch(/^rafter: updated \d+ skill\/rule files to .*need(s)? reconciling with .*SKILL\.md\.rafter-new/m);
    expect(fs.existsSync(skill + ".rafter-new")).toBe(true);

    const status = JSON.parse(cli(["agent", "status", "--json"]).stdout);
    expect(status.needs_reconcile).toContain(skill);
    expect(status.stale).toBe(true); // hooks and instruction blocks still need `agent update`
    const text = cli(["agent", "status"]).stdout;
    expect(text).toContain(`${skill}.rafter-new`);
    expect(text).toContain("To reconcile: merge your changes into <file>.rafter-new");

    fs.rmSync(skill + ".rafter-new");
    const update = cli(["agent", "update"]);
    expect(update.stdout + update.stderr).toMatch(new RegExp(`reconciled +${skill.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    const again = cli(["agent", "update"]);
    expect(again.stdout + again.stderr).not.toContain(skill);
    expect(JSON.parse(cli(["agent", "status", "--json"]).stdout).needs_reconcile).toEqual([]);
  });
});
