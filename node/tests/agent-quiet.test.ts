/**
 * Regression tests for issue #31: quiet agent commands.
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const cli = path.resolve(__dirname, "../dist/index.js");

/**
 * Fully isolated environment: temp HOME, explicit global git config inside
 * that HOME, no system git config, and no inherited repo-pointing variables,
 * so neither the CLI nor git can touch the real user's config or hooks.
 */
function isolatedEnv(home: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    GIT_CONFIG_GLOBAL: path.join(home, ".gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
  };
  for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"]) {
    delete env[key];
  }
  return env;
}

function runIsolated(command: string, args: string[], cwd: string, home: string) {
  return spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    timeout: 15000,
    env: isolatedEnv(home),
  });
}

/** Run the CLI with cwd doubling as the isolated HOME. */
function runCli(args: string[], cwd: string) {
  return runIsolated(process.execPath, [cli, ...args], cwd, cwd);
}

describe("agent --quiet (issue #31)", () => {

  it("install-hook keeps errors on stderr under --quiet", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-quiet-error-"));

    try {
      const result = runCli(["agent", "install-hook", "--quiet"], temp);
      expect(result.status).toBe(1);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("Not in a git repository");
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });


  it("init succeeds without informational stdout", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-quiet-init-"));

    try {
      const result = runCli(["agent", "init", "--quiet"], temp);
      expect(result.status).toBe(0);
      expect(result.stdout).toBe("");

      const configPath = path.join(temp, ".rafter", "config.json");
      expect(fs.existsSync(configPath)).toBe(true);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it("install-hook succeeds without informational stdout", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-quiet-hook-"));

    try {
      const init = runIsolated("git", ["init", temp], temp, temp);
      expect(init.status).toBe(0);

      const result = runCli(["agent", "install-hook", "--quiet"], temp);
      expect(result.status).toBe(0);
      expect(result.stdout).toBe("");

      const hookPath = path.join(temp, ".git", "hooks", "pre-commit");
      expect(fs.existsSync(hookPath)).toBe(true);
      expect(fs.readFileSync(hookPath, "utf8")).toContain(
        "Rafter Security Pre-Commit Hook",
      );
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it("install-hook --push succeeds without informational stdout", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-quiet-push-"));
    const home = path.join(temp, "home");
    const repo = path.join(temp, "repo");

    try {
      fs.mkdirSync(home);
      fs.mkdirSync(repo);

      const init = runIsolated("git", ["init", repo], temp, home);
      expect(init.status).toBe(0);

      const result = runIsolated(
        process.execPath,
        [cli, "agent", "install-hook", "--push", "--quiet"],
        repo,
        home,
      );
      expect(result.status).toBe(0);
      expect(result.stdout).toBe("");

      const hookPath = path.join(repo, ".git", "hooks", "pre-push");
      expect(fs.existsSync(hookPath)).toBe(true);
      expect(fs.readFileSync(hookPath, "utf8")).toContain(
        "Rafter Security Pre-Push Hook",
      );
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it("install-hook --global succeeds without informational stdout", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-quiet-global-"));
    const home = path.join(temp, "home");
    const work = path.join(temp, "work");

    try {
      fs.mkdirSync(home);
      fs.mkdirSync(work);

      const result = runIsolated(
        process.execPath,
        [cli, "agent", "install-hook", "--global", "--quiet"],
        work,
        home,
      );
      expect(result.status).toBe(0);
      expect(result.stdout).toBe("");

      const hooksDir = path.join(home, ".rafter", "git-hooks");
      expect(fs.existsSync(path.join(hooksDir, "pre-commit"))).toBe(true);

      const hooksPath = runIsolated(
        "git",
        ["config", "--global", "--get", "core.hooksPath"],
        work,
        home,
      );
      expect(hooksPath.status).toBe(0);
      expect(hooksPath.stdout.trim()).toBe(hooksDir);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it("agent init --with-openclaw --quiet suppresses legacy migration output", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-quiet-openclaw-"));
    const home = path.join(temp, "home");
    const work = path.join(temp, "work");

    try {
      fs.mkdirSync(home);
      fs.mkdirSync(work);

      const legacyPath = path.join(home, ".openclaw", "skills", "rafter-security.md");
      fs.mkdirSync(path.dirname(legacyPath), { recursive: true });
      fs.writeFileSync(legacyPath, "# legacy rafter skill\n", "utf8");

      const result = runIsolated(
        process.execPath,
        [cli, "agent", "init", "--with-openclaw", "--quiet"],
        work,
        home,
      );
      expect(result.status).toBe(0);
      expect(result.stdout).toBe("");

      expect(fs.existsSync(legacyPath)).toBe(false);

      const skillPath = path.join(
        home,
        ".openclaw",
        "workspace",
        "skills",
        "rafter-security",
        "SKILL.md",
      );
      expect(fs.existsSync(skillPath)).toBe(true);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it("agent init --dry-run --quiet --with-cursor keeps the plan and warning", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-quiet-dryrun-"));
    const home = path.join(temp, "home");
    const work = path.join(temp, "work");

    try {
      fs.mkdirSync(home);
      fs.mkdirSync(work);

      const result = runIsolated(
        process.execPath,
        [cli, "agent", "init", "--dry-run", "--quiet", "--with-cursor"],
        work,
        home,
      );
      expect(result.status).toBe(0);
      expect(result.stdout).toContain("DRY RUN");
      expect(result.stdout).not.toContain("Rafter Agent Security Setup");
      expect(result.stdout).not.toContain("No agent environments detected");
      expect(result.stderr).toContain(
        "Cursor requested but not detected (~/.cursor not found)",
      );

      expect(fs.existsSync(path.join(home, ".rafter", "config.json"))).toBe(false);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });
});
