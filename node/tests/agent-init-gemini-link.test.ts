/**
 * `agent init --local --with-gemini` registers skills with `gemini skills link
 * <path>`, where the path is under the working directory. A directory name may
 * hold shell syntax, so the path must reach gemini as one literal argument and
 * never be interpreted by a shell.
 *
 * Runs the built CLI with a stub `gemini` on PATH that logs its arguments.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { execSync, spawnSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";

const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_DIST = path.join(PROJECT_ROOT, "dist", "index.js");

beforeAll(() => {
  if (!fs.existsSync(CLI_DIST)) {
    execSync("pnpm run build", { cwd: PROJECT_ROOT, stdio: "inherit" });
  }
});

describe.skipIf(process.platform === "win32")("agent init --local --with-gemini", () => {
  it("passes a working-directory path with shell syntax to gemini literally", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-gemini-link-"));
    try {
      const bin = path.join(root, "bin");
      const log = path.join(root, "calls.log");
      fs.mkdirSync(bin);
      fs.writeFileSync(
        path.join(bin, "gemini"),
        `#!/bin/sh\nfor a in "$@"; do printf '%s\\n' "$a" >> '${log}'; done\nexit 0\n`,
        { mode: 0o755 },
      );
      const home = path.join(root, "home");
      fs.mkdirSync(home);
      const project = path.join(root, "vendor", "$(touch MARKER)");
      fs.mkdirSync(project, { recursive: true });

      const r = spawnSync(process.execPath, [CLI_DIST, "agent", "init", "--local", "--with-gemini"], {
        cwd: project,
        encoding: "utf-8",
        timeout: 60_000,
        env: { ...process.env, HOME: home, XDG_CONFIG_HOME: path.join(home, ".config"), PATH: `${bin}:${process.env.PATH}`, CI: "1" },
      });

      expect(r.status).toBe(0);
      expect(fs.existsSync(path.join(project, "MARKER"))).toBe(false);
      const args = fs.readFileSync(log, "utf-8").split("\n");
      expect(args).toContain(path.join(project, ".agents", "skills", "rafter"));
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
