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

function runCli(args: string[], cwd: string) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd,
    encoding: "utf8",
    timeout: 15000,
    env: {
      ...process.env,
      HOME: cwd,
      XDG_CONFIG_HOME: path.join(cwd, ".config"),
    },
  });
}

describe("agent --quiet (issue #31)", () => {
  it("init succeeds without informational stdout", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-quiet-init-"));

    try {
      const result = runCli(["agent", "init", "--quiet"], temp);
      expect(result.status).toBe(0);
      expect(result.stdout).toBe("");
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it("install-hook succeeds without informational stdout", () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-quiet-hook-"));

    try {
      const init = spawnSync("git", ["init", temp], { encoding: "utf8" });
      expect(init.status).toBe(0);

      const result = runCli(["agent", "install-hook", "--quiet"], temp);
      expect(result.status).toBe(0);
      expect(result.stdout).toBe("");
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });
});
