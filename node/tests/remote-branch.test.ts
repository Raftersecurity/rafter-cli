import { describe, it, expect } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { remoteBranchSha } from "../src/utils/git.js";

// `rafter run` scans the remote, so it must tell an unpushed local branch
// (remote answers, branch absent) apart from a pushed one and from a remote
// it cannot reach. Real git against a local bare origin, no network.
describe("remoteBranchSha", () => {
  it("returns the SHA for a pushed branch, null for an unpushed one, undefined when origin is unreachable", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-remote-branch-"));
    try {
      const g = (cwd: string, ...args: string[]) =>
        execFileSync("git", args, { cwd, stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
      const bare = path.join(root, "origin.git");
      const work = path.join(root, "work");
      fs.mkdirSync(work);
      g(root, "init", "-q", "--bare", bare);
      g(work, "init", "-q", "-b", "main");
      g(work, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "init");
      g(work, "remote", "add", "origin", bare);
      g(work, "push", "-q", "origin", "main");
      g(work, "checkout", "-q", "-b", "task/unpushed");

      expect(remoteBranchSha("main", work)).toBe(g(work, "rev-parse", "main"));
      expect(remoteBranchSha("task/unpushed", work)).toBeNull();

      g(work, "remote", "set-url", "origin", path.join(root, "missing.git"));
      expect(remoteBranchSha("main", work)).toBeUndefined();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
