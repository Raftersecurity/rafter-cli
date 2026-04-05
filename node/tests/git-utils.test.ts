import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { parseRemote, safeBranch, detectRepo } from "../src/utils/git.js";

// ── parseRemote (pure function) ────────────────────────────────────

describe("parseRemote", () => {
  it("parses HTTPS GitHub URL", () => {
    expect(parseRemote("https://github.com/owner/repo.git")).toBe("owner/repo");
  });

  it("parses SSH GitHub URL", () => {
    expect(parseRemote("git@github.com:owner/repo.git")).toBe("owner/repo");
  });

  it("parses URL without .git suffix", () => {
    expect(parseRemote("https://github.com/owner/repo")).toBe("owner/repo");
  });

  it("parses GitLab URL", () => {
    expect(parseRemote("git@gitlab.com:group/project.git")).toBe("group/project");
  });

  it("handles nested paths (takes last two segments)", () => {
    expect(parseRemote("https://gitlab.com/group/subgroup/project.git")).toBe("subgroup/project");
  });

  it("parses HTTP URL (no S)", () => {
    expect(parseRemote("http://github.com/owner/repo.git")).toBe("owner/repo");
  });
});

// ── safeBranch ─────────────────────────────────────────────────────

describe("safeBranch", () => {
  it("returns branch from symbolic-ref on normal branch", () => {
    const gitFn = vi.fn().mockReturnValue("feature/abc");
    expect(safeBranch(gitFn)).toBe("feature/abc");
    expect(gitFn).toHaveBeenCalledWith("symbolic-ref --quiet --short HEAD");
  });

  it("falls back to rev-parse on detached HEAD", () => {
    const gitFn = vi.fn()
      .mockImplementationOnce(() => { throw new Error("not on a branch"); })
      .mockReturnValueOnce("abc1234");
    expect(safeBranch(gitFn)).toBe("abc1234");
    expect(gitFn).toHaveBeenCalledTimes(2);
    expect(gitFn).toHaveBeenNthCalledWith(2, "rev-parse --short HEAD");
  });
});

// ── detectRepo ─────────────────────────────────────────────────────

describe("detectRepo", () => {
  const envBackup: Record<string, string | undefined> = {};
  const envKeys = [
    "GITHUB_REPOSITORY", "CI_REPOSITORY",
    "GITHUB_REF_NAME", "CI_COMMIT_BRANCH", "CI_BRANCH",
  ];

  beforeEach(() => {
    for (const key of envKeys) {
      envBackup[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    for (const key of envKeys) {
      if (envBackup[key] !== undefined) {
        process.env[key] = envBackup[key];
      } else {
        delete process.env[key];
      }
    }
  });

  it("returns explicit repo and branch when both provided", () => {
    const result = detectRepo({ repo: "org/repo", branch: "main" });
    expect(result).toEqual({ repo: "org/repo", branch: "main" });
  });

  it("uses GITHUB_REPOSITORY env var", () => {
    process.env.GITHUB_REPOSITORY = "gh-org/gh-repo";
    process.env.GITHUB_REF_NAME = "develop";
    const result = detectRepo({});
    expect(result).toEqual({ repo: "gh-org/gh-repo", branch: "develop" });
  });

  it("uses CI_REPOSITORY env var as fallback", () => {
    process.env.CI_REPOSITORY = "ci-org/ci-repo";
    process.env.CI_COMMIT_BRANCH = "staging";
    const result = detectRepo({});
    expect(result).toEqual({ repo: "ci-org/ci-repo", branch: "staging" });
  });

  it("uses CI_BRANCH env var for branch", () => {
    process.env.GITHUB_REPOSITORY = "org/repo";
    process.env.CI_BRANCH = "circle-branch";
    const result = detectRepo({});
    expect(result).toEqual({ repo: "org/repo", branch: "circle-branch" });
  });

  it("explicit opts override env vars", () => {
    process.env.GITHUB_REPOSITORY = "env-org/env-repo";
    process.env.GITHUB_REF_NAME = "env-branch";
    const result = detectRepo({ repo: "my/repo", branch: "my-branch" });
    expect(result).toEqual({ repo: "my/repo", branch: "my-branch" });
  });

  it("GITHUB_REPOSITORY takes precedence over CI_REPOSITORY", () => {
    process.env.GITHUB_REPOSITORY = "gh/repo";
    process.env.CI_REPOSITORY = "ci/repo";
    process.env.GITHUB_REF_NAME = "main";
    const result = detectRepo({});
    expect(result).toEqual({ repo: "gh/repo", branch: "main" });
  });

  it("GITHUB_REF_NAME takes precedence over CI_COMMIT_BRANCH and CI_BRANCH", () => {
    process.env.GITHUB_REPOSITORY = "org/repo";
    process.env.GITHUB_REF_NAME = "gh-branch";
    process.env.CI_COMMIT_BRANCH = "gl-branch";
    process.env.CI_BRANCH = "ci-branch";
    const result = detectRepo({});
    expect(result).toEqual({ repo: "org/repo", branch: "gh-branch" });
  });
});
