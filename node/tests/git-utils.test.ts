import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { parseRemote, safeBranch, detectRepo } from "../src/utils/git.js";

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

describe("safeBranch", () => {
  it("returns symbolic ref when available", () => {
    const gitFn = vi.fn().mockReturnValue("feature/my-branch");
    expect(safeBranch(gitFn)).toBe("feature/my-branch");
    expect(gitFn).toHaveBeenCalledWith("symbolic-ref --quiet --short HEAD");
  });

  it("falls back to rev-parse on detached HEAD", () => {
    const gitFn = vi.fn()
      .mockImplementationOnce(() => { throw new Error("not on branch"); })
      .mockReturnValueOnce("abc1234");
    expect(safeBranch(gitFn)).toBe("abc1234");
    expect(gitFn).toHaveBeenCalledTimes(2);
    expect(gitFn).toHaveBeenCalledWith("rev-parse --short HEAD");
  });
});

describe("detectRepo", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    // Clear CI env vars
    delete process.env.GITHUB_REPOSITORY;
    delete process.env.CI_REPOSITORY;
    delete process.env.GITHUB_REF_NAME;
    delete process.env.CI_COMMIT_BRANCH;
    delete process.env.CI_BRANCH;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("returns explicit repo and branch when both provided", () => {
    const result = detectRepo({ repo: "owner/repo", branch: "main" });
    expect(result).toEqual({ repo: "owner/repo", branch: "main" });
  });

  it("reads GITHUB_REPOSITORY and GITHUB_REF_NAME env vars", () => {
    process.env.GITHUB_REPOSITORY = "gh-owner/gh-repo";
    process.env.GITHUB_REF_NAME = "refs/heads/develop";
    const result = detectRepo({ quiet: true });
    expect(result).toEqual({ repo: "gh-owner/gh-repo", branch: "refs/heads/develop" });
  });

  it("reads CI_REPOSITORY and CI_COMMIT_BRANCH (GitLab)", () => {
    process.env.CI_REPOSITORY = "gl-group/gl-project";
    process.env.CI_COMMIT_BRANCH = "release/v2";
    const result = detectRepo({ quiet: true });
    expect(result).toEqual({ repo: "gl-group/gl-project", branch: "release/v2" });
  });

  it("reads CI_REPOSITORY and CI_BRANCH (generic CI)", () => {
    process.env.CI_REPOSITORY = "ci-owner/ci-repo";
    process.env.CI_BRANCH = "staging";
    const result = detectRepo({ quiet: true });
    expect(result).toEqual({ repo: "ci-owner/ci-repo", branch: "staging" });
  });

  it("prefers explicit opts over env vars", () => {
    process.env.GITHUB_REPOSITORY = "env-owner/env-repo";
    process.env.GITHUB_REF_NAME = "env-branch";
    const result = detectRepo({ repo: "explicit/repo", branch: "explicit-branch" });
    expect(result).toEqual({ repo: "explicit/repo", branch: "explicit-branch" });
  });

  it("uses GITHUB_REPOSITORY for repo but explicit branch", () => {
    process.env.GITHUB_REPOSITORY = "gh-owner/gh-repo";
    const result = detectRepo({ branch: "my-branch", quiet: true });
    expect(result).toEqual({ repo: "gh-owner/gh-repo", branch: "my-branch" });
  });

  it("GITHUB_REPOSITORY takes priority over CI_REPOSITORY", () => {
    process.env.GITHUB_REPOSITORY = "gh/repo";
    process.env.CI_REPOSITORY = "ci/repo";
    process.env.GITHUB_REF_NAME = "main";
    const result = detectRepo({ quiet: true });
    expect(result.repo).toBe("gh/repo");
  });

  it("GITHUB_REF_NAME takes priority over CI_COMMIT_BRANCH", () => {
    process.env.GITHUB_REPOSITORY = "owner/repo";
    process.env.GITHUB_REF_NAME = "gh-branch";
    process.env.CI_COMMIT_BRANCH = "gl-branch";
    const result = detectRepo({ quiet: true });
    expect(result.branch).toBe("gh-branch");
  });
});
