import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { execSync } from "child_process";
import { parseRemote, safeBranch, detectRepo, providerForHost, inferRemote } from "../src/utils/git.js";

vi.mock("child_process");
const mockedExecSync = vi.mocked(execSync);

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

// sable-pqmw: parseRemote used to slice the last two path segments of ANY
// remote with no host check at all, so a non-GitHub-shaped remote silently
// produced a wrong slug (e.g. Azure DevOps's `.../_git/repo` becomes
// `_git/repo`; a filesystem remote becomes `<parent-dir>/<repo>`). The
// backend turns that slug into `https://github.com/{slug}` and 404s,
// burning a paid scan. It must now reject anything it can't recognize.
describe("parseRemote host validation", () => {
  it.each([
    ["github https", "https://github.com/owner/repo", "owner/repo"],
    ["github ssh", "git@github.com:owner/repo.git", "owner/repo"],
    ["github https with .git", "https://github.com/owner/repo.git", "owner/repo"],
    // GitLab stays supported -- separate multi-provider feature (sable-w79q)
    // that already sends provider + repo_url alongside.
    ["gitlab ssh", "git@gitlab.com:group/project.git", "group/project"],
  ])("%s still parses", (_label, url, expected) => {
    expect(parseRemote(url)).toBe(expected);
  });

  it.each([
    // Azure DevOps: naive last-two-segments yields "_git/repo".
    ["azure devops", "https://dev.azure.com/my-org/my-proj/_git/my-repo"],
    // Bare filesystem remote: naive last-two-segments yields
    // "<parent-dir>/<repo>" -- the "local/*" class seen in production.
    ["bare filesystem path", "/home/ci/local/my-repo"],
  ])("%s is rejected", (_label, url) => {
    expect(() => parseRemote(url)).toThrow(/unsupported/i);
  });

  it("names the offending host in the error", () => {
    expect(() =>
      parseRemote("https://dev.azure.com/my-org/my-proj/_git/my-repo")
    ).toThrow(/dev\.azure\.com/);
  });

  // Found in security review of this fix: a naive "replace : with /"
  // treats the userinfo separator the same as the SCP host:path
  // separator, so `host` (the value checked against the allowlist) can be
  // attacker-chosen credentials rather than the real host -- and
  // legitimate credentialed remotes (PAT-embedded HTTPS, common in CI)
  // hard-fail the same way.
  it.each([
    // CI token-embedded remotes -- real shapes, must keep working.
    ["github https with embedded token", "https://x-access-token:ghp_abc123@github.com/owner/repo.git", "owner/repo"],
    ["gitlab https with embedded CI token", "https://gitlab-ci-token:glcbt-abc@gitlab.com/group/project.git", "group/project"],
    // Explicit ssh:// scheme -- a normal, non-adversarial clone form.
    ["explicit ssh:// scheme", "ssh://git@github.com/owner/repo.git", "owner/repo"],
    ["explicit ssh:// scheme with port", "ssh://git@github.com:2222/owner/repo.git", "owner/repo"],
  ])("%s still parses", (_label, url, expected) => {
    expect(parseRemote(url)).toBe(expected);
  });

  it("does not let userinfo smuggle an unrecognized host past the check", () => {
    // The real host is evil.com; "github.com" only appears as userinfo.
    // Must be rejected (as evil.com), never accepted as github.com.
    expect(() =>
      parseRemote("https://github.com:x@evil.com/foo/bar.git")
    ).toThrow(/evil\.com/);
  });
});

// ── providerForHost (host → provider inference) ────────────────────

describe("providerForHost", () => {
  it("maps github.com → github", () => {
    expect(providerForHost("github.com")).toBe("github");
  });

  it("maps gitlab.com → gitlab", () => {
    expect(providerForHost("gitlab.com")).toBe("gitlab");
  });

  it("maps a self-hosted *.gitlab.com subdomain → gitlab", () => {
    expect(providerForHost("git.gitlab.com")).toBe("gitlab");
  });

  it("maps bitbucket.org → bitbucket", () => {
    expect(providerForHost("bitbucket.org")).toBe("bitbucket");
  });

  it("maps codeberg.org → gitea", () => {
    expect(providerForHost("codeberg.org")).toBe("gitea");
  });

  it("maps a *.gitea.io host → gitea", () => {
    expect(providerForHost("try.gitea.io")).toBe("gitea");
  });

  it("defaults an unknown host → github (backward-compatible)", () => {
    expect(providerForHost("git.example.com")).toBe("github");
  });

  it("is case-insensitive", () => {
    expect(providerForHost("GitLab.com")).toBe("gitlab");
  });
});

// ── inferRemote (provider + canonical repo_url) ────────────────────

describe("inferRemote", () => {
  it("infers github from an https remote and omits nothing special", () => {
    expect(inferRemote("https://github.com/owner/repo.git")).toEqual({
      provider: "github",
      repoUrl: "https://github.com/owner/repo",
    });
  });

  it("infers github from an ssh remote", () => {
    expect(inferRemote("git@github.com:owner/repo.git")).toEqual({
      provider: "github",
      repoUrl: "https://github.com/owner/repo",
    });
  });

  it("normalizes a gitlab ssh remote to a canonical https url", () => {
    expect(inferRemote("git@gitlab.com:group/project.git")).toEqual({
      provider: "gitlab",
      repoUrl: "https://gitlab.com/group/project",
    });
  });

  it("normalizes a gitlab https remote (no .git suffix)", () => {
    expect(inferRemote("https://gitlab.com/group/project")).toEqual({
      provider: "gitlab",
      repoUrl: "https://gitlab.com/group/project",
    });
  });

  it("normalizes a bitbucket ssh remote", () => {
    expect(inferRemote("git@bitbucket.org:team/repo.git")).toEqual({
      provider: "bitbucket",
      repoUrl: "https://bitbucket.org/team/repo",
    });
  });

  it("normalizes a bitbucket https remote", () => {
    expect(inferRemote("https://bitbucket.org/team/repo.git")).toEqual({
      provider: "bitbucket",
      repoUrl: "https://bitbucket.org/team/repo",
    });
  });

  it("infers gitea for codeberg.org", () => {
    expect(inferRemote("https://codeberg.org/owner/repo.git")).toEqual({
      provider: "gitea",
      repoUrl: "https://codeberg.org/owner/repo",
    });
  });

  it("infers gitea for a *.gitea.io ssh remote", () => {
    expect(inferRemote("git@try.gitea.io:owner/repo.git")).toEqual({
      provider: "gitea",
      repoUrl: "https://try.gitea.io/owner/repo",
    });
  });

  it("defaults an unknown host to github while still normalizing the url", () => {
    expect(inferRemote("https://git.example.com/owner/repo.git")).toEqual({
      provider: "github",
      repoUrl: "https://git.example.com/owner/repo",
    });
  });

  it("returns provider github with no repoUrl when the url is unparseable", () => {
    expect(inferRemote("not-a-url")).toEqual({ provider: "github" });
  });
});

// ── safeBranch ─────────────────────────────────────────────────────

describe("safeBranch", () => {
  it("returns branch from symbolic-ref on normal branch", () => {
    const gitFn = vi.fn().mockReturnValue("feature/abc");
    expect(safeBranch(gitFn)).toBe("feature/abc");
    expect(gitFn).toHaveBeenCalledWith("symbolic-ref --quiet --short HEAD");
  });

  // sable-pqmw: a detached HEAD must not submit a commit SHA as a branch
  // name -- it is not a branch and is guaranteed to 404 on the backend.
  // The old behavior fell back to `rev-parse --short HEAD`; assert that
  // even when a SHA IS available, it is never returned, and rev-parse is
  // never even attempted.
  it("throws on detached HEAD even when a SHA is available", () => {
    const gitFn = vi.fn()
      .mockImplementationOnce(() => { throw new Error("not on a branch"); })
      .mockReturnValueOnce("abc1234");
    expect(() => safeBranch(gitFn)).toThrow(/branch/i);
    expect(gitFn).toHaveBeenCalledTimes(1);
  });

  // sable-pqmw: total git failure (e.g. an empty repo with no commits)
  // must not fall back to a hardcoded "main" -- that guesses the default
  // branch and is often wrong, and is misleading even when it isn't.
  it("throws rather than inventing a default branch on total failure", () => {
    const gitFn = vi.fn().mockImplementation(() => {
      throw new Error("fatal: not a git repository");
    });
    expect(() => safeBranch(gitFn)).toThrow(/branch/i);
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

  // sable-pqmw: an unrecognized-host remote (e.g. Azure DevOps) must
  // surface as a clear, catchable error through the full detection path,
  // not a silently wrong repository slug.
  describe("with a real git remote (host validation)", () => {
    beforeEach(() => {
      mockedExecSync.mockReset();
      mockedExecSync.mockImplementation((cmd: unknown) => {
        const c = String(cmd);
        if (c.includes("rev-parse --is-inside-work-tree")) return "true";
        if (c.includes("remote get-url origin")) {
          return "https://dev.azure.com/my-org/my-proj/_git/my-repo";
        }
        throw new Error(`unexpected git invocation in test: ${c}`);
      });
    });

    afterEach(() => {
      mockedExecSync.mockReset();
    });

    it("throws naming the host for an unrecognized remote", () => {
      expect(() => detectRepo({})).toThrow(/dev\.azure\.com/);
    });
  });
});
