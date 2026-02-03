import { execSync } from "child_process";

export function git(cmd: string): string {
  return execSync(`git ${cmd}`, { stdio: ["ignore", "pipe", "ignore"] })
    .toString()
    .trim();
}

export function safeBranch(gitFn: (c: string) => string): string {
  try {
    return gitFn("symbolic-ref --quiet --short HEAD");
  } catch {
    return gitFn("rev-parse --short HEAD");
  }
}

export function parseRemote(url: string): string {
  url = url.replace(/^(https?:\/\/|git@)/, "").replace(":", "/");
  if (url.endsWith(".git")) url = url.slice(0, -4);
  const parts = url.split("/");
  return parts.slice(-2).join("/"); // owner/repo
}

export function detectRepo(opts: { repo?: string; branch?: string; quiet?: boolean }) {
  if (opts.repo && opts.branch) return opts;
  const repoEnv = process.env.GITHUB_REPOSITORY || process.env.CI_REPOSITORY;
  const branchEnv = process.env.GITHUB_REF_NAME || process.env.CI_COMMIT_BRANCH || process.env.CI_BRANCH;
  let repoSlug = opts.repo || repoEnv;
  let branch = opts.branch || branchEnv;
  try {
    if (!repoSlug || !branch) {
      if (git("rev-parse --is-inside-work-tree") !== "true")
        throw new Error("not a repo");
      if (!repoSlug) repoSlug = parseRemote(git("remote get-url origin"));
      if (!branch) {
        try {
          branch = safeBranch(git);
        } catch {
          branch = "main";
        }
      }
    }
    if ((!opts.repo || !opts.branch) && !opts.quiet) {
      console.error(`Repo auto-detected: ${repoSlug} @ ${branch} (note: scanning remote)`);
    }
    return { repo: repoSlug, branch };
  } catch {
    throw new Error(
      "Could not auto-detect Git repository. Please pass --repo and --branch explicitly."
    );
  }
}
