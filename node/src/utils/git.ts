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

export type Provider = "github" | "gitlab" | "gitea" | "bitbucket";

/**
 * Map a git remote host to a provider. `github` is the backward-compatible
 * default for any host we don't recognize — a GitHub user's request is
 * unaffected, and unknown self-hosted hosts fall back to the legacy behavior.
 */
export function providerForHost(host: string): Provider {
  host = host.toLowerCase();
  if (host === "github.com") return "github";
  if (host === "gitlab.com" || host.endsWith(".gitlab.com")) return "gitlab";
  if (host === "bitbucket.org") return "bitbucket";
  if (host === "codeberg.org" || host.endsWith(".gitea.io")) return "gitea";
  return "github"; // backward-compatible default
}

/**
 * Split a git remote URL into its host + owner/repo slug, handling both
 * `git@host:owner/repo(.git)` (scp-like) and `https://host/owner/repo(.git)`.
 * Returns null when the URL can't be parsed into host + slug.
 */
function splitRemote(url: string): { host: string; slug: string } | null {
  let rest = url.replace(/^(https?:\/\/|git@)/, "").replace(":", "/");
  if (rest.endsWith(".git")) rest = rest.slice(0, -4);
  const parts = rest.split("/").filter((p) => p.length > 0);
  if (parts.length < 3) return null; // need host + owner + repo
  const host = parts[0];
  const slug = parts.slice(-2).join("/");
  return { host, slug };
}

/**
 * Infer the provider and a canonical `https://<host>/<owner>/<repo>` clone URL
 * from a git remote (either scp-like `git@` or `https://` form). Falls back to
 * `{ provider: "github", repoUrl: undefined }` when the URL can't be parsed.
 */
export function inferRemote(url: string): { provider: Provider; repoUrl?: string } {
  const parts = splitRemote(url);
  if (!parts) return { provider: "github" };
  return {
    provider: providerForHost(parts.host),
    repoUrl: `https://${parts.host}/${parts.slug}`,
  };
}

export interface DetectedRepo {
  repo?: string;
  branch?: string;
  provider?: Provider;
  repo_url?: string;
}

export function detectRepo(opts: { repo?: string; branch?: string; quiet?: boolean }): DetectedRepo {
  // Both explicit — return them as-is. No provider/repo_url is inferred here;
  // the caller's --provider/--repo-url flags fill that in when needed.
  if (opts.repo && opts.branch) return { repo: opts.repo, branch: opts.branch };
  const repoEnv = process.env.GITHUB_REPOSITORY || process.env.CI_REPOSITORY;
  const branchEnv = process.env.GITHUB_REF_NAME || process.env.CI_COMMIT_BRANCH || process.env.CI_BRANCH;
  let repoSlug = opts.repo || repoEnv;
  let branch = opts.branch || branchEnv;
  let provider: Provider | undefined;
  let repoUrl: string | undefined;
  try {
    if (!repoSlug || !branch) {
      if (git("rev-parse --is-inside-work-tree") !== "true")
        throw new Error("not a repo");
      // Read the remote once when we need to detect the slug, and reuse it to
      // infer the provider + canonical clone URL. When repo/branch come from
      // env (CI), we never touch git here — behavior is byte-identical.
      if (!repoSlug) {
        const remoteUrl = git("remote get-url origin");
        repoSlug = parseRemote(remoteUrl);
        const inferred = inferRemote(remoteUrl);
        provider = inferred.provider;
        repoUrl = inferred.repoUrl;
      }
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
    return { repo: repoSlug, branch, provider, repo_url: repoUrl };
  } catch {
    throw new Error(
      "Could not auto-detect Git repository. Please pass --repo and --branch explicitly."
    );
  }
}
