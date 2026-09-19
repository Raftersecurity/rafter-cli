import { execSync } from "child_process";

export function git(cmd: string): string {
  return execSync(`git ${cmd}`, { stdio: ["ignore", "pipe", "ignore"] })
    .toString()
    .trim();
}

/**
 * Return the current branch name.
 *
 * Throws on a detached HEAD (or when there is no HEAD at all, e.g. an
 * empty repo) instead of falling back to a commit SHA or a hardcoded
 * default branch. Neither is a real branch: a SHA is guaranteed to 404 as
 * a "branch" on the backend, and a hardcoded default is a guess that is
 * often wrong and, even when right, doesn't reflect what is actually
 * checked out.
 */
export function safeBranch(gitFn: (c: string) => string): string {
  try {
    return gitFn("symbolic-ref --quiet --short HEAD");
  } catch {
    throw new Error(
      "Could not determine the current branch (detached HEAD or no commits yet). " +
        "Please pass --branch explicitly."
    );
  }
}

export type Provider = "github" | "gitlab" | "gitea" | "bitbucket";

const SCHEME_RE = /^(https?|ssh):\/\//i;

/**
 * Split a git remote URL into its host + owner/repo slug, handling
 * `https://[user[:token]@]host[:port]/owner/repo(.git)` (and http, ssh),
 * and the scp-like `[user@]host:owner/repo(.git)`. Returns null when the
 * URL can't be parsed into host + slug.
 *
 * Uses the URL parser (not a blanket ":" -> "/" substitution) so a colon
 * inside userinfo — `https://user:token@host/...`, a real shape for
 * CI-embedded credentials — is never mistaken for the scp host:path
 * separator. Getting this wrong is a security bug, not just a parsing
 * one: the naive substitution let `https://github.com:x@evil.com/a/b`
 * read as host `github.com` (an allowed host) with the real host,
 * evil.com, silently discarded.
 */
function splitRemote(url: string): { host: string; slug: string } | null {
  let rest: string;
  if (SCHEME_RE.test(url)) {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return null;
    }
    if (!parsed.hostname) return null;
    rest = `${parsed.hostname}${parsed.pathname}`;
  } else if (url.includes(":")) {
    // scp-like: "[user@]host:owner/repo(.git)". The user (if any) is
    // whatever precedes the LAST "@" before this colon.
    const colonIdx = url.indexOf(":");
    const head = url.slice(0, colonIdx);
    const path = url.slice(colonIdx + 1);
    const atIdx = head.lastIndexOf("@");
    const host = atIdx === -1 ? head : head.slice(atIdx + 1);
    if (!host || host.includes("/")) return null;
    rest = `${host}/${path}`;
  } else {
    // No scheme, no ":" -- e.g. a bare filesystem path. Treated opaquely:
    // the leading segment stands in for "host" below, so it is rejected
    // unless it happens to equal a real host (it never will for a real
    // filesystem path).
    rest = url;
  }

  if (rest.endsWith(".git")) rest = rest.slice(0, -4);
  const parts = rest.split("/").filter((p) => p.length > 0);
  if (parts.length < 3) return null; // need host + owner + repo
  const host = parts[0];
  const slug = parts.slice(-2).join("/");
  return { host, slug };
}

/**
 * Map a git remote host to a provider we actually recognize. Unlike
 * providerForHost, returns null for a host we don't recognize instead of
 * defaulting to "github" — used where guessing is not safe.
 */
function knownProviderForHost(host: string): Provider | null {
  host = host.toLowerCase();
  if (host === "github.com") return "github";
  if (host === "gitlab.com" || host.endsWith(".gitlab.com")) return "gitlab";
  if (host === "bitbucket.org") return "bitbucket";
  if (host === "codeberg.org" || host.endsWith(".gitea.io")) return "gitea";
  return null;
}

/**
 * Parse a git remote URL into "owner/repo" format.
 *
 * Throws when the remote's host isn't one we recognize. Blindly slicing
 * the last two path segments of an arbitrary URL (the old behavior)
 * manufactures a wrong slug for anything that isn't GitHub/GitLab/
 * Bitbucket/Gitea shaped — e.g. an Azure DevOps remote
 * (`.../org/proj/_git/repo`) becomes `_git/repo`, and a bare filesystem
 * remote becomes `<parent-dir>/<repo>`. The backend turns that slug into
 * an invalid clone URL and 404s, burning a paid scan.
 */
export function parseRemote(url: string): string {
  const parts = splitRemote(url);
  if (!parts) {
    throw new Error(
      `Could not determine owner/repo from git remote "${url}". ` +
        "Please pass --repo and --branch explicitly."
    );
  }
  if (!knownProviderForHost(parts.host)) {
    throw new Error(
      `Unsupported git remote host "${parts.host}" (from "${url}"). ` +
        "Only GitHub, GitLab, Bitbucket, and Gitea remotes are auto-detected. " +
        "Please pass --repo and --branch explicitly."
    );
  }
  return parts.slug; // owner/repo
}

/**
 * Map a git remote host to a provider. `github` is the backward-compatible
 * default for any host we don't recognize — a GitHub user's request is
 * unaffected, and unknown self-hosted hosts fall back to the legacy behavior.
 * (Only used for the additive provider/repoUrl fields; parseRemote uses the
 * stricter knownProviderForHost and rejects what this would silently default.)
 */
export function providerForHost(host: string): Provider {
  return knownProviderForHost(host) ?? "github";
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

const AUTO_DETECT_FAILURE =
  "Could not auto-detect Git repository. Please pass --repo and --branch explicitly.";

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

  if (repoSlug && branch) {
    return { repo: repoSlug, branch, provider, repo_url: repoUrl };
  }

  let insideRepo: boolean;
  try {
    insideRepo = git("rev-parse --is-inside-work-tree") === "true";
  } catch {
    insideRepo = false;
  }
  if (!insideRepo) {
    throw new Error(AUTO_DETECT_FAILURE);
  }

  // Read the remote once when we need to detect the slug, and reuse it to
  // infer the provider + canonical clone URL. When repo/branch come from
  // env (CI), we never touch git here — behavior is byte-identical.
  // A rejection from parseRemote (unrecognized host) is deliberately NOT
  // swallowed into the generic message below — it names the offending
  // remote, which is the actionable part.
  if (!repoSlug) {
    let remoteUrl: string;
    try {
      remoteUrl = git("remote get-url origin");
    } catch {
      throw new Error(AUTO_DETECT_FAILURE);
    }
    repoSlug = parseRemote(remoteUrl);
    const inferred = inferRemote(remoteUrl);
    provider = inferred.provider;
    repoUrl = inferred.repoUrl;
  }

  if (!branch) {
    branch = safeBranch(git);
  }

  if ((!opts.repo || !opts.branch) && !opts.quiet) {
    console.error(`Repo auto-detected: ${repoSlug} @ ${branch} (note: scanning remote)`);
  }
  return { repo: repoSlug, branch, provider, repo_url: repoUrl };
}
