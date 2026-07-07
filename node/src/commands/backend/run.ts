import { Command } from "commander";
import axios from "axios";
import ora from "ora";
import { detectRepo } from "../../utils/git.js";
import {
  API,
  resolveKey,
  EXIT_GENERAL_ERROR,
  EXIT_QUOTA_EXHAUSTED,
  handle403
} from "../../utils/api.js";
import { handleScanStatus } from "./scan-status.js";

export interface RunOpts {
  repo?: string;
  branch?: string;
  apiKey?: string;
  format?: string;
  mode?: string;
  skipInteractive?: boolean;
  quiet?: boolean;
  githubToken?: string;
  provider?: string;
  repoUrl?: string;
}

/**
 * Shared handler for the remote backend scan (used by both `rafter run` and `rafter scan` / `rafter scan remote`).
 */
export async function runRemoteScan(opts: RunOpts): Promise<void> {
  const key = resolveKey(opts.apiKey);
  const ghToken = opts.githubToken || process.env.RAFTER_GITHUB_TOKEN;
  let repo: string | undefined, branch: string | undefined;
  let detectedProvider: string | undefined, detectedRepoUrl: string | undefined;
  try {
    ({ repo, branch, provider: detectedProvider, repo_url: detectedRepoUrl } = detectRepo({
      repo: opts.repo,
      branch: opts.branch,
      quiet: opts.quiet,
    }));
  } catch (e) {
    if (e instanceof Error) {
      console.error(e.message);
    } else {
      console.error(e);
    }
    process.exit(EXIT_GENERAL_ERROR);
  }

  // Explicit flags override inferred values.
  const provider = opts.provider ?? detectedProvider;
  const repoUrl = opts.repoUrl ?? detectedRepoUrl;

  const body: Record<string, string> = {
    repository_name: repo!,
    branch_name: branch!,
    scan_mode: opts.mode ?? "fast",
  };
  if (ghToken) body.github_token = ghToken;

  // Additive, backward-compatible: only send provider + repo_url for non-github
  // remotes. For github (or an unknown host that defaulted to github), omit both
  // so the request body is byte-identical to the legacy github-only behavior.
  if (provider && provider !== "github" && repoUrl) {
    body.provider = provider;
    body.repo_url = repoUrl;
  }

  if (!opts.quiet) {
    const spinner = ora("Submitting scan").start();
    try {
      const { data } = await axios.post(
        `${API}/static/scan`,
        body,
        { headers: { "x-api-key": key } }
      );
      spinner.succeed(`Scan ID: ${data.scan_id}`);
      if (opts.skipInteractive) return;
      const exitCode = await handleScanStatus(data.scan_id, { "x-api-key": key }, opts.format ?? "md", opts.quiet);
      process.exit(exitCode);
    } catch (e: any) {
      spinner.fail("Request failed");
      const forbiddenCode = handle403(e);
      if (forbiddenCode >= 0) {
        process.exit(forbiddenCode);
      } else if (e.response?.status === 429) {
        console.error("Quota exhausted");
        process.exit(EXIT_QUOTA_EXHAUSTED);
      } else if (e.response?.data) {
        console.error(e.response.data);
      } else if (e instanceof Error) {
        console.error(e.message);
      } else {
        console.error(e);
      }
      process.exit(EXIT_GENERAL_ERROR);
    }
  } else {
    try {
      const { data } = await axios.post(
        `${API}/static/scan`,
        body,
        { headers: { "x-api-key": key } }
      );
      if (opts.skipInteractive) return;
      const exitCode = await handleScanStatus(data.scan_id, { "x-api-key": key }, opts.format ?? "md", opts.quiet);
      process.exit(exitCode);
    } catch (e: any) {
      const forbiddenCode = handle403(e);
      if (forbiddenCode >= 0) {
        process.exit(forbiddenCode);
      } else if (e.response?.status === 429) {
        process.exit(EXIT_QUOTA_EXHAUSTED);
      } else if (e.response?.data) {
        console.error(e.response.data);
      } else if (e instanceof Error) {
        console.error(e.message);
      } else {
        console.error(e);
      }
      process.exit(EXIT_GENERAL_ERROR);
    }
  }
}

function addRunOptions(cmd: Command): Command {
  return cmd
    .option("-r, --repo <repo>", "org/repo (default: current)")
    .option("-b, --branch <branch>", "branch (default: current else main)")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "md")
    .option("-m, --mode <mode>", "scan mode: fast | plus", "fast")
    .option("--github-token <token>", "GitHub PAT for private repos (or RAFTER_GITHUB_TOKEN env var)")
    .option("--provider <provider>", "git provider: gitlab | gitea | bitbucket (default: auto-detected; github requires nothing)")
    .option("--repo-url <url>", "full https clone URL for non-github remotes (default: auto-detected)")
    .option("--skip-interactive", "do not wait for scan to complete")
    .option("--quiet", "suppress status messages");
}

export function createRunCommand(): Command {
  return addRunOptions(
    new Command("run")
      .description("Trigger a remote security scan")
  ).action(async (opts) => {
    await runRemoteScan(opts);
  });
}
