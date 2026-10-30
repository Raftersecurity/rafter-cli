import { Command } from "commander";
import { apiUrl, resolveKey, writePayload, EXIT_GENERAL_ERROR, apiClient} from "../../utils/api.js";
import { describeSitesError, rejectUnsupportedFormat } from "./errors.js";
import { waitForSiteRun, parseWaitTimeout, SitesWaitDeps } from "./wait.js";

const VALID_SECTIONS = new Set(["flight", "security", "dns"]);

/** True when the argument parses as an absolute URL (has a scheme); false → treat as a project id. */
function looksLikeUrl(value: string): boolean {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

export interface SitesScanOpts {
  apiKey?: string;
  format?: string;
  sections?: string;
  quiet?: boolean;
  wait?: boolean;
  timeout?: string | number;
}

/**
 * Trigger a re-scan of an existing site, identified by project id or URL.
 * Returns the process exit code.
 *
 * `waitDeps` overrides the poll interval and clock used by `--wait`; see
 * `runSitesCreate`'s docstring — same contract, no CLI flag of its own.
 */
export async function runSitesScan(
  projectIdOrUrl: string,
  opts: SitesScanOpts,
  waitDeps: SitesWaitDeps = {}
): Promise<number> {
  if (rejectUnsupportedFormat(opts.format)) return EXIT_GENERAL_ERROR;

  let timeoutSeconds = 0;
  if (opts.wait) {
    const parsed = parseWaitTimeout(opts.timeout);
    if (parsed.error) {
      console.error(parsed.error);
      return EXIT_GENERAL_ERROR;
    }
    timeoutSeconds = parsed.seconds;
  }

  const key = resolveKey(opts.apiKey);

  const isUrl = looksLikeUrl(projectIdOrUrl);
  const body: Record<string, unknown> = isUrl
    ? { url: projectIdOrUrl }
    : { projectId: projectIdOrUrl };

  if (opts.sections) {
    const sections = String(opts.sections).split(",").map((s) => s.trim()).filter(Boolean);
    const invalid = sections.filter((s) => !VALID_SECTIONS.has(s));
    if (invalid.length > 0) {
      console.error(`Error: invalid --sections value(s): ${invalid.join(", ")} (expected: flight, security, dns)`);
      return 1;
    }
    body.sections = sections;
  }

  try {
    const { data } = await apiClient.post(
      apiUrl("static/sites/scan"),
      body,
      { headers: { "x-api-key": key } }
    );
    if (!opts.wait) return writePayload(data, opts.format, opts.quiet);

    const runId = data?.run?.id;
    if (!runId) {
      console.error("Error: no run was started; nothing to wait for.");
      return writePayload(data, opts.format, opts.quiet);
    }
    // The scan response carries only `run`, not the site itself. Prefer a
    // site id the response names explicitly; fall back to the argument only
    // when it was already a project id (not a URL we'd have no site id for).
    const siteId = data?.run?.project_id ?? (!isUrl ? projectIdOrUrl : undefined);
    if (!siteId) {
      console.error(
        "Error: cannot determine the site id to wait on (the scan response named none, " +
        "and a URL was given instead of a project id). Use 'rafter sites list' to find it, " +
        `then 'rafter sites get <id>' to check run ${runId}.`
      );
      return EXIT_GENERAL_ERROR;
    }
    return waitForSiteRun(siteId, runId, { apiKey: opts.apiKey, format: opts.format, quiet: opts.quiet, timeoutSeconds }, waitDeps);
  } catch (e: any) {
    const { message, exitCode } = describeSitesError(e);
    console.error(`Error: ${message}`);
    return exitCode;
  }
}

export function createSitesScanCommand(): Command {
  return new Command("scan")
    .description("Trigger a re-scan of an existing site")
    .argument("<projectIdOrUrl>", "site's project id, or its URL")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "json")
    .option("--sections <sections>", "comma-separated subset of flight,security,dns (default: all)")
    .option("--quiet", "suppress status messages")
    .option("--wait", "poll until the triggered run finishes (succeeded or failed)")
    .option("--timeout <seconds>", "max seconds to wait with --wait (default: 900)")
    .action(async (projectIdOrUrl, opts) => {
      process.exit(await runSitesScan(projectIdOrUrl, opts));
    });
}
