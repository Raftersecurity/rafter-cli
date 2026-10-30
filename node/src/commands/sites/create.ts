import { Command } from "commander";
import { apiUrl, resolveKey, writePayload, EXIT_GENERAL_ERROR, apiClient} from "../../utils/api.js";
import { describeSitesError, rejectUnsupportedFormat } from "./errors.js";
import { waitForSiteRun, parseWaitTimeout, SitesWaitDeps } from "./wait.js";

export interface SitesCreateOpts {
  apiKey?: string;
  format?: string;
  quiet?: boolean;
  wait?: boolean;
  timeout?: string | number;
}

/**
 * Register a URL as a Site and kick off its first scan. Returns the process
 * exit code.
 *
 * `waitDeps` overrides the poll interval and clock used by `--wait`; it has
 * no CLI flag of its own — production call sites omit it, and tests pass a
 * zero-ish interval and a fake clock so `--wait` tests don't actually sleep.
 */
export async function runSitesCreate(
  url: string,
  opts: SitesCreateOpts,
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
  try {
    const { data } = await apiClient.post(
      apiUrl("static/sites"),
      { url },
      { headers: { "x-api-key": key } }
    );
    if (!opts.wait) return writePayload(data, opts.format, opts.quiet);

    const runId = data?.run?.id;
    if (!runId) {
      // No run was started — the site already existed, or the first scan
      // failed to kick off (`scan_error`). Either way there is nothing to
      // poll; report the create result as-is.
      console.error("Error: no run was started; nothing to wait for.");
      return writePayload(data, opts.format, opts.quiet);
    }
    const siteId = data?.site?.id;
    return waitForSiteRun(siteId, runId, { apiKey: opts.apiKey, format: opts.format, quiet: opts.quiet, timeoutSeconds }, waitDeps);
  } catch (e: any) {
    const { message, exitCode } = describeSitesError(e);
    console.error(`Error: ${message}`);
    return exitCode;
  }
}

export function createSitesCreateCommand(): Command {
  return new Command("create")
    .description("Register a site for live monitoring and kick off its first scan")
    .argument("<url>", "URL of the site to monitor")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "json")
    .option("--quiet", "suppress status messages")
    .option("--wait", "poll until the triggered run finishes (succeeded or failed)")
    .option("--timeout <seconds>", "max seconds to wait with --wait (default: 900)")
    .action(async (url, opts) => {
      process.exit(await runSitesCreate(url, opts));
    });
}
