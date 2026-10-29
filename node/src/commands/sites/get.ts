import { Command } from "commander";
import { apiUrl, resolveKey, writePayload, EXIT_GENERAL_ERROR, apiClient} from "../../utils/api.js";
import { describeSitesError, rejectUnsupportedFormat } from "./errors.js";

export interface SitesGetOpts {
  apiKey?: string;
  format?: string;
  quiet?: boolean;
}

/** Get a site's status, latest run, and findings summary. Returns the process exit code. */
export async function runSitesGet(id: string, opts: SitesGetOpts): Promise<number> {
  if (rejectUnsupportedFormat(opts.format)) return EXIT_GENERAL_ERROR;
  const key = resolveKey(opts.apiKey);
  try {
    const { data } = await apiClient.get(
      apiUrl(`static/sites/${encodeURIComponent(id)}`),
      { headers: { "x-api-key": key } }
    );
    return writePayload(data, opts.format, opts.quiet);
  } catch (e: any) {
    const { message, exitCode } = describeSitesError(e);
    console.error(`Error: ${message}`);
    return exitCode;
  }
}

export function createSitesGetCommand(): Command {
  return new Command("get")
    .description("Get a site's status, latest run, and findings summary")
    .argument("<id>", "site's project id")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "json")
    .option("--quiet", "suppress status messages")
    .action(async (id, opts) => {
      process.exit(await runSitesGet(id, opts));
    });
}
