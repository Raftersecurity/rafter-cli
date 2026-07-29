import { Command } from "commander";
import axios from "axios";
import { apiUrl, resolveKey, writePayload, EXIT_GENERAL_ERROR } from "../../utils/api.js";
import { describeSitesError, rejectUnsupportedFormat } from "./errors.js";

export interface SitesListOpts {
  apiKey?: string;
  format?: string;
  limit?: string | number;
  offset?: string | number;
  includeArchived?: boolean;
  quiet?: boolean;
}

/** List registered sites, paginated. Returns the process exit code. */
export async function runSitesList(opts: SitesListOpts): Promise<number> {
  if (rejectUnsupportedFormat(opts.format)) return EXIT_GENERAL_ERROR;
  const key = resolveKey(opts.apiKey);
  const params: Record<string, string> = {};
  if (opts.limit !== undefined) params.limit = String(opts.limit);
  if (opts.offset !== undefined) params.offset = String(opts.offset);
  if (opts.includeArchived) params.include_archived = "true";

  try {
    const { data } = await axios.get(
      apiUrl("static/sites"),
      { params, headers: { "x-api-key": key } }
    );
    return writePayload(data, opts.format, opts.quiet);
  } catch (e: any) {
    const { message, exitCode } = describeSitesError(e);
    console.error(`Error: ${message}`);
    return exitCode;
  }
}

export function createSitesListCommand(): Command {
  return new Command("list")
    .description("List registered sites")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "json")
    .option("--limit <limit>", "results per page, 1-100 (default: 25)")
    .option("--offset <offset>", "pagination offset (default: 0)")
    .option("--include-archived", "include archived sites")
    .option("--quiet", "suppress status messages")
    .action(async (opts) => {
      process.exit(await runSitesList(opts));
    });
}
