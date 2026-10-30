import { Command } from "commander";
import { apiUrl, resolveKey, writePayload, EXIT_SUCCESS, apiClient} from "../../utils/api.js";
import { describeSitesError, stripControlCharsForDisplay } from "./errors.js";

export interface SitesReportOpts {
  apiKey?: string;
  format?: string;
  quiet?: boolean;
}

/**
 * Get a site's full security report, as JSON (default) or Markdown. Unlike
 * `create`/`scan`/`list`/`get`, `--format md` is valid here — the report
 * route actually renders one — so this does NOT call rejectUnsupportedFormat.
 *
 * `format=json` prints the `{"report": {...}}` body the same way the other
 * sites commands print theirs (writePayload). `format=md` prints the raw
 * markdown body as-is, after stripping control characters (see
 * stripControlCharsForDisplay) — the report's content comes from scanning a
 * third-party site and is not trusted terminal input.
 */
export async function runSitesReport(id: string, opts: SitesReportOpts): Promise<number> {
  const fmt = opts.format === "md" ? "md" : "json";
  const key = resolveKey(opts.apiKey);
  try {
    const { data } = await apiClient.get(
      apiUrl(`static/sites/${encodeURIComponent(id)}/report`),
      { params: { format: fmt }, headers: { "x-api-key": key } }
    );
    if (fmt === "md") {
      const text = typeof data === "string" ? data : String(data);
      process.stdout.write(stripControlCharsForDisplay(text));
      return EXIT_SUCCESS;
    }
    return writePayload(data, opts.format, opts.quiet);
  } catch (e: any) {
    const { message, exitCode } = describeSitesError(e);
    console.error(`Error: ${message}`);
    return exitCode;
  }
}

export function createSitesReportCommand(): Command {
  return new Command("report")
    .description("Get a site's full security report (JSON or Markdown)")
    .argument("<id>", "site's project id")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "json")
    .option("--quiet", "suppress status messages")
    .action(async (id, opts) => {
      process.exit(await runSitesReport(id, opts));
    });
}
