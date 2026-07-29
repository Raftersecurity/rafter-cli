import { Command } from "commander";
import axios from "axios";
import { apiUrl, resolveKey, writePayload, EXIT_GENERAL_ERROR } from "../../utils/api.js";
import { describeSitesError, rejectUnsupportedFormat } from "./errors.js";

export interface SitesCreateOpts {
  apiKey?: string;
  format?: string;
  quiet?: boolean;
}

/** Register a URL as a Site and kick off its first scan. Returns the process exit code. */
export async function runSitesCreate(url: string, opts: SitesCreateOpts): Promise<number> {
  if (rejectUnsupportedFormat(opts.format)) return EXIT_GENERAL_ERROR;
  const key = resolveKey(opts.apiKey);
  try {
    const { data } = await axios.post(
      apiUrl("static/sites"),
      { url },
      { headers: { "x-api-key": key } }
    );
    return writePayload(data, opts.format, opts.quiet);
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
    .action(async (url, opts) => {
      process.exit(await runSitesCreate(url, opts));
    });
}
