import { Command } from "commander";
import axios from "axios";
import { apiUrl, resolveKey, writePayload, EXIT_GENERAL_ERROR } from "../../utils/api.js";
import { describeSitesError, rejectUnsupportedFormat } from "./errors.js";

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
}

/** Trigger a re-scan of an existing site, identified by project id or URL. Returns the process exit code. */
export async function runSitesScan(projectIdOrUrl: string, opts: SitesScanOpts): Promise<number> {
  if (rejectUnsupportedFormat(opts.format)) return EXIT_GENERAL_ERROR;
  const key = resolveKey(opts.apiKey);

  const body: Record<string, unknown> = looksLikeUrl(projectIdOrUrl)
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
    const { data } = await axios.post(
      apiUrl("static/sites/scan"),
      body,
      { headers: { "x-api-key": key } }
    );
    return writePayload(data, opts.format, opts.quiet);
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
    .action(async (projectIdOrUrl, opts) => {
      process.exit(await runSitesScan(projectIdOrUrl, opts));
    });
}
