/**
 * rafter issues create from-scan — create GitHub issues from scan results.
 *
 * Supports both:
 * - Backend scans: --scan-id <id> (fetches from Rafter API)
 * - Local scans: --from-local <path> (reads JSON file from `rafter scan local --format json`)
 */
import { Command } from "commander";
import fs from "fs";
import axios from "axios";
import { API, resolveKey, EXIT_GENERAL_ERROR } from "../../utils/api.js";
import { detectRepo } from "../../utils/git.js";
import { fmt } from "../../utils/formatter.js";
import { createIssue, listOpenIssues } from "./github-client.js";
import { findDuplicates } from "./dedup.js";
import {
  buildFromBackendVulnerability,
  buildFromLocalMatch,
  IssueDraft,
  BackendVulnerability,
  LocalScanResult,
} from "./issue-builder.js";

export function createFromScanCommand(): Command {
  return new Command("from-scan")
    .description("Create GitHub issues from scan results")
    .option("--scan-id <id>", "Backend scan ID to create issues from")
    .option(
      "--from-local <path>",
      "Path to local scan JSON (from rafter scan local --format json)"
    )
    .option("-r, --repo <repo>", "Target GitHub repo (org/repo)")
    .option(
      "-k, --api-key <key>",
      "Rafter API key (for --scan-id)"
    )
    .option("--no-dedup", "Skip deduplication check")
    .option("--dry-run", "Show issues that would be created without creating them")
    .option("--quiet", "Suppress status messages")
    .action(async (opts) => {
      try {
        await runFromScan(opts);
      } catch (e: any) {
        console.error(fmt.error(e.message || String(e)));
        process.exit(EXIT_GENERAL_ERROR);
      }
    });
}

async function runFromScan(opts: {
  scanId?: string;
  fromLocal?: string;
  repo?: string;
  apiKey?: string;
  dedup?: boolean;
  dryRun?: boolean;
  quiet?: boolean;
}): Promise<void> {
  if (!opts.scanId && !opts.fromLocal) {
    console.error(
      fmt.error("Provide --scan-id or --from-local")
    );
    process.exit(EXIT_GENERAL_ERROR);
  }

  // Resolve target repo
  let repo: string;
  if (opts.repo) {
    repo = opts.repo;
  } else {
    const detected = detectRepo({});
    repo = detected.repo!;
  }

  if (!opts.quiet) {
    console.error(fmt.info(`Target repo: ${repo}`));
  }

  // Build issue drafts from scan results
  let drafts: IssueDraft[];

  if (opts.scanId) {
    drafts = await draftsFromBackendScan(opts.scanId, opts.apiKey);
  } else {
    drafts = draftsFromLocalScan(opts.fromLocal!);
  }

  if (drafts.length === 0) {
    if (!opts.quiet) {
      console.error(fmt.success("No findings to create issues for"));
    }
    return;
  }

  if (!opts.quiet) {
    console.error(fmt.info(`Found ${drafts.length} findings`));
  }

  // Dedup against existing open issues
  if (opts.dedup !== false) {
    const existing = listOpenIssues(repo);
    const dupes = findDuplicates(
      existing,
      drafts.map((d) => d.fingerprint)
    );
    const before = drafts.length;
    drafts = drafts.filter((d) => !dupes.has(d.fingerprint));
    if (before !== drafts.length && !opts.quiet) {
      console.error(
        fmt.info(`Skipped ${before - drafts.length} duplicate(s)`)
      );
    }
  }

  if (drafts.length === 0) {
    if (!opts.quiet) {
      console.error(fmt.success("All findings already have open issues"));
    }
    return;
  }

  // Dry run — print what would be created
  if (opts.dryRun) {
    console.error(
      fmt.info(`Would create ${drafts.length} issue(s):`)
    );
    for (const draft of drafts) {
      console.error(`  - ${draft.title}`);
    }
    // Output drafts as JSON to stdout for piping
    process.stdout.write(JSON.stringify(drafts, null, 2));
    return;
  }

  // Create issues
  const created: string[] = [];
  for (const draft of drafts) {
    try {
      const issue = createIssue({
        repo,
        title: draft.title,
        body: draft.body,
        labels: draft.labels,
      });
      created.push(issue.html_url);
      if (!opts.quiet) {
        console.error(fmt.success(`Created: ${issue.html_url}`));
      }
    } catch (e: any) {
      console.error(fmt.error(`Failed to create issue: ${e.message}`));
    }
  }

  // Output created issue URLs to stdout
  if (created.length > 0) {
    process.stdout.write(created.join("\n") + "\n");
  }

  if (!opts.quiet) {
    console.error(
      fmt.success(
        `Created ${created.length}/${drafts.length} issue(s)`
      )
    );
  }
}

async function draftsFromBackendScan(
  scanId: string,
  apiKey?: string
): Promise<IssueDraft[]> {
  const key = resolveKey(apiKey);
  const { data } = await axios.get(`${API}/static/scan`, {
    params: { scan_id: scanId, format: "json" },
    headers: { "x-api-key": key },
  });

  const vulns: BackendVulnerability[] = data.vulnerabilities || [];
  return vulns.map(buildFromBackendVulnerability);
}

function draftsFromLocalScan(filePath: string): IssueDraft[] {
  const raw = fs.readFileSync(filePath, "utf-8");
  const results: LocalScanResult[] = JSON.parse(raw);
  const drafts: IssueDraft[] = [];

  for (const result of results) {
    for (const match of result.matches) {
      drafts.push(buildFromLocalMatch(result.file, match));
    }
  }

  return drafts;
}
