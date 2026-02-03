import { Command } from "commander";
import axios from "axios";
import ora from "ora";
import { detectRepo } from "../../utils/git.js";
import {
  API,
  resolveKey,
  EXIT_GENERAL_ERROR,
  EXIT_QUOTA_EXHAUSTED
} from "../../utils/api.js";
import { handleScanStatus } from "./scan-status.js";

export function createRunCommand(): Command {
  return new Command("run")
    .option("-r, --repo <repo>", "org/repo (default: current)")
    .option("-b, --branch <branch>", "branch (default: current else main)")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "md")
    .option("--skip-interactive", "do not wait for scan to complete")
    .option("--quiet", "suppress status messages")
    .action(async (opts) => {
      const key = resolveKey(opts.apiKey);
      let repo, branch;
      try {
        ({ repo, branch } = detectRepo({ repo: opts.repo, branch: opts.branch, quiet: opts.quiet }));
      } catch (e) {
        if (e instanceof Error) {
          console.error(e.message);
        } else {
          console.error(e);
        }
        process.exit(EXIT_GENERAL_ERROR);
      }

      if (!opts.quiet) {
        const spinner = ora("Submitting scan").start();
        try {
          const { data } = await axios.post(
            `${API}/static/scan`,
            { repository_name: repo, branch_name: branch },
            { headers: { "x-api-key": key } }
          );
          spinner.succeed(`Scan ID: ${data.scan_id}`);
          if (opts.skipInteractive) return;
          const exitCode = await handleScanStatus(data.scan_id, { "x-api-key": key }, opts.format, opts.quiet);
          process.exit(exitCode);
        } catch (e: any) {
          spinner.fail("Request failed");
          if (e.response?.status === 429) {
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
            { repository_name: repo, branch_name: branch },
            { headers: { "x-api-key": key } }
          );
          if (opts.skipInteractive) return;
          const exitCode = await handleScanStatus(data.scan_id, { "x-api-key": key }, opts.format, opts.quiet);
          process.exit(exitCode);
        } catch (e: any) {
          if (e.response?.status === 429) {
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
    });
}
