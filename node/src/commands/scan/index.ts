/**
 * rafter scan — top-level scan command group.
 *
 * Default (no subcommand): remote scan (same as `rafter run`)
 * rafter scan remote:       explicit alias for remote scan
 * rafter scan local [path]: hidden back-compat alias for `rafter secrets`
 *                           (was `rafter agent scan` before 0.7.4).
 */
import { Command } from "commander";
import { runRemoteScan } from "../backend/run.js";
import { createScanCommand as createLocalScanCommand } from "../agent/scan.js";

export function createScanGroupCommand(): Command {
  // "local" subcommand — back-compat alias for `rafter secrets`. Hidden from help.
  const localCmd = createLocalScanCommand();
  localCmd.name("local");
  localCmd.description("(deprecated alias for 'rafter secrets')");

  // "remote" subcommand — same handler as `rafter run`
  const remoteCmd = new Command("remote")
    .description("Trigger a remote backend security scan (explicit alias for 'rafter run')")
    .option("-r, --repo <repo>", "org/repo (default: current)")
    .option("-b, --branch <branch>", "branch (default: current else main)")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "md")
    .option("-m, --mode <mode>", "scan mode: fast | plus", "fast")
    .option("--github-token <token>", "GitHub PAT for private repos (or RAFTER_GITHUB_TOKEN env var)")
    .option("--skip-interactive", "do not wait for scan to complete")
    .option("--quiet", "suppress status messages")
    .action(async (opts) => {
      await runRemoteScan(opts);
    });

  // Root scan group — default action is remote scan
  const scanGroup = new Command("scan")
    .description("Trigger a remote security scan (requires RAFTER_API_KEY).")
    .enablePositionalOptions()
    .option("-r, --repo <repo>", "org/repo (default: current)")
    .option("-b, --branch <branch>", "branch (default: current else main)")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "md")
    .option("-m, --mode <mode>", "scan mode: fast | plus", "fast")
    .option("--github-token <token>", "GitHub PAT for private repos (or RAFTER_GITHUB_TOKEN env var)")
    .option("--skip-interactive", "do not wait for scan to complete")
    .option("--quiet", "suppress status messages");

  scanGroup.addCommand(localCmd, { hidden: true });
  scanGroup.addCommand(remoteCmd);

  // When invoked with no subcommand, run remote scan
  scanGroup.action(async (opts) => {
    await runRemoteScan(opts);
  });

  return scanGroup;
}
