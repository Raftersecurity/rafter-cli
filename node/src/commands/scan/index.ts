/**
 * rafter scan — top-level scan command group.
 *
 * Default (no subcommand): remote backend scan (same as `rafter run`)
 * rafter scan remote:       explicit alias for remote backend scan
 * rafter scan local [path]: local secret scanner (was `rafter agent scan`)
 */
import { Command } from "commander";
import { runRemoteScan } from "../backend/run.js";
import { createScanCommand as createLocalScanCommand } from "../agent/scan.js";

export function createScanGroupCommand(): Command {
  // "local" subcommand — reuses agent/scan.ts logic, renamed
  const localCmd = createLocalScanCommand();
  localCmd.name("local");
  localCmd.description("Scan files or directories for secrets (local)");

  // "remote" subcommand — same handler as `rafter run`
  const remoteCmd = new Command("remote")
    .description("Trigger a remote backend security scan (explicit alias for 'rafter run')")
    .option("-r, --repo <repo>", "org/repo (default: current)")
    .option("-b, --branch <branch>", "branch (default: current else main)")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "md")
    .option("--skip-interactive", "do not wait for scan to complete")
    .option("--quiet", "suppress status messages")
    .action(async (opts) => {
      await runRemoteScan(opts);
    });

  // Root scan group — default action is remote backend scan
  const scanGroup = new Command("scan")
    .description(
      "Scan for security issues. Default: remote backend scan. Use 'scan local' for local secret scanning."
    )
    .option("-r, --repo <repo>", "org/repo (default: current)")
    .option("-b, --branch <branch>", "branch (default: current else main)")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "md")
    .option("--skip-interactive", "do not wait for scan to complete")
    .option("--quiet", "suppress status messages");

  scanGroup.addCommand(localCmd);
  scanGroup.addCommand(remoteCmd);

  // When invoked with no subcommand, run remote backend scan
  scanGroup.action(async (opts) => {
    await runRemoteScan(opts);
  });

  return scanGroup;
}
