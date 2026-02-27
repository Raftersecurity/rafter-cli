import { Command } from "commander";
import { createScanCommand as createLocalScanCommand } from "../agent/scan.js";
import { runRemoteScan } from "../backend/run.js";

/**
 * `rafter scan` — top-level scan group.
 *
 * - `rafter scan` (no subcommand) → remote backend scan (same as `rafter run`)
 * - `rafter scan remote`          → explicit remote backend scan
 * - `rafter scan local [path]`    → local secret scanner
 */
export function createScanGroupCommand(): Command {
  const scan = new Command("scan")
    .description("Security scanning (local and remote)")
    .option("-r, --repo <repo>", "org/repo (default: current)")
    .option("-b, --branch <branch>", "branch (default: current else main)")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "md")
    .option("--skip-interactive", "do not wait for scan to complete")
    .option("--quiet", "suppress status messages")
    .action(runRemoteScan);

  // `rafter scan local [path]` → local secret scanner
  const localCmd = createLocalScanCommand();
  localCmd.name("local").description("Scan local files for secrets");
  scan.addCommand(localCmd);

  // `rafter scan remote` → explicit remote backend scan
  const remoteCmd = new Command("remote")
    .description("Trigger a remote backend security scan")
    .option("-r, --repo <repo>", "org/repo (default: current)")
    .option("-b, --branch <branch>", "branch (default: current else main)")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-f, --format <format>", "json | md", "md")
    .option("--skip-interactive", "do not wait for scan to complete")
    .option("--quiet", "suppress status messages")
    .action(runRemoteScan);
  scan.addCommand(remoteCmd);

  return scan;
}
