import { Command } from "commander";
import fs from "fs";
import path from "path";
import { mapGates, formatGateMap } from "../scanners/gate-scanner.js";

export function createGatesCommand(): Command {
  return new Command("gates")
    .description("Map a codebase's security gates (functions that decide whether something is allowed) and their twins, for an audit")
    .argument("[path]", "Directory or file to map", ".")
    .option("--json", "Output JSON")
    .option("--limit <n>", "Number of ranked gates to show", "60")
    .option("--no-gitignore", "Do not honor .gitignore")
    .action((target: string, opts: { json?: boolean; limit: string; gitignore: boolean }) => {
      const limit = /^\d+$/.test(opts.limit) ? Number(opts.limit) : NaN;
      if (!Number.isInteger(limit) || limit < 1) {
        console.error(`Error: --limit must be a positive integer, got: ${opts.limit}`);
        process.exit(2);
      }
      const resolved = path.resolve(target);
      if (!fs.existsSync(resolved)) {
        console.error(`Error: Path not found: ${resolved}`);
        process.exit(2);
      }
      const map = mapGates(resolved, { limit, respectGitignore: opts.gitignore });
      if (map.stats.files_scanned === 0) {
        console.error(`Warning: no source files scanned under ${resolved} (none found, unreadable, oversize or generated)`);
      }
      if (opts.json) {
        process.stdout.write(JSON.stringify(map, null, 2) + "\n");
      } else {
        process.stdout.write(formatGateMap(map));
      }
      // exitCode, not exit(): exit() can cut off output still buffered for a pipe.
      process.exitCode = 0;
    });
}
