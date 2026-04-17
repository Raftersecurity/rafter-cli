import { Command } from "commander";
import fs from "fs";
import { resolveComponent, recordComponentState, getComponentRegistry } from "./components.js";
import { fmt } from "../../utils/formatter.js";

/**
 * `rafter agent enable <component-id>...` — install one or more specific components.
 * This is the fine-grained complement to `rafter agent init --with-<platform>`; it
 * targets a single (platform, kind) pair rather than a whole platform.
 *
 * Exit codes: 0 success · 1 invalid id or install failure · 2 platform not detected
 *             (unless --force is passed).
 */
export function createEnableCommand(): Command {
  return new Command("enable")
    .description("Install a specific agent component (e.g. claude-code.mcp, cursor.hooks)")
    .argument("<components...>", "Component IDs to install")
    .option("--force", "Install even if platform is not detected on this machine")
    .action((components: string[], opts) => {
      let exitCode = 0;
      const seenIds = new Set<string>();
      for (const raw of components) {
        if (seenIds.has(raw)) continue;
        seenIds.add(raw);

        const spec = resolveComponent(raw);
        if (!spec) {
          console.error(fmt.error(`Unknown component: ${raw}`));
          console.error(
            fmt.info(`Run 'rafter agent list' to see available components. Known IDs: ${
              getComponentRegistry().map((c) => c.id).join(", ")
            }`),
          );
          exitCode = 1;
          continue;
        }

        const detected = fs.existsSync(spec.detectDir);
        if (!detected && !opts.force) {
          console.error(
            fmt.warning(
              `${spec.id}: platform not detected (${spec.detectDir}). Re-run with --force to install anyway.`,
            ),
          );
          exitCode = exitCode || 2;
          continue;
        }

        try {
          spec.install();
          recordComponentState(spec.id, true);
          console.log(fmt.success(`Enabled ${spec.id} → ${spec.path}`));
        } catch (e) {
          console.error(fmt.error(`Failed to enable ${spec.id}: ${e}`));
          exitCode = 1;
        }
      }
      process.exit(exitCode);
    });
}
