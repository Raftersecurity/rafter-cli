import { Command } from "commander";
import { resolveComponent, recordComponentState, getComponentRegistry } from "./components.js";
import { fmt } from "../../utils/formatter.js";

/**
 * `rafter agent disable <component-id>...` — uninstall one or more specific components.
 * For hook/MCP entries, removes rafter's entries from the shared config file. For skills
 * and our own instruction files, deletes them. Other (non-rafter) entries are preserved.
 *
 * Exit codes: 0 success · 1 invalid id or uninstall failure.
 */
export function createDisableCommand(): Command {
  return new Command("disable")
    .description("Uninstall a specific agent component (e.g. claude-code.mcp, cursor.hooks)")
    .argument("<components...>", "Component IDs to uninstall")
    .action((components: string[]) => {
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

        try {
          const wasInstalled = spec.isInstalled();
          spec.uninstall();
          recordComponentState(spec.id, false);
          if (wasInstalled) {
            console.log(fmt.success(`Disabled ${spec.id} (removed from ${spec.path})`));
          } else {
            console.log(fmt.info(`${spec.id} was not installed — no changes`));
          }
        } catch (e) {
          console.error(fmt.error(`Failed to disable ${spec.id}: ${e}`));
          exitCode = 1;
        }
      }
      process.exit(exitCode);
    });
}
