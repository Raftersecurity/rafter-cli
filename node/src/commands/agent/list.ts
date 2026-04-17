import { Command } from "commander";
import { snapshotComponents } from "./components.js";
import { fmt } from "../../utils/formatter.js";

/**
 * `rafter agent list` — machine-readable inventory of everything rafter has touched
 * (or could touch) on this machine. One row per (platform, component).
 *
 * Exit codes: 0 on success.
 */
export function createListCommand(): Command {
  return new Command("list")
    .description("List agent integration components and their state")
    .option("--json", "Output machine-readable JSON")
    .option("--installed", "Only show components that are currently installed")
    .option("--detected", "Only show components whose platform is detected")
    .action((opts) => {
      let rows = snapshotComponents();
      if (opts.installed) rows = rows.filter((r) => r.installed);
      if (opts.detected) rows = rows.filter((r) => r.detected);

      if (opts.json) {
        const payload = {
          components: rows.map((r) => ({
            id: r.id,
            platform: r.platform,
            kind: r.kind,
            description: r.description,
            path: r.path,
            state: r.state,
            installed: r.installed,
            detected: r.detected,
            configEnabled: r.configEnabled,
          })),
        };
        console.log(JSON.stringify(payload, null, 2));
        return;
      }

      const byPlatform = new Map<string, typeof rows>();
      for (const r of rows) {
        const arr = byPlatform.get(r.platform) ?? [];
        arr.push(r);
        byPlatform.set(r.platform, arr);
      }

      console.log(fmt.header("Rafter agent components"));
      console.log(fmt.divider());
      for (const [platform, list] of byPlatform) {
        const detected = list[0]?.detected ?? false;
        const suffix = detected ? "" : " (not detected)";
        console.log(`\n${platform}${suffix}`);
        for (const r of list) {
          const label = r.id.padEnd(28);
          let marker: string;
          switch (r.state) {
            case "installed":
              marker = "● installed";
              break;
            case "not-installed":
              marker = "○ not installed";
              break;
            case "not-detected":
            default:
              marker = "· platform not detected";
              break;
          }
          console.log(`  ${label} ${marker}`);
        }
      }
      console.log();
      console.log(
        fmt.info("Use `rafter agent enable <id>` or `rafter agent disable <id>` to toggle individual components."),
      );
    });
}
