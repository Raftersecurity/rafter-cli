import { Command } from "commander";
import {
  listBundledSkills,
  snapshotSkills,
  SKILL_PLATFORMS,
  SkillPlatform,
} from "./registry.js";
import { fmt } from "../../utils/formatter.js";

/**
 * `rafter skill list` — show rafter-authored skills available in this CLI and
 * whether each is installed for each supported platform (claude-code, codex,
 * openclaw, cursor).
 *
 * Exit code: 0 on success.
 */
export function createListCommand(): Command {
  return new Command("list")
    .description("List rafter-authored skills and their install state per platform")
    .option("--json", "Output machine-readable JSON")
    .option("--installed", "Only show (skill, platform) pairs where the skill is installed")
    .option("--platform <platform>", "Limit to one platform")
    .action((opts) => {
      const bundled = listBundledSkills();
      let rows = snapshotSkills();

      const platformFilter = opts.platform as string | undefined;
      if (platformFilter) {
        if (!SKILL_PLATFORMS.includes(platformFilter as SkillPlatform)) {
          console.error(
            fmt.error(`Unknown platform: ${platformFilter}. Known: ${SKILL_PLATFORMS.join(", ")}`),
          );
          process.exit(1);
        }
        rows = rows.filter((r) => r.platform === platformFilter);
      }
      if (opts.installed) rows = rows.filter((r) => r.installed);

      if (opts.json) {
        const payload = {
          skills: bundled.map((s) => ({
            name: s.name,
            version: s.version,
            description: s.description,
          })),
          installations: rows.map((r) => ({
            name: r.name,
            platform: r.platform,
            path: r.path,
            detected: r.detected,
            installed: r.installed,
            version: r.version,
          })),
        };
        console.log(JSON.stringify(payload, null, 2));
        return;
      }

      console.log(fmt.header("Rafter-authored skills"));
      for (const s of bundled) {
        console.log(`  ${s.name.padEnd(24)} v${s.version}`);
      }
      console.log();

      console.log(fmt.header("Installations by platform"));
      const byPlatform = new Map<string, typeof rows>();
      for (const r of rows) {
        const arr = byPlatform.get(r.platform) ?? [];
        arr.push(r);
        byPlatform.set(r.platform, arr);
      }
      for (const [platform, list] of byPlatform) {
        const detected = list[0]?.detected ?? false;
        const suffix = detected ? "" : " (not detected)";
        console.log(`\n${platform}${suffix}`);
        for (const r of list) {
          const label = r.name.padEnd(24);
          if (r.installed) {
            const ver = r.version ? ` v${r.version}` : "";
            console.log(`  ${label} ● installed${ver}  (${r.path})`);
          } else {
            console.log(`  ${label} ○ not installed`);
          }
        }
      }
      console.log();
      console.log(
        fmt.info(
          "Use `rafter skill install <name>` / `rafter skill uninstall <name>` to toggle skills.",
        ),
      );
    });
}
