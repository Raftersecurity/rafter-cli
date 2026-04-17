import { Command } from "commander";
import fs from "fs";
import {
  resolveSkill,
  listBundledSkills,
  skillDestPath,
  deleteSkillAt,
  recordSkillState,
  SKILL_PLATFORMS,
  SkillPlatform,
} from "./registry.js";
import { fmt } from "../../utils/formatter.js";

/**
 * `rafter skill uninstall <name>` — remove a rafter-authored skill from one or
 * more platforms. Missing files are reported, not errored.
 *
 * Exit codes:
 *   0 — uninstall succeeded (or skill was already absent)
 *   1 — unknown skill or unknown platform
 */
export function createUninstallCommand(): Command {
  return new Command("uninstall")
    .description("Uninstall a rafter-authored skill from one or more platforms")
    .argument("<name>", "Skill name (e.g. rafter, rafter-secure-design)")
    .option(
      "--platform <platform...>",
      `Target platform(s). One or more of: ${SKILL_PLATFORMS.join(", ")}. Default: all installed.`,
    )
    .action((name: string, opts) => {
      const skill = resolveSkill(name);
      if (!skill) {
        console.error(fmt.error(`Unknown skill: ${name}`));
        console.error(
          fmt.info(
            `Available: ${listBundledSkills().map((s) => s.name).join(", ") || "(none)"}`,
          ),
        );
        process.exit(1);
      }

      let targets: SkillPlatform[];
      if (Array.isArray(opts.platform) && opts.platform.length > 0) {
        targets = [];
        for (const raw of opts.platform as string[]) {
          const p = raw.trim() as SkillPlatform;
          if (!SKILL_PLATFORMS.includes(p)) {
            console.error(
              fmt.error(`Unknown platform: ${raw}. Known: ${SKILL_PLATFORMS.join(", ")}`),
            );
            process.exit(1);
          }
          targets.push(p);
        }
      } else {
        // Default: remove from every platform where the file currently exists.
        targets = SKILL_PLATFORMS.filter((p) => fs.existsSync(skillDestPath(p, skill.name)));
        if (targets.length === 0) {
          console.log(fmt.info(`${skill.name} is not installed on any known platform — no changes`));
          process.exit(0);
        }
      }

      let exitCode = 0;
      for (const platform of targets) {
        const destPath = skillDestPath(platform, skill.name);
        try {
          const existed = deleteSkillAt(destPath);
          recordSkillState(platform, skill.name, false, null);
          if (existed) {
            console.log(fmt.success(`Uninstalled ${skill.name} from ${platform} (${destPath})`));
          } else {
            console.log(fmt.info(`${skill.name} was not installed on ${platform} — no changes`));
          }
        } catch (e) {
          console.error(fmt.error(`Failed to uninstall ${skill.name} from ${platform}: ${e}`));
          exitCode = 1;
        }
      }
      process.exit(exitCode);
    });
}
