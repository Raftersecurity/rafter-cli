import { Command } from "commander";
import fs from "fs";
import {
  resolveSkill,
  listBundledSkills,
  skillDestPath,
  skillDetectDir,
  resolveExplicitDest,
  writeSkillTo,
  recordSkillState,
  SKILL_PLATFORMS,
  SkillPlatform,
} from "./registry.js";
import { fmt } from "../../utils/formatter.js";

/**
 * `rafter skill install <name>` — install a rafter-authored skill to one or
 * more platforms (or an explicit --to path).
 *
 * Exit codes:
 *   0 — installed successfully (or already installed — copy is idempotent)
 *   1 — unknown skill, unknown platform, or install failure
 *   2 — no detected platform found and --force was not passed
 */
export function createInstallCommand(): Command {
  return new Command("install")
    .description("Install a rafter-authored skill to detected platform(s) or an explicit path")
    .argument("<name>", "Skill name (e.g. rafter, rafter-secure-design)")
    .option(
      "--platform <platform...>",
      `Target platform(s). One or more of: ${SKILL_PLATFORMS.join(", ")}. Default: all detected.`,
    )
    .option(
      "--to <path>",
      "Explicit destination. If it ends in .md/.mdc, used as-is; otherwise treated as a skills-base directory.",
    )
    .option("--force", "Install even if no target platform is detected")
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

      // --to overrides platform-based resolution.
      if (opts.to) {
        const destPath = resolveExplicitDest(opts.to as string, skill.name);
        try {
          writeSkillTo(skill, destPath);
          console.log(fmt.success(`Installed ${skill.name} v${skill.version} → ${destPath}`));
          process.exit(0);
        } catch (e) {
          console.error(fmt.error(`Failed to install ${skill.name} to ${destPath}: ${e}`));
          process.exit(1);
        }
      }

      // Resolve target platforms: either explicit --platform list, or "all detected".
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
        targets = SKILL_PLATFORMS.filter((p) => fs.existsSync(skillDetectDir(p)));
        if (targets.length === 0) {
          if (!opts.force) {
            console.error(
              fmt.warning(
                `No supported platform detected. Re-run with --platform <name> or --force to install to all known platforms.`,
              ),
            );
            process.exit(2);
          }
          targets = [...SKILL_PLATFORMS];
        }
      }

      let exitCode = 0;
      for (const platform of targets) {
        const detected = fs.existsSync(skillDetectDir(platform));
        if (!detected && !opts.force && !(Array.isArray(opts.platform) && opts.platform.length > 0)) {
          // Shouldn't hit this — we pre-filtered to detected — but defensive.
          continue;
        }
        if (!detected && !opts.force && Array.isArray(opts.platform) && opts.platform.length > 0) {
          console.error(
            fmt.warning(
              `${platform}: not detected (${skillDetectDir(platform)}). Re-run with --force to install anyway.`,
            ),
          );
          exitCode = exitCode || 2;
          continue;
        }
        const destPath = skillDestPath(platform, skill.name);
        try {
          writeSkillTo(skill, destPath);
          recordSkillState(platform, skill.name, true, skill.version);
          console.log(
            fmt.success(`Installed ${skill.name} v${skill.version} → ${destPath} (${platform})`),
          );
        } catch (e) {
          console.error(fmt.error(`Failed to install ${skill.name} for ${platform}: ${e}`));
          exitCode = 1;
        }
      }
      process.exit(exitCode);
    });
}
