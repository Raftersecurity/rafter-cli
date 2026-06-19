import { Command } from "commander";
import { execSync } from "child_process";
import {
  SkillScannerInstaller,
  SKILL_SCANNER_VERSION,
} from "../../scanners/skill-scanner.js";
import { fmt } from "../../utils/formatter.js";

export function createUpdateSkillScannerCommand(): Command {
  return new Command("update-skill-scanner")
    .description(
      "Install or update the optional skill-scanner deep engine (audit-skill --deep)",
    )
    .option("--version <version>", "skill-scanner version to install", SKILL_SCANNER_VERSION)
    .action(async (opts: { version: string }) => {
      const checkCmd =
        process.platform === "win32" ? "where skill-scanner" : "which skill-scanner";
      let existing: string | null = null;
      try {
        existing = execSync(checkCmd, { timeout: 5000, encoding: "utf-8" }).trim().split("\n")[0].trim() || null;
      } catch {
        existing = null;
      }
      if (existing) {
        console.log(fmt.info(`Current skill-scanner: ${existing}`));
      } else {
        console.log(fmt.info("skill-scanner not currently on PATH"));
      }

      console.log(fmt.warning(
        "skill-scanner is a heavy third-party package (pulls litellm, fastapi, " +
        "yara-x, …). Installing it in an isolated environment.",
      ));
      console.log(fmt.info(`Installing skill-scanner v${opts.version}...`));
      console.log();

      const result = await new SkillScannerInstaller().install(
        opts.version,
        (msg) => console.log(`   ${msg}`),
      );
      console.log();
      if (!result.ok) {
        console.error(fmt.error(`Install failed: ${result.message}`));
        console.log(fmt.info(
          "To fix: install manually with `uv tool install cisco-ai-skill-scanner` " +
          "(or `pip install --user cisco-ai-skill-scanner`) and ensure " +
          "`skill-scanner` is on PATH.",
        ));
        process.exit(1);
      }
      console.log(fmt.success(`skill-scanner installed (via ${result.via}): ${result.message}`));
      console.log(fmt.info("Run `rafter agent audit-skill <path> --deep` to use it."));
    });
}
