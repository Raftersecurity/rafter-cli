import { Command } from "commander";
import { SkillScannerInstaller } from "../../scanners/skill-scanner.js";
import { fmt } from "../../utils/formatter.js";

export function createRemoveSkillScannerCommand(): Command {
  return new Command("remove-skill-scanner")
    .description(
      "Uninstall the optional skill-scanner deep engine (inverse of update-skill-scanner)",
    )
    .action(async () => {
      const result = await new SkillScannerInstaller().uninstall((msg) => console.log(`   ${msg}`));
      console.log();
      if (!result.ok) {
        console.error(fmt.error(`Uninstall failed: ${result.message}`));
        process.exit(1);
      }
      console.log(fmt.success(`skill-scanner removed: ${result.message}`));
    });
}
