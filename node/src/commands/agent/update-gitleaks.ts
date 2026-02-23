import { Command } from "commander";
import { BinaryManager, GITLEAKS_VERSION } from "../../utils/binary-manager.js";
import { fmt } from "../../utils/formatter.js";

export function createUpdateGitleaksCommand(): Command {
  return new Command("update-gitleaks")
    .description("Update (or reinstall) the managed gitleaks binary")
    .option(
      "--version <version>",
      "Gitleaks version to install",
      GITLEAKS_VERSION,
    )
    .action(async (opts) => {
      const bm = new BinaryManager();

      if (!bm.isPlatformSupported()) {
        const { platform, arch } = bm.getPlatformInfo();
        console.error(fmt.error(`Gitleaks not available for ${platform}/${arch}`));
        process.exit(1);
      }

      // Show current version if installed
      if (bm.isGitleaksInstalled()) {
        const current = await bm.getGitleaksVersion();
        console.log(fmt.info(`Current: ${current}`));
      } else {
        console.log(fmt.info("Gitleaks not currently installed (managed binary)"));
      }

      console.log(fmt.info(`Installing gitleaks v${opts.version}...`));
      console.log();

      try {
        await bm.downloadGitleaks((msg) => console.log(`   ${msg}`), opts.version);
        console.log();
        const installed = await bm.getGitleaksVersion();
        console.log(fmt.success(`Gitleaks updated: ${installed}`));
        console.log(fmt.info(`  Binary: ${bm.getGitleaksPath()}`));
      } catch (e) {
        console.log();
        console.error(fmt.error(`Update failed: ${e}`));
        console.log(fmt.info(
          "To fix: install gitleaks manually (https://github.com/gitleaks/gitleaks/releases) " +
          "and ensure it is on PATH."
        ));
        process.exit(1);
      }
    });
}
