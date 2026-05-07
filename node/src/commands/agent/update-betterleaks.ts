import { Command } from "commander";
import { BinaryManager, BETTERLEAKS_VERSION } from "../../utils/binary-manager.js";
import { fmt } from "../../utils/formatter.js";

export function createUpdateBetterleaksCommand(): Command {
  return new Command("update-betterleaks")
    .alias("update-gitleaks")
    .description("Update (or reinstall) the managed betterleaks binary")
    .option(
      "--version <version>",
      "Betterleaks version to install",
      BETTERLEAKS_VERSION,
    )
    .action(async (opts) => {
      const bm = new BinaryManager();

      if (!bm.isPlatformSupported()) {
        const { platform, arch } = bm.getPlatformInfo();
        console.error(fmt.error(`Betterleaks not available for ${platform}/${arch}`));
        process.exit(1);
      }

      if (bm.isBetterleaksInstalled()) {
        const current = await bm.getBetterleaksVersion();
        console.log(fmt.info(`Current: ${current}`));
      } else {
        console.log(fmt.info("Betterleaks not currently installed (managed binary)"));
      }

      console.log(fmt.info(`Installing betterleaks v${opts.version}...`));
      console.log();

      try {
        await bm.downloadBetterleaks((msg) => console.log(`   ${msg}`), opts.version);
        console.log();
        const installed = await bm.getBetterleaksVersion();
        console.log(fmt.success(`Betterleaks updated: ${installed}`));
        console.log(fmt.info(`  Binary: ${bm.getBetterleaksPath()}`));
      } catch (e) {
        console.log();
        console.error(fmt.error(`Update failed: ${e}`));
        console.log(fmt.info(
          "To fix: install betterleaks manually (https://github.com/betterleaks/betterleaks/releases) " +
          "and ensure it is on PATH."
        ));
        process.exit(1);
      }
    });
}
