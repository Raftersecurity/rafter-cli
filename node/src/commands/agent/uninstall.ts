import { Command } from "commander";
import fs from "fs";
import path from "path";
import os from "os";
import { createInterface } from "readline";
import {
  getComponentRegistry,
  recordComponentState,
  resetComponentRegistryCache,
  type ComponentSpec,
} from "./components.js";
import { fmt } from "../../utils/formatter.js";

/**
 * `rafter agent uninstall` — bulk revert of a prior `rafter agent init`.
 *
 * Walks every registered ComponentSpec and calls its `.uninstall()` callback,
 * which removes only the entries rafter added (other tools' hook/MCP entries
 * are preserved). Optionally also removes ~/.rafter/{config.json,bin,patterns}
 * under --purge. The audit log is kept by default so a user can still inspect
 * what rafter did before they ran uninstall.
 *
 * Idempotent: each ComponentSpec.uninstall() is a no-op when the component is
 * not installed, so running uninstall twice writes nothing the second time.
 *
 * Exit codes: 0 success · 1 one or more component uninstalls failed.
 */
export function createUninstallCommand(): Command {
  return new Command("uninstall")
    .description("Remove all rafter agent integrations installed by 'rafter agent init'")
    .option("--dry-run", "Preview what would be removed without changing anything")
    .option("-y, --yes", "Skip the confirmation prompt")
    .option(
      "--purge",
      "Also delete ~/.rafter (config, bin, patterns). Audit log is removed too.",
    )
    .option(
      "--local",
      "Operate against ./.rafter and ./.* platform dirs (matches 'agent init --local')",
    )
    .action(async (opts: { dryRun?: boolean; yes?: boolean; purge?: boolean; local?: boolean }) => {
      // --local re-roots HOME at cwd so every component's os.homedir()-based
      // path resolves into the project. Mirrors init's --local semantics
      // without forking the per-component path logic.
      if (opts.local) {
        process.env.HOME = process.cwd();
        resetComponentRegistryCache();
      }

      const home = os.homedir();
      const rafterDir = path.join(home, ".rafter");
      const registry = getComponentRegistry();

      const installed: ComponentSpec[] = registry.filter((c) => {
        try {
          return c.isInstalled();
        } catch {
          return false;
        }
      });

      const purgeTargets: string[] = [];
      if (opts.purge) {
        for (const sub of ["config.json", "audit.jsonl", "bin", "patterns"]) {
          const p = path.join(rafterDir, sub);
          if (fs.existsSync(p)) purgeTargets.push(p);
        }
      }

      if (installed.length === 0 && purgeTargets.length === 0) {
        console.log(fmt.info("Nothing to uninstall — no rafter agent components are installed."));
        process.exit(0);
      }

      if (opts.dryRun) {
        console.log(fmt.info("DRY RUN — no files will be modified."));
        console.log(fmt.divider());
        if (installed.length > 0) {
          console.log("Components to remove:");
          for (const c of installed) {
            console.log(`  REMOVE  ${c.id.padEnd(28)} ${c.path}`);
          }
        }
        if (purgeTargets.length > 0) {
          console.log("Purge targets:");
          for (const p of purgeTargets) console.log(`  DELETE  ${p}`);
        }
        if (!opts.purge) {
          console.log(fmt.info(
            "User data preserved: ~/.rafter/audit.jsonl, ~/.rafter/config.json, .rafter.yml (pass --purge to remove)",
          ));
        }
        console.log(fmt.info("Re-run without --dry-run to apply."));
        process.exit(0);
      }

      if (!opts.yes) {
        const summary = `Uninstall ${installed.length} component${installed.length === 1 ? "" : "s"}` +
          (opts.purge ? ` and purge ${rafterDir}` : "") + "?";
        const ok = await askYesNo(summary, false);
        if (!ok) {
          console.log(fmt.info("Aborted."));
          process.exit(0);
        }
      }

      let exitCode = 0;
      for (const spec of installed) {
        try {
          spec.uninstall();
          recordComponentState(spec.id, false);
          console.log(fmt.success(`Removed ${spec.id} (${spec.path})`));
        } catch (e) {
          console.error(fmt.error(`Failed to remove ${spec.id}: ${e}`));
          exitCode = 1;
        }
      }

      if (opts.purge) {
        for (const target of purgeTargets) {
          try {
            fs.rmSync(target, { recursive: true, force: true });
            console.log(fmt.success(`Purged ${target}`));
          } catch (e) {
            console.error(fmt.error(`Failed to purge ${target}: ${e}`));
            exitCode = 1;
          }
        }
        // Drop the now-empty ~/.rafter shell if nothing else remains.
        try {
          if (fs.existsSync(rafterDir) && fs.readdirSync(rafterDir).length === 0) {
            fs.rmdirSync(rafterDir);
          }
        } catch {
          /* leave it — purge is best-effort on the wrapping dir */
        }
      } else {
        console.log(fmt.info(
          "Preserved: ~/.rafter/audit.jsonl, ~/.rafter/config.json, .rafter.yml. " +
          "Re-run with --purge to delete them too.",
        ));
      }

      process.exit(exitCode);
    });
}

function askYesNo(question: string, defaultYes: boolean): Promise<boolean> {
  // Non-TTY (CI, piped stdin) gets the default — never blocks a script.
  if (!process.stdin.isTTY) return Promise.resolve(defaultYes);
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const suffix = defaultYes ? "[Y/n]" : "[y/N]";
  return new Promise((resolve) => {
    rl.question(`  ${question} ${suffix} `, (answer) => {
      rl.close();
      const t = answer.trim().toLowerCase();
      if (t === "") resolve(defaultYes);
      else resolve(t === "y" || t === "yes");
    });
  });
}
