/**
 * rafter sites — live-application security monitoring ("Sites").
 *
 * Subcommands:
 *   rafter sites create <url>              Register a site, kick off its first scan
 *   rafter sites scan <projectId-or-url>   Trigger a re-scan of an existing site
 *   rafter sites list                       List registered sites
 *   rafter sites get <id>                   Get a site's status + latest run + findings summary
 */
import { Command } from "commander";
import { createSitesCreateCommand } from "./create.js";
import { createSitesScanCommand } from "./scan.js";
import { createSitesListCommand } from "./list.js";
import { createSitesGetCommand } from "./get.js";

export function createSitesCommand(): Command {
  const sitesGroup = new Command("sites")
    .description("Manage Rafter Sites — live-application security monitoring");

  sitesGroup.addCommand(createSitesCreateCommand());
  sitesGroup.addCommand(createSitesScanCommand());
  sitesGroup.addCommand(createSitesListCommand());
  sitesGroup.addCommand(createSitesGetCommand());

  // Default action for `rafter sites` with no subcommand — show help.
  sitesGroup.action(() => {
    sitesGroup.help();
  });

  return sitesGroup;
}
