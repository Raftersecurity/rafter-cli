import { Command } from "commander";
import { createListCommand } from "./list.js";
import { createInstallCommand } from "./install.js";
import { createUninstallCommand } from "./uninstall.js";

export function createSkillCommand(): Command {
  const skill = new Command("skill")
    .description("Manage rafter-authored skills (list / install / uninstall)");

  skill.addCommand(createListCommand());
  skill.addCommand(createInstallCommand());
  skill.addCommand(createUninstallCommand());

  return skill;
}
