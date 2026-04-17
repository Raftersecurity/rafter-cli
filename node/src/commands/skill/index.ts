import { Command } from "commander";
import { createListCommand } from "./list.js";
import { createInstallCommand } from "./install.js";
import { createUninstallCommand } from "./uninstall.js";
import { createReviewCommand } from "./review.js";

export function createSkillCommand(): Command {
  const skill = new Command("skill")
    .description("Manage rafter-authored skills (list / install / uninstall / review)");

  skill.addCommand(createListCommand());
  skill.addCommand(createInstallCommand());
  skill.addCommand(createUninstallCommand());
  skill.addCommand(createReviewCommand());

  return skill;
}
