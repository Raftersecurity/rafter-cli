import { Command } from "commander";
import { createCiInitCommand } from "./init.js";

export function createCiCommand(): Command {
  const ci = new Command("ci")
    .description("CI/CD integration commands");

  ci.addCommand(createCiInitCommand());

  return ci;
}
