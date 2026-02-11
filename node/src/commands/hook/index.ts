import { Command } from "commander";
import { createHookPretoolCommand } from "./pretool.js";

export function createHookCommand(): Command {
  const hook = new Command("hook")
    .description("Hook handlers for agent platform integration");

  hook.addCommand(createHookPretoolCommand());

  return hook;
}
