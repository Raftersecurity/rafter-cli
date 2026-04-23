import { Command } from "commander";
import { createHookPretoolCommand } from "./pretool.js";
import { createHookPosttoolCommand } from "./posttool.js";
import { createHookSessionStartCommand } from "./session-start.js";

export function createHookCommand(): Command {
  const hook = new Command("hook")
    .description("Hook handlers for agent platform integration");

  hook.addCommand(createHookPretoolCommand());
  hook.addCommand(createHookPosttoolCommand());
  hook.addCommand(createHookSessionStartCommand());

  return hook;
}
