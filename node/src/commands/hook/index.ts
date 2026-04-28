import { Command } from "commander";
import { createHookPretoolCommand } from "./pretool.js";
import { createHookPosttoolCommand } from "./posttool.js";
import { createHookUserPromptSubmitCommand } from "./user-prompt-submit.js";
import { createHookBeforeModelCommand } from "./before-model.js";
import { createHookGatewayDispatchCommand } from "./gateway-dispatch.js";

export function createHookCommand(): Command {
  const hook = new Command("hook")
    .description("Hook handlers for agent platform integration");

  hook.addCommand(createHookPretoolCommand());
  hook.addCommand(createHookPosttoolCommand());
  hook.addCommand(createHookUserPromptSubmitCommand());
  hook.addCommand(createHookBeforeModelCommand());
  hook.addCommand(createHookGatewayDispatchCommand());

  return hook;
}
