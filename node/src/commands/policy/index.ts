import { Command } from "commander";
import { createPolicyExportCommand } from "./export.js";

export function createPolicyCommand(): Command {
  const policy = new Command("policy")
    .description("Security policy management");

  policy.addCommand(createPolicyExportCommand());

  return policy;
}
