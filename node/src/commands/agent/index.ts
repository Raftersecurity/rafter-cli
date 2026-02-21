import { Command } from "commander";
import { createAuditCommand } from "./audit.js";
import { createScanCommand } from "./scan.js";
import { createInitCommand } from "./init.js";
import { createConfigCommand } from "./config.js";
import { createExecCommand } from "./exec.js";
import { createAuditSkillCommand } from "./audit-skill.js";
import { createInstallHookCommand } from "./install-hook.js";
import { createVerifyCommand } from "./verify.js";

export function createAgentCommand(): Command {
  const agent = new Command("agent")
    .description("Agent security features");

  // Add subcommands
  agent.addCommand(createInitCommand());
  agent.addCommand(createScanCommand());
  agent.addCommand(createExecCommand());
  agent.addCommand(createConfigCommand());
  agent.addCommand(createAuditCommand());
  agent.addCommand(createAuditSkillCommand());
  agent.addCommand(createInstallHookCommand());
  agent.addCommand(createVerifyCommand());

  return agent;
}
