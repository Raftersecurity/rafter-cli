import { Command } from "commander";
import { createAuditCommand } from "./audit.js";

export function createAgentCommand(): Command {
  const agent = new Command("agent")
    .description("Agent security features");

  // Add subcommands
  agent.addCommand(createAuditCommand());

  // Placeholder subcommands (to be implemented)
  // agent.addCommand(createInitCommand());
  // agent.addCommand(createScanCommand());
  // agent.addCommand(createConfigCommand());
  // agent.addCommand(createExecCommand());

  return agent;
}
