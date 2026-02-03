import { Command } from "commander";
import { createAuditCommand } from "./audit.js";
import { createScanCommand } from "./scan.js";

export function createAgentCommand(): Command {
  const agent = new Command("agent")
    .description("Agent security features");

  // Add subcommands
  agent.addCommand(createAuditCommand());
  agent.addCommand(createScanCommand());

  // Placeholder subcommands (to be implemented)
  // agent.addCommand(createInitCommand());
  // agent.addCommand(createConfigCommand());
  // agent.addCommand(createExecCommand());

  return agent;
}
