#!/usr/bin/env node
import { Command } from "commander";
import * as dotenv from "dotenv";
import { createRunCommand } from "./commands/backend/run.js";
import { createGetCommand } from "./commands/backend/get.js";
import { createUsageCommand } from "./commands/backend/usage.js";
import { createAgentCommand } from "./commands/agent/index.js";
import { createCiCommand } from "./commands/ci/index.js";
import { createHookCommand } from "./commands/hook/index.js";
import { createMcpCommand } from "./commands/mcp/index.js";
import { createPolicyCommand } from "./commands/policy/index.js";
import { createCompletionCommand } from "./commands/completion.js";
import { checkForUpdate } from "./utils/update-checker.js";
import { setAgentMode } from "./utils/formatter.js";

dotenv.config();

const VERSION = "0.5.3";

const program = new Command()
  .name("rafter")
  .description("Rafter CLI")
  .version(VERSION)
  .option("-a, --agent", "Plain output for AI agents (no colors/emoji)");

// Set agent mode before any subcommand runs
program.hook("preAction", (thisCommand) => {
  const opts = thisCommand.opts();
  if (opts.agent) {
    setAgentMode(true);
  }
});

// Backend commands (existing)
program.addCommand(createRunCommand());
program.addCommand(createGetCommand());
program.addCommand(createUsageCommand());

// Agent commands
program.addCommand(createAgentCommand());

// CI commands
program.addCommand(createCiCommand());

// Hook commands (for agent platform integration)
program.addCommand(createHookCommand());

// MCP server
program.addCommand(createMcpCommand());

// Policy commands
program.addCommand(createPolicyCommand());

// Shell completions
program.addCommand(createCompletionCommand());

// Non-blocking update check — runs after command, prints to stderr
checkForUpdate(VERSION).then((notice) => {
  if (notice) process.stderr.write(notice);
});

program.parse();
