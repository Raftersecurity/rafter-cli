#!/usr/bin/env node
import { Command } from "commander";
import * as dotenv from "dotenv";
import { createRunCommand } from "./commands/backend/run.js";
import { createGetCommand } from "./commands/backend/get.js";
import { createUsageCommand } from "./commands/backend/usage.js";
import { createAgentCommand } from "./commands/agent/index.js";
import { checkForUpdate } from "./utils/update-checker.js";

dotenv.config();

const VERSION = "0.4.1";

const program = new Command()
  .name("rafter")
  .description("Rafter CLI")
  .version(VERSION);

// Backend commands (existing)
program.addCommand(createRunCommand());
program.addCommand(createGetCommand());
program.addCommand(createUsageCommand());

// Agent commands
program.addCommand(createAgentCommand());

// Non-blocking update check — runs after command, prints to stderr
checkForUpdate(VERSION).then((notice) => {
  if (notice) process.stderr.write(notice);
});

program.parse();
