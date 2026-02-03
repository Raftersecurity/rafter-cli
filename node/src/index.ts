#!/usr/bin/env node
import { Command } from "commander";
import * as dotenv from "dotenv";
import { createRunCommand } from "./commands/backend/run.js";
import { createGetCommand } from "./commands/backend/get.js";
import { createUsageCommand } from "./commands/backend/usage.js";

dotenv.config();

const program = new Command()
  .name("rafter")
  .description("Rafter CLI")
  .version("0.3.0");

// Backend commands (existing)
program.addCommand(createRunCommand());
program.addCommand(createGetCommand());
program.addCommand(createUsageCommand());

// Agent commands (placeholder for future implementation)
// program.addCommand(createAgentCommand());

program.parse();
