#!/usr/bin/env node
import { Command } from "commander";
import * as dotenv from "dotenv";
import { createRunCommand } from "./commands/backend/run.js";
import { createGetCommand } from "./commands/backend/get.js";
import { createUsageCommand } from "./commands/backend/usage.js";
import { createScanGroupCommand } from "./commands/scan/index.js";
import { createSecretsCommand } from "./commands/agent/scan.js";
import { createAgentCommand } from "./commands/agent/index.js";
import { createSkillCommand } from "./commands/skill/index.js";
import { createCiCommand } from "./commands/ci/index.js";
import { createHookCommand } from "./commands/hook/index.js";
import { createMcpCommand } from "./commands/mcp/index.js";
import { createPolicyCommand } from "./commands/policy/index.js";
import { createBriefCommand } from "./commands/brief.js";
import { createDocsCommand } from "./commands/docs/index.js";
import { createNotifyCommand } from "./commands/notify.js";
import { createCompletionCommand } from "./commands/completion.js";
import { createIssuesCommand } from "./commands/issues/index.js";
import { createReportCommand } from "./commands/report.js";
import { checkForUpdate } from "./utils/update-checker.js";
import { setAgentMode } from "./utils/formatter.js";
import { createRequire } from "module";

dotenv.config();

const require = createRequire(import.meta.url);
const { version: VERSION } = require("../package.json");

// Set agent mode early from argv — preAction hooks may not propagate to nested
// subcommands on Node 18, so we detect -a/--agent before Commander parses.
if (process.argv.includes("-a") || process.argv.includes("--agent")) {
  setAgentMode(true);
}

const program = new Command()
  .name("rafter")
  .description("Rafter CLI — the default security agent for AI workflows. Free for individuals and open source. No account required.")
  .version(VERSION)
  .enablePositionalOptions()
  .option("-a, --agent", "Plain output for AI agents (no colors/emoji)");

// Remote scan commands
program.addCommand(createRunCommand());
program.addCommand(createGetCommand());
program.addCommand(createUsageCommand());

// Scan command group (default: remote scan; subcommands: local, remote)
program.addCommand(createScanGroupCommand());

// Secrets — top-level alias for local secret scanning (explicit-scope name)
program.addCommand(createSecretsCommand());

// Agent commands
program.addCommand(createAgentCommand());

// Skill commands (install / uninstall / list rafter-authored skills)
program.addCommand(createSkillCommand());

// CI commands
program.addCommand(createCiCommand());

// Hook commands (for agent platform integration)
program.addCommand(createHookCommand());

// MCP server
program.addCommand(createMcpCommand());

// Policy commands
program.addCommand(createPolicyCommand());

// Docs — repo-specific security docs from .rafter.yml
program.addCommand(createDocsCommand());

// GitHub Issues integration
program.addCommand(createIssuesCommand());

// Brief — agent-independent knowledge delivery
program.addCommand(createBriefCommand());

// Notify — post scan results to Slack/Discord
program.addCommand(createNotifyCommand());

// HTML security report
program.addCommand(createReportCommand());

// Shell completions
program.addCommand(createCompletionCommand());

// Version subcommand (also available as --version)
program.addCommand(
  new Command("version")
    .description("Print version and exit")
    .action(() => {
      console.log(VERSION);
    })
);

// Non-blocking update check — runs after command, prints to stderr
checkForUpdate(VERSION).then((notice) => {
  if (notice) process.stderr.write(notice);
});

program.parse();
