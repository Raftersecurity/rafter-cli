#!/usr/bin/env node
import { Command } from "commander";
import * as dotenv from "dotenv";
import { guardSecurityEnvFromDotenv } from "./utils/env-guard.js";
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
import { createGatesCommand } from "./commands/gates.js";
import { createSitesCommand } from "./commands/sites/index.js";
import { createTelemetryCommand } from "./commands/telemetry.js";
import { installUsageCounters } from "./core/usage-counters.js";
import { checkForUpdate } from "./utils/update-checker.js";
import { setAgentMode } from "./utils/formatter.js";
import { createRequire } from "module";

// Commands call process.exit() right after writing results. When stdout is a
// pipe, Node writes asynchronously and exit drops whatever is still queued, so
// `rafter secrets --json . | jq` got only the first 64 KiB. Write synchronously.
// Only stdout: a blocking stderr stalls the process (including `mcp serve`)
// when a parent pipes stderr and never reads it.
(process.stdout as any)._handle?.setBlocking?.(true);

// A repo `.env` must not be able to set any RAFTER_* variable (key, token, disables).
guardSecurityEnvFromDotenv(() => dotenv.config());

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

// Sites — live-application security monitoring
program.addCommand(createSitesCommand());

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

// Gates — static map of security gates for an audit
program.addCommand(createGatesCommand());

// Shell completions
program.addCommand(createCompletionCommand());

// Local usage counters (nothing leaves the machine)
program.addCommand(createTelemetryCommand());

// Version subcommand (also available as --version)
program.addCommand(
  new Command("version")
    .description("Print version and exit")
    .action(() => {
      console.log(VERSION);
    })
);

/**
 * `-a`/`--agent` is declared only on the root `program`, so Commander rejects
 * it as an unknown option once it appears after a subcommand name
 * (`rafter secrets . -a`, `rafter scan local . -a`). The actual mode switch
 * already happens above via the `process.argv` scan, which is
 * position-independent — this just teaches every command in the tree to
 * accept the flag syntactically instead of erroring on it.
 *
 * Skipped on a command that declares its own `--agent <value>` option
 * (`agent audit`, `skill review` filter by agent type) and on every parent
 * of one: Commander lets a parent consume its options anywhere in argv, so a
 * boolean `--agent` on `skill` would swallow `skill review --agent codex` and
 * leave `codex` as a stray positional. `rafter -a agent audit ...` (the flag
 * before the subcommand) still works for those two.
 */
function declaresAgentOption(cmd: Command): boolean {
  return (
    cmd.options.some((o) => o.long === "--agent") ||
    cmd.commands.some(declaresAgentOption)
  );
}
function allowAgentFlagAtAnyDepth(cmd: Command): void {
  if (!declaresAgentOption(cmd)) {
    cmd.option("-a, --agent", "Plain output for AI agents (no colors/emoji)");
  }
  for (const sub of cmd.commands) {
    allowAgentFlagAtAnyDepth(sub);
  }
}
allowAgentFlagAtAnyDepth(program);

// Non-blocking update check — runs after command, prints to stderr
checkForUpdate(VERSION).then((notice) => {
  if (notice) process.stderr.write(notice);
});

installUsageCounters(program);

program.parse();
