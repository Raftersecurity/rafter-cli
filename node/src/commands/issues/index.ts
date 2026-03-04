/**
 * rafter issues — GitHub Issues integration.
 *
 * Subcommands:
 *   rafter issues create --from-scan <id>     Create issues from backend scan results
 *   rafter issues create --from-local <path>   Create issues from local scan JSON
 *   rafter issues create --from-text           Create issue from natural text (stdin/file/inline)
 */
import { Command } from "commander";
import { createFromScanCommand } from "./from-scan.js";
import { createFromTextCommand } from "./from-text.js";

export function createIssuesCommand(): Command {
  const issuesGroup = new Command("issues")
    .description("GitHub Issues integration — create issues from scan results or text");

  const createGroup = new Command("create")
    .description("Create GitHub issues from scan findings or natural text");

  createGroup.addCommand(createFromScanCommand());
  createGroup.addCommand(createFromTextCommand());

  // Default action for `rafter issues create` with no subcommand — show help
  createGroup.action(() => {
    createGroup.help();
  });

  issuesGroup.addCommand(createGroup);

  return issuesGroup;
}
