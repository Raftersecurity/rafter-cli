import { Command } from "commander";
import { createDocsListCommand } from "./list.js";
import { createDocsShowCommand } from "./show.js";

export function createDocsCommand(): Command {
  const docs = new Command("docs")
    .description("Repo-specific security docs declared in .rafter.yml")
    .addHelpText(
      "after",
      [
        "",
        "Examples:",
        "  $ rafter docs list",
        "  $ rafter docs list --tag owasp",
        "  $ rafter docs show secure-coding",
        "  $ rafter docs show secure-coding --refresh",
      ].join("\n"),
    );

  docs.addCommand(createDocsListCommand());
  docs.addCommand(createDocsShowCommand());

  return docs;
}
