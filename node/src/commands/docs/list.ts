import { Command } from "commander";
import { listDocs } from "../../core/docs-loader.js";

export function createDocsListCommand(): Command {
  return new Command("list")
    .description("List security docs declared in .rafter.yml")
    .option("--tag <tag>", "Filter to docs matching this tag")
    .option("--json", "Output as JSON")
    .action((opts) => {
      const entries = listDocs().filter(d =>
        !opts.tag || (Array.isArray(d.tags) && d.tags.includes(opts.tag))
      );

      if (entries.length === 0) {
        if (opts.json) {
          process.stdout.write("[]\n");
        } else {
          process.stderr.write("No docs configured in .rafter.yml\n");
        }
        process.exit(3);
      }

      if (opts.json) {
        process.stdout.write(JSON.stringify(entries.map(e => ({
          id: e.id,
          source: e.source,
          source_kind: e.sourceKind,
          description: e.description || "",
          tags: e.tags || [],
          cache_status: e.cacheStatus,
        })), null, 2) + "\n");
        return;
      }

      for (const e of entries) {
        const tags = (e.tags && e.tags.length) ? ` [${e.tags.join(", ")}]` : "";
        const cache = e.sourceKind === "url" ? ` (${e.cacheStatus})` : "";
        const desc = e.description ? ` — ${e.description}` : "";
        process.stdout.write(`${e.id}  ${e.source}${cache}${tags}${desc}\n`);
      }
    });
}
