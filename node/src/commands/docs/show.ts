import { Command } from "commander";
import { resolveDocSelector, fetchDoc } from "../../core/docs-loader.js";

export function createDocsShowCommand(): Command {
  return new Command("show")
    .description("Print the content of a doc by id or tag")
    .argument("<id-or-tag>", "Doc id or tag selector")
    .option("--refresh", "Force re-fetch for URL-backed docs (bypass cache)")
    .option("--json", "Output as JSON (array of { id, source, content })")
    .action(async (selector: string, opts) => {
      const entries = resolveDocSelector(selector);
      if (entries.length === 0) {
        const { loadPolicy } = await import("../../core/policy-loader.js");
        const policy = loadPolicy();
        if (!policy || !policy.docs || policy.docs.length === 0) {
          process.stderr.write("No docs configured in .rafter.yml\n");
          process.exit(3);
        }
        process.stderr.write(`No doc matched id or tag: ${selector}\n`);
        process.exit(2);
      }

      const results: Array<{ id: string; source: string; source_kind: string; stale: boolean; content: string }> = [];
      let anyError = false;

      for (const entry of entries) {
        try {
          const fetched = await fetchDoc(entry, { refresh: opts.refresh });
          results.push({
            id: entry.id,
            source: fetched.source,
            source_kind: fetched.sourceKind,
            stale: fetched.stale,
            content: fetched.content,
          });
          if (fetched.stale) {
            process.stderr.write(`Warning: ${entry.id} served from stale cache (fetch failed)\n`);
          }
        } catch (err: any) {
          anyError = true;
          process.stderr.write(`Error: failed to fetch ${entry.id}: ${err.message || err}\n`);
        }
      }

      if (results.length === 0) {
        process.exit(1);
      }

      if (opts.json) {
        process.stdout.write(JSON.stringify(results, null, 2) + "\n");
      } else if (results.length === 1) {
        process.stdout.write(results[0].content);
        if (!results[0].content.endsWith("\n")) process.stdout.write("\n");
      } else {
        for (const r of results) {
          process.stdout.write(`\n===== ${r.id} (${r.source}) =====\n`);
          process.stdout.write(r.content);
          if (!r.content.endsWith("\n")) process.stdout.write("\n");
        }
      }

      if (anyError) process.exit(1);
    });
}
