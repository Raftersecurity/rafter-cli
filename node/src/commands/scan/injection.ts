/**
 * rafter scan injection — EXPERIMENTAL prompt-injection scan.
 *
 * Reads a file (or stdin with `-`) and reports possible prompt-injection
 * findings. Hidden from help until the parallel APPROVE bead (rf-i17)
 * closes. See docs/research/prompt-injection-detector.md.
 */

import { Command } from "commander";
import fs from "fs";
import {
  PromptInjectionDetector,
  InjectionScanResult,
} from "../../scanners/prompt-injection.js";
import type { InjectionSeverity } from "../../scanners/prompt-injection-patterns.js";

const SEVERITY_RANK: Record<InjectionSeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

export function createScanInjectionCommand(): Command {
  return new Command("injection")
    .description("(experimental) Scan a file or stdin for prompt-injection patterns")
    .argument("<path>", "file path, or - for stdin")
    .option("--min-severity <level>", "low | medium | high | critical", "low")
    .option("--fail-on <level>", "exit 1 when finding ≥ this severity", "medium")
    .option("--json", "output JSON (default human-readable)")
    .option("--quiet", "suppress non-essential output")
    .action((path: string, opts) => {
      const minSeverity = (opts.minSeverity || "low") as InjectionSeverity;
      const failOn = (opts.failOn || "medium") as InjectionSeverity;
      let text: string;
      try {
        text = path === "-"
          ? fs.readFileSync(0, "utf-8")
          : fs.readFileSync(path, "utf-8");
      } catch (err: any) {
        if (!opts.quiet) {
          process.stderr.write(`error reading ${path}: ${err.message}\n`);
        }
        process.exit(2);
      }

      const det = new PromptInjectionDetector();
      const result = det.scan(text, { minSeverity });

      if (opts.json) {
        process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      } else {
        printHuman(result, path);
      }

      const failRank = SEVERITY_RANK[failOn];
      const triggered = result.findings.some(f => SEVERITY_RANK[f.severity] >= failRank);
      process.exit(triggered ? 1 : 0);
    });
}

function printHuman(r: InjectionScanResult, path: string): void {
  if (r.findings.length === 0) {
    process.stdout.write(`✓ ${path}: clean (score 0)\n`);
    return;
  }
  process.stdout.write(`! ${path}: ${r.verdict} (score ${r.score})\n`);
  for (const f of r.findings) {
    process.stdout.write(
      `  [${f.severity.padEnd(8)}] ${f.pattern} @${f.offset}: ${f.evidence}\n`
    );
  }
}
