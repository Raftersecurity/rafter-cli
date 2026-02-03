import { Command } from "commander";
import { RegexScanner } from "../../scanners/regex-scanner.js";
import fs from "fs";
import path from "path";

export function createScanCommand(): Command {
  return new Command("scan")
    .description("Scan files or directories for secrets")
    .argument("[path]", "File or directory to scan", ".")
    .option("-q, --quiet", "Only output if secrets found")
    .option("--json", "Output as JSON")
    .action(async (scanPath, opts) => {
      const scanner = new RegexScanner();
      const resolvedPath = path.resolve(scanPath);

      // Check if path exists
      if (!fs.existsSync(resolvedPath)) {
        console.error(`Error: Path not found: ${resolvedPath}`);
        process.exit(1);
      }

      // Determine if path is file or directory
      const stats = fs.statSync(resolvedPath);
      let results;

      if (stats.isDirectory()) {
        if (!opts.quiet) {
          console.error(`Scanning directory: ${resolvedPath}`);
        }
        results = scanner.scanDirectory(resolvedPath);
      } else {
        if (!opts.quiet) {
          console.error(`Scanning file: ${resolvedPath}`);
        }
        const result = scanner.scanFile(resolvedPath);
        results = result.matches.length > 0 ? [result] : [];
      }

      // Output results
      if (opts.json) {
        console.log(JSON.stringify(results, null, 2));
      } else {
        if (results.length === 0) {
          if (!opts.quiet) {
            console.log("\n✓ No secrets detected\n");
          }
          process.exit(0);
        } else {
          console.log(`\n⚠️  Found secrets in ${results.length} file(s):\n`);

          let totalMatches = 0;
          for (const result of results) {
            console.log(`\n📄 ${result.file}`);

            for (const match of result.matches) {
              totalMatches++;
              const location = match.line ? `Line ${match.line}` : "Unknown location";
              const severity = getSeverityEmoji(match.pattern.severity);

              console.log(`  ${severity} [${match.pattern.severity.toUpperCase()}] ${match.pattern.name}`);
              console.log(`     Location: ${location}`);
              console.log(`     Pattern: ${match.pattern.description || match.pattern.regex}`);
              console.log(`     Redacted: ${match.redacted}`);
              console.log();
            }
          }

          console.log(`\n⚠️  Total: ${totalMatches} secret(s) detected in ${results.length} file(s)\n`);
          console.log("Run 'rafter agent audit' to see the security log.\n");

          process.exit(1);
        }
      }
    });
}

function getSeverityEmoji(severity: string): string {
  const emojiMap: Record<string, string> = {
    critical: "🔴",
    high: "🟠",
    medium: "🟡",
    low: "🟢"
  };
  return emojiMap[severity] || "⚪";
}
