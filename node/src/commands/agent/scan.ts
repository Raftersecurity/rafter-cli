import { Command } from "commander";
import { RegexScanner } from "../../scanners/regex-scanner.js";
import { GitleaksScanner } from "../../scanners/gitleaks.js";
import { BinaryManager } from "../../utils/binary-manager.js";
import fs from "fs";
import path from "path";

export function createScanCommand(): Command {
  return new Command("scan")
    .description("Scan files or directories for secrets")
    .argument("[path]", "File or directory to scan", ".")
    .option("-q, --quiet", "Only output if secrets found")
    .option("--json", "Output as JSON")
    .option("--engine <engine>", "Scan engine: gitleaks or patterns", "auto")
    .action(async (scanPath, opts) => {
      const resolvedPath = path.resolve(scanPath);

      // Check if path exists
      if (!fs.existsSync(resolvedPath)) {
        console.error(`Error: Path not found: ${resolvedPath}`);
        process.exit(1);
      }

      // Determine scan engine
      const engine = await selectEngine(opts.engine, opts.quiet);

      // Determine if path is file or directory
      const stats = fs.statSync(resolvedPath);
      let results;

      if (stats.isDirectory()) {
        if (!opts.quiet) {
          console.error(`Scanning directory: ${resolvedPath} (${engine})`);
        }
        results = await scanDirectory(resolvedPath, engine);
      } else {
        if (!opts.quiet) {
          console.error(`Scanning file: ${resolvedPath} (${engine})`);
        }
        results = await scanFile(resolvedPath, engine);
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

/**
 * Select scan engine based on availability and user preference
 */
async function selectEngine(preference: string, quiet: boolean): Promise<"gitleaks" | "patterns"> {
  if (preference === "patterns") {
    return "patterns";
  }

  if (preference === "gitleaks") {
    const gitleaks = new GitleaksScanner();
    const available = await gitleaks.isAvailable();
    if (!available) {
      if (!quiet) {
        console.error("⚠️  Gitleaks requested but not available, using patterns");
      }
      return "patterns";
    }
    return "gitleaks";
  }

  // Auto mode: try Gitleaks, fall back to patterns
  const gitleaks = new GitleaksScanner();
  const available = await gitleaks.isAvailable();

  return available ? "gitleaks" : "patterns";
}

/**
 * Scan a file with selected engine
 */
async function scanFile(filePath: string, engine: "gitleaks" | "patterns") {
  if (engine === "gitleaks") {
    try {
      const gitleaks = new GitleaksScanner();
      const result = await gitleaks.scanFile(filePath);
      return result.matches.length > 0 ? [result] : [];
    } catch (e) {
      // Fall back to patterns on error
      console.error(`⚠️  Gitleaks scan failed, falling back to patterns`);
      const scanner = new RegexScanner();
      const result = scanner.scanFile(filePath);
      return result.matches.length > 0 ? [result] : [];
    }
  } else {
    const scanner = new RegexScanner();
    const result = scanner.scanFile(filePath);
    return result.matches.length > 0 ? [result] : [];
  }
}

/**
 * Scan a directory with selected engine
 */
async function scanDirectory(dirPath: string, engine: "gitleaks" | "patterns") {
  if (engine === "gitleaks") {
    try {
      const gitleaks = new GitleaksScanner();
      return await gitleaks.scanDirectory(dirPath);
    } catch (e) {
      // Fall back to patterns on error
      console.error(`⚠️  Gitleaks scan failed, falling back to patterns`);
      const scanner = new RegexScanner();
      return scanner.scanDirectory(dirPath);
    }
  } else {
    const scanner = new RegexScanner();
    return scanner.scanDirectory(dirPath);
  }
}
