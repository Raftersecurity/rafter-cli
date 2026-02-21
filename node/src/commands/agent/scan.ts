import { Command } from "commander";
import { RegexScanner, ScanResult } from "../../scanners/regex-scanner.js";
import { GitleaksScanner } from "../../scanners/gitleaks.js";
import { ConfigManager } from "../../core/config-manager.js";
import { execSync, execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import { fmt } from "../../utils/formatter.js";

interface ScanOpts {
  quiet?: boolean;
  json?: boolean;
  format?: string;
  engine?: string;
  staged?: boolean;
  diff?: string;
}

export function createScanCommand(): Command {
  return new Command("scan")
    .description("Scan files or directories for secrets")
    .argument("[path]", "File or directory to scan", ".")
    .option("-q, --quiet", "Only output if secrets found")
    .option("--json", "Output as JSON")
    .option("--format <format>", "Output format: text, json, sarif", "text")
    .option("--staged", "Scan only git staged files")
    .option("--diff <ref>", "Scan files changed since a git ref")
    .option("--engine <engine>", "Scan engine: gitleaks or patterns", "auto")
    .action(async (scanPath, opts: ScanOpts) => {
      // Load policy-merged config for excludePaths/customPatterns
      const manager = new ConfigManager();
      const cfg = manager.loadWithPolicy();
      const scanCfg = cfg.agent?.scan;

      // Handle --diff flag
      if (opts.diff) {
        await scanDiffFiles(opts.diff, opts, scanCfg);
        return;
      }

      // Handle --staged flag
      if (opts.staged) {
        await scanStagedFiles(opts, scanCfg);
        return;
      }

      const resolvedPath = path.resolve(scanPath);

      // Check if path exists
      if (!fs.existsSync(resolvedPath)) {
        console.error(`Error: Path not found: ${resolvedPath}`);
        process.exit(2);
      }

      // Determine scan engine
      const engine = await selectEngine(opts.engine || "auto", opts.quiet || false);

      // Determine if path is file or directory
      const stats = fs.statSync(resolvedPath);
      let results;

      if (stats.isDirectory()) {
        if (!opts.quiet) {
          console.error(`Scanning directory: ${resolvedPath} (${engine})`);
        }
        results = await scanDirectory(resolvedPath, engine, scanCfg);
      } else {
        if (!opts.quiet) {
          console.error(`Scanning file: ${resolvedPath} (${engine})`);
        }
        results = await scanFile(resolvedPath, engine, scanCfg);
      }

      outputScanResults(results, opts);
    });
}

/**
 * Emit SARIF 2.1.0 JSON for GitHub/GitLab security tab integration
 */
function outputSarif(results: ScanResult[]): void {
  const rules = new Map<string, { id: string; name: string; shortDescription: string }>();
  const sarifResults: object[] = [];

  for (const r of results) {
    for (const m of r.matches) {
      const ruleId = m.pattern.name.toLowerCase().replace(/\s+/g, "-");
      if (!rules.has(ruleId)) {
        rules.set(ruleId, {
          id: ruleId,
          name: m.pattern.name,
          shortDescription: m.pattern.description || m.pattern.name,
        });
      }
      sarifResults.push({
        ruleId,
        level: m.pattern.severity === "critical" || m.pattern.severity === "high" ? "error" : "warning",
        message: { text: `${m.pattern.name} detected` },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: r.file.replace(/\\/g, "/"), uriBaseId: "%SRCROOT%" },
              region: m.line ? { startLine: m.line, startColumn: m.column ?? 1 } : undefined,
            },
          },
        ],
      });
    }
  }

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "rafter",
            informationUri: "https://rafter.so",
            rules: Array.from(rules.values()),
          },
        },
        results: sarifResults,
      },
    ],
  };

  console.log(JSON.stringify(sarif, null, 2));
  process.exit(results.length > 0 ? 1 : 0);
}

/**
 * Shared output logic for scan results
 */
function outputScanResults(
  results: ScanResult[],
  opts: ScanOpts,
  context?: string,
): void {
  const format = opts.format ?? (opts.json ? "json" : "text");

  if (format === "sarif") {
    outputSarif(results);
    return;
  }

  if (format === "json" || opts.json) {
    const out = results.map((r) => ({
      file: r.file,
      matches: r.matches.map((m) => ({
        pattern: { name: m.pattern.name, severity: m.pattern.severity, description: m.pattern.description || "" },
        line: m.line ?? null,
        column: m.column ?? null,
        redacted: m.redacted || "",
      })),
    }));
    console.log(JSON.stringify(out, null, 2));
    process.exit(results.length > 0 ? 1 : 0);
  }

  if (results.length === 0) {
    if (!opts.quiet) {
      const msg = context ? `No secrets detected in ${context}` : "No secrets detected";
      console.log(`\n${fmt.success(msg)}\n`);
    }
    process.exit(0);
  }

  console.log(`\n${fmt.warning(`Found secrets in ${results.length} file(s):`)}\n`);

  let totalMatches = 0;
  for (const result of results) {
    console.log(`\n${fmt.info(result.file)}`);

    for (const match of result.matches) {
      totalMatches++;
      const location = match.line ? `Line ${match.line}` : "Unknown location";
      const sev = fmt.severity(match.pattern.severity);

      console.log(`  ${sev} ${match.pattern.name}`);
      console.log(`     Location: ${location}`);
      console.log(`     Pattern: ${match.pattern.description || match.pattern.regex}`);
      console.log(`     Redacted: ${match.redacted}`);
      console.log();
    }
  }

  console.log(`\n${fmt.warning(`Total: ${totalMatches} secret(s) detected in ${results.length} file(s)`)}\n`);

  if (context === "staged files") {
    console.log(`${fmt.error("Commit blocked. Remove secrets before committing.")}\n`);
  } else {
    console.log(`Run 'rafter agent audit' to see the security log.\n`);
  }

  process.exit(1);
}

/**
 * Scan files changed since a git ref
 */
async function scanDiffFiles(
  ref: string,
  opts: ScanOpts,
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }> },
): Promise<void> {
  try {
    const diffOutput = execFileSync("git", ["diff", "--name-only", "--diff-filter=ACM", ref], {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();

    if (!diffOutput) {
      if (!opts.quiet) {
        console.log(fmt.success(`No files changed since ${ref}`));
      }
      process.exit(0);
    }

    const changedFiles = diffOutput.split("\n").map(f => f.trim()).filter(f => f);

    if (!opts.quiet) {
      console.error(`Scanning ${changedFiles.length} file(s) changed since ${ref}...`);
    }

    const engine = await selectEngine(opts.engine || "auto", opts.quiet || false);

    const allResults: ScanResult[] = [];
    for (const file of changedFiles) {
      const filePath = path.resolve(file);
      if (!fs.existsSync(filePath)) continue;
      const stats = fs.statSync(filePath);
      if (!stats.isFile()) continue;

      const results = await scanFile(filePath, engine, scanCfg);
      allResults.push(...results);
    }

    outputScanResults(allResults, opts, `files changed since ${ref}`);
  } catch (error: any) {
    if (error.status === 128) {
      console.error("Error: Not in a git repository or invalid ref");
      process.exit(2);
    }
    throw error;
  }
}

/**
 * Scan git staged files for secrets
 */
async function scanStagedFiles(
  opts: ScanOpts,
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }> },
): Promise<void> {
  try {
    const stagedFilesOutput = execSync("git diff --cached --name-only --diff-filter=ACM", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"]
    }).trim();

    if (!stagedFilesOutput) {
      if (!opts.quiet) {
        console.log(fmt.success("No files staged for commit"));
      }
      process.exit(0);
    }

    const stagedFiles = stagedFilesOutput.split("\n").map(f => f.trim()).filter(f => f);

    if (!opts.quiet) {
      console.error(`Scanning ${stagedFiles.length} staged file(s)...`);
    }

    const engine = await selectEngine(opts.engine || "auto", opts.quiet || false);

    const allResults: ScanResult[] = [];
    for (const file of stagedFiles) {
      const filePath = path.resolve(file);
      if (!fs.existsSync(filePath)) continue;
      const stats = fs.statSync(filePath);
      if (!stats.isFile()) continue;

      const results = await scanFile(filePath, engine, scanCfg);
      allResults.push(...results);
    }

    outputScanResults(allResults, opts, "staged files");
  } catch (error: any) {
    if (error.status === 128) {
      console.error("Error: Not in a git repository");
      process.exit(2);
    }
    throw error;
  }
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
        console.error(fmt.warning("Gitleaks requested but not available, using patterns"));
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
async function scanFile(
  filePath: string,
  engine: "gitleaks" | "patterns",
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }> },
): Promise<ScanResult[]> {
  if (engine === "gitleaks") {
    try {
      const gitleaks = new GitleaksScanner();
      const result = await gitleaks.scanFile(filePath);
      return result.matches.length > 0 ? [result] : [];
    } catch (e) {
      console.error(fmt.warning("Gitleaks scan failed, falling back to patterns"));
      const scanner = new RegexScanner(scanCfg?.customPatterns);
      const result = scanner.scanFile(filePath);
      return result.matches.length > 0 ? [result] : [];
    }
  } else {
    const scanner = new RegexScanner(scanCfg?.customPatterns);
    const result = scanner.scanFile(filePath);
    return result.matches.length > 0 ? [result] : [];
  }
}

/**
 * Scan a directory with selected engine
 */
async function scanDirectory(
  dirPath: string,
  engine: "gitleaks" | "patterns",
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }> },
): Promise<ScanResult[]> {
  if (engine === "gitleaks") {
    try {
      const gitleaks = new GitleaksScanner();
      return await gitleaks.scanDirectory(dirPath);
    } catch (e) {
      console.error(fmt.warning("Gitleaks scan failed, falling back to patterns"));
      const scanner = new RegexScanner(scanCfg?.customPatterns);
      return scanner.scanDirectory(dirPath, { excludePaths: scanCfg?.excludePaths });
    }
  } else {
    const scanner = new RegexScanner(scanCfg?.customPatterns);
    return scanner.scanDirectory(dirPath, { excludePaths: scanCfg?.excludePaths });
  }
}
