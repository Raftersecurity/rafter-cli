import { Command } from "commander";
import { RegexScanner, ScanResult } from "../../scanners/regex-scanner.js";
import { BetterleaksScanner } from "../../scanners/betterleaks.js";
import { ConfigManager } from "../../core/config-manager.js";
import { AuditLogger } from "../../core/audit-logger.js";
import {
  Suppression,
  SuppressedFinding,
  applySuppressions,
  loadSuppressions,
  policyIgnoreToSuppressions,
} from "../../core/custom-patterns.js";
import type { ScanIgnoreRule } from "../../core/config-schema.js";
import { execSync, execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { fmt } from "../../utils/formatter.js";
import { createRequire } from "module";
import { minimatch } from "minimatch";

const _require = createRequire(import.meta.url);
const { version: CLI_VERSION } = _require("../../../package.json");

interface ScanOpts {
  quiet?: boolean;
  json?: boolean;
  format?: string;
  engine?: string;
  staged?: boolean;
  diff?: string;
  baseline?: boolean;
  watch?: boolean;
  history?: boolean;
  /** Commander maps `--no-gitignore` to `gitignore: false` (default true). */
  gitignore?: boolean;
}

interface BaselineEntry {
  file: string;
  line: number | null;
  pattern: string;
}

function loadBaselineEntries(): BaselineEntry[] {
  const baselinePath = path.join(os.homedir(), ".rafter", "baseline.json");
  if (!fs.existsSync(baselinePath)) return [];
  try {
    const data = JSON.parse(fs.readFileSync(baselinePath, "utf-8"));
    return (data.entries as BaselineEntry[]) || [];
  } catch {
    return [];
  }
}

/**
 * Does `relPath` (forward-slash relative path) match an `exclude_paths`
 * entry from `.rafter.yml`?
 *
 * sable-yz0 — single source of truth for `scan.exclude_paths` semantics
 * across both scan engines and the staged / diff modes. Rules (any one
 * matches → exclude):
 *
 *   1. Exact match: `relPath === pattern` (the pattern is the full file path)
 *   2. Directory-prefix: `relPath` starts with `pattern + "/"` (the pattern
 *      is a directory; everything under it is excluded). Trailing "/" on
 *      the pattern is ignored — `scripts/` and `scripts` mean the same.
 *   3. Dir-name anywhere: any segment of `relPath` equals `pattern` (preserves
 *      the historical RegexScanner walker behavior — `node_modules` skips
 *      `pkg/foo/node_modules/...` too).
 *   4. Glob: if `pattern` contains `* ? [`, run it through minimatch with
 *      `dot:true, matchBase:true`. Same defaults as `policyIgnoreToSuppressions`.
 */
function pathMatchesExcludePattern(relPath: string, pattern: string): boolean {
  const rel = relPath.replace(/\\/g, "/");
  const p = pattern.replace(/\\/g, "/").replace(/\/+$/, "");
  if (!p) return false;
  if (rel === p) return true;
  if (rel.startsWith(p + "/")) return true;
  if (rel.split("/").includes(p)) return true;
  if (/[*?[]/.test(p)) {
    if (minimatch(rel, p, { dot: true, matchBase: true })) return true;
    // Auto-anchor relative globs so `foo/**` matches anywhere in the tree.
    if (!p.startsWith("/") && !p.startsWith("**")) {
      if (minimatch(rel, "**/" + p, { dot: true })) return true;
    }
  }
  return false;
}

/**
 * Strip findings whose file path matches any `scan.exclude_paths` entry.
 * Called at the `scanDirectory` chokepoint so both the betterleaks and
 * patterns engines get the same filter (and the same semantics).
 *
 * `scanRoot` is the absolute directory the scan was rooted at; finding
 * paths are converted to scan-root-relative before matching, so users
 * write `components/common/Mermaid.tsx` in their `.rafter.yml`, not the
 * absolute path on the CI runner.
 */
function applyExcludePaths(
  results: ScanResult[],
  excludePaths: string[] | undefined,
  scanRoot: string,
): ScanResult[] {
  if (!excludePaths || excludePaths.length === 0) return results;
  const root = path.resolve(scanRoot).replace(/\\/g, "/");
  return results.filter((r) => {
    const abs = path.resolve(r.file).replace(/\\/g, "/");
    let rel = abs;
    if (abs === root) {
      rel = "";
    } else if (abs.startsWith(root + "/")) {
      rel = abs.slice(root.length + 1);
    }
    return !excludePaths.some((pat) => pathMatchesExcludePattern(rel, pat));
  });
}

function applyBaseline(results: ScanResult[], entries: BaselineEntry[]): ScanResult[] {
  if (entries.length === 0) return results;
  return results
    .map((r) => ({
      ...r,
      matches: r.matches.filter(
        (m) =>
          !entries.some(
            (e) =>
              e.file === r.file &&
              e.pattern === m.pattern.name &&
              (e.line == null || e.line === (m.line ?? null)),
          ),
      ),
    }))
    .filter((r) => r.matches.length > 0);
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
    .option("--engine <engine>", "Scan engine: betterleaks or patterns", "auto")
    .option("--baseline", "Filter findings present in the saved baseline")
    .option("--watch", "Watch for file changes and re-scan on change")
    .option("--history", "Scan git history for secrets (requires betterleaks engine)")
    .option("--no-gitignore", "Scan files even if .gitignore would exclude them (default: respect .gitignore)")
    .action(async (scanPath, opts: ScanOpts) => {
      // Validate flags before doing any work.
      const validEngines = ["auto", "betterleaks", "patterns"];
      const engineValue = opts.engine || "auto";
      if (!validEngines.includes(engineValue)) {
        console.error(`Invalid engine: ${engineValue}. Valid values: ${validEngines.join(", ")}`);
        process.exit(2);
      }

      const format = opts.format ?? (opts.json ? "json" : "text");
      const validFormats = ["text", "json", "sarif"];
      if (!validFormats.includes(format)) {
        console.error(`Invalid format: ${format}. Valid values: ${validFormats.join(", ")}`);
        process.exit(2);
      }

      // Deprecation notice — only when invoked as `rafter agent scan`, not as `rafter scan local`
      const argv = process.argv;
      const isAgentScan = argv.includes("agent") && argv.includes("scan") &&
        argv.indexOf("agent") < argv.indexOf("scan");
      if (isAgentScan) {
        process.stderr.write(
          "Warning: rafter agent scan is deprecated and will be removed in a future major version. Use rafter secrets instead.\n"
        );
      }
      // Load policy-merged config for excludePaths/customPatterns/ignore
      const manager = new ConfigManager();
      const cfg = manager.loadWithPolicy();
      const scanCfg = cfg.agent?.scan;
      const suppressions = collectSuppressions(scanCfg?.ignore);

      const baselineEntries = opts.baseline ? loadBaselineEntries() : [];

      // Handle --diff flag
      if (opts.diff) {
        await scanDiffFiles(opts.diff, opts, scanCfg, baselineEntries, path.resolve(scanPath), suppressions);
        return;
      }

      // Handle --staged flag
      if (opts.staged) {
        await scanStagedFiles(opts, scanCfg, baselineEntries, path.resolve(scanPath), suppressions);
        return;
      }

      const resolvedPath = path.resolve(scanPath);

      // Check if path exists
      if (!fs.existsSync(resolvedPath)) {
        console.error(`Error: Path not found: ${resolvedPath}`);
        process.exit(2);
      }

      // Handle --watch flag
      if (opts.watch) {
        await watchAndScan(resolvedPath, opts, scanCfg, suppressions);
        return;
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
        results = await scanDirectory(resolvedPath, engine, scanCfg, opts.history, opts.gitignore);
      } else {
        if (!opts.quiet) {
          console.error(`Scanning file: ${resolvedPath} (${engine})`);
        }
        results = await scanFile(resolvedPath, engine, scanCfg);
      }

      outputScanResults(applyBaseline(results, baselineEntries), opts, undefined, true, suppressions);
    });
}

/**
 * `rafter secrets` — top-level alias for the secret scanner. Same engine
 * and flags as `rafter scan local`; the name makes the scope (secrets only,
 * not full code analysis) explicit to agents and humans.
 */
export function createSecretsCommand(): Command {
  const cmd = createScanCommand();
  cmd.name("secrets");
  cmd.description(
    "Scan files/directories for hardcoded secrets (regex + betterleaks). Secrets only — not a code analysis. For full SAST/SCA, use 'rafter run'.",
  );
  return cmd;
}

/**
 * Combine .rafterignore + policy ignore rules into a single Suppression list.
 * Order matters — first match wins, and policy rules are checked first so an
 * explicit reason wins over a bare .rafterignore line covering the same finding.
 */
function collectSuppressions(policyIgnore?: ScanIgnoreRule[]): Suppression[] {
  return [...policyIgnoreToSuppressions(policyIgnore), ...loadSuppressions()];
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
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "rafter",
            version: CLI_VERSION,
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
  exitOnFindings: boolean = true,
  suppressions: Suppression[] = [],
): void {
  const format = opts.format ?? (opts.json ? "json" : "text");

  if (!["text", "json", "sarif"].includes(format)) {
    console.error(`Invalid format: ${format}. Valid values: text, json, sarif`);
    process.exit(2);
  }

  // Split suppressed findings off the main result list. Both engines feed
  // through here, so policy-driven suppression applies regardless of source.
  const { results: keptResults, suppressed } = applySuppressions(results, suppressions);

  if (format === "sarif") {
    outputSarif(keptResults);
    return;
  }

  if (format === "json" || opts.json) {
    const filesOut = keptResults.map((r) => ({
      file: r.file,
      matches: r.matches.map((m) => ({
        pattern: { name: m.pattern.name, severity: m.pattern.severity, description: m.pattern.description || "" },
        line: m.line ?? null,
        column: m.column ?? null,
        redacted: m.redacted || "",
      })),
    }));
    const out: { _note: string; scan_mode: string; triage_applied: boolean; results: typeof filesOut; _suppressed?: SuppressedFinding[] } = {
      _note:
        "Local-only scan: pattern-based detection without agentic-intelligence triage. " +
        "Findings have not been evaluated for context (public exposure, key validity, " +
        "deployment environment). Investigate each before acting; do not dismiss. " +
        "Run 'rafter run' for backend agentic analysis.",
      scan_mode: "local",
      triage_applied: false,
      results: filesOut,
    };
    if (suppressed.length > 0) {
      out._suppressed = suppressed;
    }
    console.log(JSON.stringify(out, null, 2));
    if (exitOnFindings) process.exit(keptResults.length > 0 ? 1 : 0);
    return;
  }

  // Text output — note suppression on stderr so stdout remains parseable.
  if (suppressed.length > 0 && !opts.quiet) {
    console.error(fmt.info(`(${suppressed.length} finding(s) hidden by .rafter.yml)`));
  }

  if (keptResults.length === 0) {
    if (!opts.quiet) {
      const msg = context ? `No secrets detected in ${context}` : "No secrets detected";
      console.log(`\n${fmt.success(msg)}\n`);
    }
    if (exitOnFindings) process.exit(0);
    return;
  }

  console.log(`\n${fmt.warning(`Found secrets in ${keptResults.length} file(s):`)}\n`);

  let totalMatches = 0;
  for (const result of keptResults) {
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

  console.log(`\n${fmt.warning(`Total: ${totalMatches} secret(s) detected in ${keptResults.length} file(s)`)}\n`);

  if (context === "staged files") {
    console.log(`${fmt.error("Commit blocked. Remove secrets before committing.")}\n`);
  } else if (exitOnFindings) {
    console.log(`Run 'rafter agent audit' to see the security log.\n`);
  }

  if (exitOnFindings) process.exit(1);
}

/**
 * Scan files changed since a git ref
 */
async function scanDiffFiles(
  ref: string,
  opts: ScanOpts,
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }>; ignore?: ScanIgnoreRule[] },
  baselineEntries: BaselineEntry[] = [],
  scanPath?: string,
  suppressions: Suppression[] = [],
): Promise<void> {
  const cwd = scanPath && fs.existsSync(scanPath) && fs.statSync(scanPath).isDirectory() ? scanPath : undefined;
  try {
    const diffOutput = execFileSync("git", ["diff", "--name-only", "--diff-filter=ACM", ref], {
      encoding: "utf-8",
      cwd,
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();

    if (!diffOutput) {
      outputScanResults([], opts, `files changed since ${ref}`, true, suppressions);
      return;
    }

    const changedFiles = diffOutput.split("\n").map(f => f.trim()).filter(f => f);

    if (!opts.quiet) {
      console.error(`Scanning ${changedFiles.length} file(s) changed since ${ref}...`);
    }

    const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      encoding: "utf-8",
      cwd,
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();

    const engine = await selectEngine(opts.engine || "auto", opts.quiet || false);

    const allResults: ScanResult[] = [];
    for (const file of changedFiles) {
      const filePath = path.resolve(repoRoot, file);
      if (!fs.existsSync(filePath)) continue;
      const stats = fs.statSync(filePath);
      if (!stats.isFile()) continue;

      const results = await scanFile(filePath, engine, scanCfg);
      allResults.push(...results);
    }

    // sable-yz0 — honor scan.exclude_paths in --diff mode too (was previously
    // dropped). Use the repo root as scanRoot so user-relative paths in
    // .rafter.yml resolve consistently with the directory-scan behavior.
    const filteredDiff = applyExcludePaths(allResults, scanCfg?.excludePaths, repoRoot);
    outputScanResults(applyBaseline(filteredDiff, baselineEntries), opts, `files changed since ${ref}`, true, suppressions);
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
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }>; ignore?: ScanIgnoreRule[] },
  baselineEntries: BaselineEntry[] = [],
  scanPath?: string,
  suppressions: Suppression[] = [],
): Promise<void> {
  const cwd = scanPath && fs.existsSync(scanPath) && fs.statSync(scanPath).isDirectory() ? scanPath : undefined;
  try {
    const stagedFilesOutput = execFileSync("git", ["diff", "--cached", "--name-only", "--diff-filter=ACM"], {
      encoding: "utf-8",
      cwd,
      stdio: ["pipe", "pipe", "ignore"]
    }).trim();

    if (!stagedFilesOutput) {
      outputScanResults([], opts, "staged files", true, suppressions);
      return;
    }

    const stagedFiles = stagedFilesOutput.split("\n").map(f => f.trim()).filter(f => f);

    if (!opts.quiet) {
      console.error(`Scanning ${stagedFiles.length} staged file(s)...`);
    }

    const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      encoding: "utf-8",
      cwd,
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();

    const engine = await selectEngine(opts.engine || "auto", opts.quiet || false);

    const allResults: ScanResult[] = [];
    for (const file of stagedFiles) {
      const filePath = path.resolve(repoRoot, file);
      if (!fs.existsSync(filePath)) continue;
      const stats = fs.statSync(filePath);
      if (!stats.isFile()) continue;

      const results = await scanFile(filePath, engine, scanCfg);
      allResults.push(...results);
    }

    // sable-yz0 — honor scan.exclude_paths in --staged mode too.
    const filteredStaged = applyExcludePaths(allResults, scanCfg?.excludePaths, repoRoot);
    outputScanResults(applyBaseline(filteredStaged, baselineEntries), opts, "staged files", true, suppressions);
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
async function selectEngine(preference: string, quiet: boolean): Promise<"betterleaks" | "patterns"> {
  if (preference === "patterns") {
    return "patterns";
  }

  if (preference === "betterleaks") {
    const bl = new BetterleaksScanner();
    const available = await bl.isAvailable();
    if (!available) {
      if (!quiet) {
        console.error(fmt.warning("Betterleaks requested but not available, using patterns"));
      }
      return "patterns";
    }
    return "betterleaks";
  }

  if (preference !== "auto") {
    console.error(`Invalid engine: ${preference}. Valid values: auto, betterleaks, patterns`);
    process.exit(2);
  }

  // Auto mode: try Betterleaks, fall back to patterns
  const bl = new BetterleaksScanner();
  const available = await bl.isAvailable();

  return available ? "betterleaks" : "patterns";
}

/**
 * Scan a file with selected engine
 */
async function scanFile(
  filePath: string,
  engine: "betterleaks" | "patterns",
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }> },
): Promise<ScanResult[]> {
  if (engine === "betterleaks") {
    try {
      const bl = new BetterleaksScanner();
      const result = await bl.scanFile(filePath);
      return result.matches.length > 0 ? [result] : [];
    } catch (e) {
      console.error(fmt.warning("Betterleaks scan failed, falling back to patterns"));
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
  engine: "betterleaks" | "patterns",
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }> },
  history?: boolean,
  respectGitignore?: boolean,
): Promise<ScanResult[]> {
  // respectGitignore default is true. The patterns engine honors it via
  // RegexScanner.scanDirectory; betterleaks honors it natively (gitleaks
  // ancestry — reads .gitignore unless --no-git is set).
  let results: ScanResult[];
  if (engine === "betterleaks") {
    try {
      const bl = new BetterleaksScanner();
      results = await bl.scanDirectory(dirPath, { useGit: history ?? false });
    } catch (e) {
      console.error(fmt.warning("Betterleaks scan failed, falling back to patterns"));
      const scanner = new RegexScanner(scanCfg?.customPatterns);
      results = scanner.scanDirectory(dirPath, {
        excludePaths: scanCfg?.excludePaths,
        respectGitignore,
      });
    }
  } else {
    const scanner = new RegexScanner(scanCfg?.customPatterns);
    results = scanner.scanDirectory(dirPath, {
      excludePaths: scanCfg?.excludePaths,
      respectGitignore,
    });
  }
  // sable-yz0 — post-filter by `.rafter.yml scan.exclude_paths`. Two bugs
  // motivated this chokepoint:
  //   1. The betterleaks happy-path above never received excludePaths,
  //      so `auto`-engine scans (the default when betterleaks is on disk)
  //      silently ignored user policy.
  //   2. The patterns engine's walker only matches `excludePaths` entries
  //      against single directory NAMES (`entry.name`), so a customer
  //      writing `components/common/Mermaid.tsx` (file path) or
  //      `supabase/migrations/foo.sql` (multi-segment path) got no
  //      filtering at all.
  // The post-filter applies the same path-aware semantics to BOTH engines
  // (exact path, directory-prefix, dir-name-anywhere, glob via minimatch),
  // catching whatever leaks through the walker-level optimization.
  return applyExcludePaths(results, scanCfg?.excludePaths, dirPath);
}

/**
 * Watch a path for changes and re-scan on each change
 */
async function watchAndScan(
  watchPath: string,
  opts: ScanOpts,
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }>; ignore?: ScanIgnoreRule[] },
  suppressions: Suppression[] = [],
): Promise<void> {
  const { watch } = await import("chokidar");
  const logger = new AuditLogger();

  const engine = await selectEngine(opts.engine || "auto", opts.quiet || false);

  if (!opts.quiet) {
    console.error(fmt.info(`Watching ${watchPath} for changes (${engine}). Press Ctrl+C to exit.`));
  }

  // Do an initial scan
  const stats = fs.statSync(watchPath);
  const initialResults = stats.isDirectory()
    ? await scanDirectory(watchPath, engine, scanCfg)
    : await scanFile(watchPath, engine, scanCfg);

  if (initialResults.length > 0) {
    console.log(fmt.warning(`\n[Initial scan] Found secrets:`));
    outputScanResults(initialResults, { ...opts, quiet: false }, undefined, /* exitOnFindings= */ false, suppressions);
    logWatchFindings(logger, initialResults);
  } else if (!opts.quiet) {
    console.log(fmt.success(`[Initial scan] No secrets detected`));
  }

  const watcher = watch(watchPath, {
    ignoreInitial: true,
    persistent: true,
    ignored: [/(^|[/\\])\./, /node_modules/, /\.git/],
    depth: 10,
  });

  watcher.on("change", async (filePath: string) => {
    const timestamp = new Date().toLocaleTimeString();
    if (!opts.quiet) {
      console.error(`\n[${timestamp}] Changed: ${filePath}`);
    }

    if (!fs.existsSync(filePath)) return;
    const fileStats = fs.statSync(filePath);
    if (!fileStats.isFile()) return;

    const results = await scanFile(filePath, engine, scanCfg);
    if (results.length > 0) {
      outputScanResults(results, { ...opts, quiet: false }, undefined, /* exitOnFindings= */ false, suppressions);
      logWatchFindings(logger, results);
    } else if (!opts.quiet) {
      console.log(fmt.success(`  No secrets detected`));
    }
  });

  watcher.on("add", async (filePath: string) => {
    const timestamp = new Date().toLocaleTimeString();
    if (!opts.quiet) {
      console.error(`\n[${timestamp}] Added: ${filePath}`);
    }

    const fileStats = fs.statSync(filePath);
    if (!fileStats.isFile()) return;

    const results = await scanFile(filePath, engine, scanCfg);
    if (results.length > 0) {
      outputScanResults(results, { ...opts, quiet: false }, undefined, /* exitOnFindings= */ false, suppressions);
      logWatchFindings(logger, results);
    } else if (!opts.quiet) {
      console.log(fmt.success(`  No secrets detected`));
    }
  });

  // Keep process alive until Ctrl+C
  await new Promise<void>((resolve) => {
    process.on("SIGINT", () => {
      if (!opts.quiet) {
        console.log(fmt.info("\nWatch mode stopped."));
      }
      watcher.close();
      resolve();
    });
  });
}

/**
 * Log watch findings to audit log
 */
function logWatchFindings(logger: AuditLogger, results: ScanResult[]): void {
  for (const result of results) {
    for (const match of result.matches) {
      logger.log({
        eventType: "secret_detected",
        securityCheck: {
          passed: false,
          reason: `${match.pattern.name} detected in ${result.file}`,
          details: {
            file: result.file,
            line: match.line,
            pattern: match.pattern.name,
            severity: match.pattern.severity,
            watchMode: true,
          },
        },
        resolution: {
          actionTaken: "allowed",
        },
      });
    }
  }
}
