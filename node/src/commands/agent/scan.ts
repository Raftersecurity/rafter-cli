import { Command } from "commander";
import { RegexScanner, ScanResult } from "../../scanners/regex-scanner.js";
import { scanAddedDiffLines } from "../../scanners/git-diff-scan.js";
import { gitRepoRoot, scanGitHistory } from "../../scanners/git-history-scan.js";
import { parseUnifiedDiffAddedLines, gitDiffMaxBuffer } from "../../utils/git-diff.js";
import { BetterleaksScanner } from "../../scanners/betterleaks.js";
import { unionScanResults } from "../../scanners/union.js";
import { BinaryManager, BETTERLEAKS_VERSION } from "../../utils/binary-manager.js";
import { askYesNo } from "../../utils/prompt.js";
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
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { fmt } from "../../utils/formatter.js";
import { createRequire } from "module";
import { minimatch } from "minimatch";
import { countScan } from "../../core/usage-counters.js";

const _require = createRequire(import.meta.url);
const { version: CLI_VERSION } = _require("../../../package.json");

interface ScanOpts {
  quiet?: boolean;
  json?: boolean;
  format?: string;
  engine?: string;
  staged?: boolean;
  diff?: string;
  range?: string;
  baseline?: boolean;
  watch?: boolean;
  history?: boolean;
  /** Commander maps `--no-gitignore` to `gitignore: false` (default true). */
  gitignore?: boolean;
  /**
   * Commander maps `--no-auto-update` to `autoUpdate: false` (default true).
   * sable-o4k — opt out of auto-updating a stale managed betterleaks binary.
   */
  autoUpdate?: boolean;
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
export function applyExcludePaths(
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
    // Keep a read-error entry even with no matches (sable-ilbx), so an
    // unreadable file survives a baseline filter.
    .filter((r) => r.matches.length > 0 || r.readError);
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
    .option("--range <range>", "Scan only files changed in a git commit range, e.g. main..HEAD")
    .option("--engine <engine>", "Scan engine: betterleaks or patterns", "auto")
    .option("--baseline", "Filter findings present in the saved baseline")
    .option("--watch", "Watch for file changes and re-scan on change")
    .option("--history", "Scan every commit on every ref instead of the working tree")
    .option("--no-gitignore", "Scan files even if .gitignore would exclude them (default: respect .gitignore)")
    .option("--no-auto-update", "Do not auto-update a stale managed betterleaks binary; fall back to the patterns engine instead")
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
      // Load policy-merged config for excludePaths/customPatterns/ignore.
      // Discover and anchor the policy from the scan TARGET, not the process
      // cwd (sable-lu0j), so an ambient `.rafter.yml` in cwd cannot suppress
      // real secrets in a scan of a different tree. For `--staged`/`--diff` the
      // default target is "." (cwd), which is the repo the command runs in.
      const scanBase = path.resolve(scanPath);
      const rafterignoreDir =
        fs.existsSync(scanBase) && fs.statSync(scanBase).isDirectory()
          ? scanBase
          : path.dirname(scanBase);
      const manager = new ConfigManager();
      const cfg = manager.loadWithPolicy(scanBase);
      const scanCfg = cfg.agent?.scan;
      const suppressions = collectSuppressions(scanCfg?.ignore, scanCfg?.ignoreBaseDir, rafterignoreDir);

      const baselineEntries = opts.baseline ? loadBaselineEntries() : [];

      // Handle --diff flag
      if (opts.diff) {
        await scanDiffFiles(opts.diff, opts, scanCfg, baselineEntries, path.resolve(scanPath), suppressions);
        return;
      }

      // Handle --range flag (a commit range a..b; reuses the diff plumbing so a
      // user can scope the scan to the changed files on a huge repo).
      if (opts.range) {
        await scanRangeFiles(opts.range, opts, scanCfg, baselineEntries, path.resolve(scanPath), suppressions);
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
      const requestedEngine = opts.engine || "auto";
      const scanStart = Date.now();
      const selected = await selectEngine(requestedEngine, opts.quiet || false, autoUpdateEnabled(opts, scanCfg));
      const engine = selected.engine;
      // Threaded through the scan so a scan-time fall-back (e.g. a betterleaks
      // timeout) updates it before the output reports the engine actually used.
      const report = buildEngineReport(requestedEngine, engine, selected.reason);

      // Determine if path is file or directory
      const stats = fs.statSync(resolvedPath);
      let results;

      if (stats.isDirectory()) {
        if (!opts.quiet) {
          console.error(`Scanning directory: ${resolvedPath} (${engineLabel(engine)})`);
        }
        results = await scanDirectory(resolvedPath, engine, scanCfg, opts.history, opts.gitignore, report);
      } else {
        if (!opts.quiet) {
          console.error(`Scanning file: ${resolvedPath} (${engineLabel(engine)})`);
        }
        results = await scanFile(resolvedPath, engine, scanCfg, report);
      }

      countScan(report, Date.now() - scanStart);
      outputScanResults(applyBaseline(results, baselineEntries), opts, undefined, true, suppressions, report);
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
export function collectSuppressions(
  policyIgnore?: ScanIgnoreRule[],
  policyBaseDir?: string,
  rafterignoreDir: string = process.cwd(),
): Suppression[] {
  // Anchor policy globs to the `.rafter.yml`'s directory and `.rafterignore`
  // globs to the scanned tree (sable-lu0j), so neither can suppress findings in
  // a different tree.
  return [
    ...policyIgnoreToSuppressions(policyIgnore, policyBaseDir),
    ...loadSuppressions(rafterignoreDir),
  ];
}

/**
 * Emit SARIF 2.1.0 JSON for GitHub/GitLab security tab integration
 */
function outputSarif(results: ScanResult[], emptyExitCode: number = 0): void {
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
  // A read error (sable-ilbx) makes an otherwise-empty scan non-clean; the
  // caller passes that exit code in.
  process.exit(results.length > 0 ? 1 : emptyExitCode);
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
  report?: EngineReport,
): void {
  const format = opts.format ?? (opts.json ? "json" : "text");

  if (!["text", "json", "sarif"].includes(format)) {
    console.error(`Invalid format: ${format}. Valid values: text, json, sarif`);
    process.exit(2);
  }

  // Partition off files that could not be read (sable-ilbx). A read failure is
  // not a finding and not a clean pass — surface it so "no secrets detected"
  // cannot stand in for "could not open". Warn on stderr (so stdout stays
  // parseable), report it in the JSON/text body, and let it set the exit code.
  const readErrors = results
    .filter((r) => r.readError)
    .map((r) => ({ file: r.file, error: r.readError! }));
  const scanResults = results.filter((r) => !r.readError);
  if (readErrors.length > 0 && !opts.quiet) {
    console.error(
      fmt.warning(`Could not read ${readErrors.length} file(s); results may be incomplete.`),
    );
  }

  // No silent downgrade (sable-jiqb): when betterleaks was requested/auto but
  // patterns ran instead, say so on stderr so it is visible in every format
  // without corrupting a JSON/SARIF stdout payload. The JSON body below also
  // carries it as structured fields.
  if (report?.degraded && !opts.quiet) {
    console.error(
      fmt.warning(
        `Engine: requested ${report.requested}, used ${engineLabel(report.used)}` +
          (report.reason ? ` (${report.reason})` : ""),
      ),
    );
  }

  // Split suppressed findings off the main result list. Both engines feed
  // through here, so policy-driven suppression applies regardless of source.
  const { results: keptResults, suppressed } = applySuppressions(scanResults, suppressions);

  // Exit code: findings dominate (1); otherwise an unreadable file is a scan
  // that could not complete cleanly (2); a clean, complete scan is 0.
  const scanExitCode = keptResults.length > 0 ? 1 : readErrors.length > 0 ? 2 : 0;

  // Before the format branches, so --json and SARIF runs are recorded too. A
  // clean scan is recorded as well: "we looked on this date and found nothing"
  // is what a postmortem needs.
  logScanToAudit(keptResults, context);

  if (format === "sarif") {
    outputSarif(keptResults, scanExitCode);
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
        // sable-j85 — present only for `auto`-mode (both-engine) scans, so
        // consumers can tell which engine surfaced each finding.
        ...(m.engines ? { engines: m.engines } : {}),
      })),
    }));
    const out: {
      _note: string;
      scan_mode: string;
      triage_applied: boolean;
      engine_requested?: string;
      engine_used?: ResolvedEngine;
      degraded?: boolean;
      degraded_reason?: string;
      results: typeof filesOut;
      _suppressed?: SuppressedFinding[];
      unreadable?: Array<{ file: string; error: string }>;
    } = {
      _note:
        "Local-only scan: pattern-based detection without agentic-intelligence triage. " +
        "Findings have not been evaluated for context (public exposure, key validity, " +
        "deployment environment). Investigate each before acting; do not dismiss. " +
        "Run 'rafter run' for backend agentic analysis.",
      scan_mode: "local",
      triage_applied: false,
      results: filesOut,
    };
    // sable-jiqb — report the engine actually used and any fall-back, so a
    // json/MCP/CI consumer is never left thinking betterleaks ran when it did not.
    if (report) {
      out.engine_requested = report.requested;
      out.engine_used = report.used;
      out.degraded = report.degraded;
      if (report.degraded && report.reason) out.degraded_reason = report.reason;
    }
    if (suppressed.length > 0) {
      out._suppressed = suppressed;
    }
    // Files that could not be read (sable-ilbx) — a reader can tell an empty
    // `results` from an incomplete scan.
    if (readErrors.length > 0) {
      out.unreadable = readErrors;
    }
    console.log(JSON.stringify(out, null, 2));
    if (exitOnFindings) process.exit(scanExitCode);
    return;
  }

  // Text output — note suppression on stderr so stdout remains parseable.
  if (suppressed.length > 0 && !opts.quiet) {
    console.error(fmt.info(`(${suppressed.length} finding(s) hidden by .rafter.yml)`));
  }

  if (keptResults.length === 0) {
    if (readErrors.length > 0) {
      // Not a clean pass — the scan could not read some files (sable-ilbx).
      if (!opts.quiet) {
        console.log(`\n${fmt.warning(`${readErrors.length} file(s) could not be read:`)}`);
        for (const re of readErrors) console.log(`  ${re.file} (${re.error})`);
        console.log();
      }
    } else if (!opts.quiet) {
      const msg = context ? `No secrets detected in ${context}` : "No secrets detected";
      console.log(`\n${fmt.success(msg)}\n`);
    }
    if (exitOnFindings) process.exit(scanExitCode);
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

  if (readErrors.length > 0 && !opts.quiet) {
    console.log(`${fmt.warning(`${readErrors.length} file(s) could not be read:`)}`);
    for (const re of readErrors) console.log(`  ${re.file} (${re.error})`);
    console.log();
  }

  if (context === "staged files") {
    console.log(`${fmt.error("Commit blocked. Remove secrets before committing.")}\n`);
  } else if (exitOnFindings) {
    console.log(`Run 'rafter agent audit' to see the security log.\n`);
  }

  if (exitOnFindings) process.exit(scanExitCode);
}

/**
 * Scan files changed since a git ref (+ lines only in the unified diff).
 */
async function scanDiffFiles(
  ref: string,
  opts: ScanOpts,
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }>; ignore?: ScanIgnoreRule[]; autoUpdateBetterleaks?: boolean },
  baselineEntries: BaselineEntry[] = [],
  scanPath?: string,
  suppressions: Suppression[] = [],
): Promise<void> {
  // git would parse a leading "-" as one of its own options, not a ref.
  if (ref.startsWith("-")) {
    console.error(`Error: invalid ref "${ref}" (a git ref cannot start with "-")`);
    process.exit(2);
  }
  await runGitAddedLineScan(
    ["diff", "-U0", "--no-color", "--diff-filter=ACM", ref],
    opts,
    scanCfg,
    baselineEntries,
    scanPath,
    suppressions,
    `files changed since ${ref}`,
    `No files changed since ${ref}`,
  );
}

/**
 * Scan only the files changed in a git commit range (e.g. `main..HEAD`).
 *
 * sable-jiqb — on a repo large enough that a full betterleaks scan is slow, a
 * user can scope the scan to a range's changed files. Reuses the `--diff`
 * added-line plumbing (patterns engine; git line scope is incompatible with
 * betterleaks' whole-file `dir` scan), with the range passed to `git diff` as a
 * single revision argument.
 */
async function scanRangeFiles(
  range: string,
  opts: ScanOpts,
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }>; ignore?: ScanIgnoreRule[]; autoUpdateBetterleaks?: boolean },
  baselineEntries: BaselineEntry[] = [],
  scanPath?: string,
  suppressions: Suppression[] = [],
): Promise<void> {
  // git would parse a leading "-" as one of its own options, not a revision range.
  if (range.startsWith("-")) {
    console.error(`Error: invalid range "${range}" (a git range cannot start with "-")`);
    process.exit(2);
  }
  await runGitAddedLineScan(
    ["diff", "-U0", "--no-color", "--diff-filter=ACM", range],
    opts,
    scanCfg,
    baselineEntries,
    scanPath,
    suppressions,
    `files changed in ${range}`,
    `No files changed in ${range}`,
  );
}

/**
 * Scan git staged files for secrets (+ lines only in the staged diff).
 */
async function scanStagedFiles(
  opts: ScanOpts,
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }>; ignore?: ScanIgnoreRule[]; autoUpdateBetterleaks?: boolean },
  baselineEntries: BaselineEntry[] = [],
  scanPath?: string,
  suppressions: Suppression[] = [],
): Promise<void> {
  await runGitAddedLineScan(
    ["diff", "-U0", "--no-color", "--cached", "--diff-filter=ACM"],
    opts,
    scanCfg,
    baselineEntries,
    scanPath,
    suppressions,
    "staged files",
    "No files staged for commit",
    { notRepoMessage: "Error: Not in a git repository" },
  );
}

/**
 * Shared handler for --diff / --staged: parse unified diff for + lines, scan
 * with the patterns engine, then apply exclude_paths / baseline / suppressions.
 */
async function runGitAddedLineScan(
  gitArgs: string[],
  opts: ScanOpts,
  scanCfg: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }>; ignore?: ScanIgnoreRule[]; autoUpdateBetterleaks?: boolean } | undefined,
  baselineEntries: BaselineEntry[],
  scanPath: string | undefined,
  suppressions: Suppression[],
  contextLabel: string,
  emptyMessage: string,
  errorOpts?: { notRepoMessage?: string },
): Promise<void> {
  const cwd = scanPath && fs.existsSync(scanPath) && fs.statSync(scanPath).isDirectory() ? scanPath : undefined;
  const diffReport = diffModeReport(opts);
  try {
    const patch = execFileSync("git", gitArgs, {
      encoding: "utf-8",
      cwd,
      stdio: ["pipe", "pipe", "ignore"],
      // The default 1 MiB cap makes `git diff` throw ENOBUFS on ordinary large
      // staged diffs (lockfiles, generated or vendored files). That crash used
      // to exit 1 — indistinguishable from a real finding, so a commit gate
      // reported a broken scan as a possible secret (#274). Read the whole diff.
      maxBuffer: gitDiffMaxBuffer(),
    });

    if (!patch.trim()) {
      if (!opts.quiet) {
        // Status line, so stderr — stdout must stay parseable as JSON under
        // --json, and outputScanResults owns the single stdout success line.
        console.error(fmt.success(emptyMessage));
      }
      outputScanResults([], opts, contextLabel, true, suppressions, diffReport);
      return;
    }

    const addedLines = parseUnifiedDiffAddedLines(patch);
    if (addedLines.length === 0) {
      if (!opts.quiet) {
        // Status line, so stderr — stdout must stay parseable as JSON under
        // --json, and outputScanResults owns the single stdout success line.
        console.error(fmt.success(emptyMessage));
      }
      outputScanResults([], opts, contextLabel, true, suppressions, diffReport);
      return;
    }

    const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      encoding: "utf-8",
      cwd,
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();

    const fileCount = new Set(addedLines.map((l) => l.file)).size;
    if (!opts.quiet) {
      console.error(
        `Scanning ${addedLines.length} added line(s) in ${fileCount} file(s) (${contextLabel})...`,
      );
    }

    const allResults = scanAddedDiffLines(addedLines, repoRoot, scanCfg?.customPatterns);
    const filtered = applyExcludePaths(allResults, scanCfg?.excludePaths, repoRoot);
    outputScanResults(applyBaseline(filtered, baselineEntries), opts, contextLabel, true, suppressions, diffReport);
  } catch (error: any) {
    if (error.status === 128) {
      console.error(errorOpts?.notRepoMessage ?? "Error: Not in a git repository or invalid ref");
      process.exit(2);
    }
    // A scan that could not run is a scan ERROR, never a finding. Exit 2 (per
    // CLI_SPEC: invalid input / scan error) so a commit gate keying on the exit
    // code never mistakes a broken scan for a detected secret (#274). ENOBUFS is
    // the known case (a diff past the buffer), but any failure to read/parse the
    // diff belongs here rather than surfacing as exit 1.
    const detail = error?.code === "ENOBUFS"
      ? "staged diff too large for the scanner to read"
      : (error?.message ?? String(error));
    console.error(`Error: secret scan could not run (${detail}); no scan was performed`);
    process.exit(2);
  }
}

/** Engine the scanners dispatch on. `both` (sable-j85) runs betterleaks and
 * patterns and unions the findings; it is only ever produced internally by
 * `auto` mode, never typed by a user. */
type ResolvedEngine = "betterleaks" | "patterns" | "both";

/** Self-explanatory display label for a resolved engine — "both" alone
 * doesn't say which two engines ran (issue #231 item 6). */
export function engineLabel(engine: ResolvedEngine): string {
  return engine === "both" ? "both: betterleaks + patterns" : engine;
}

/**
 * What engine the user asked for, what actually ran, and whether that was a
 * downgrade (sable-jiqb). Threaded through the scan so both the text and the
 * JSON output can report it: betterleaks timing out or being unavailable used
 * to drop the scan silently to the patterns engine with nothing in the JSON to
 * say so, leaving json/MCP/CI consumers unaware the stronger engine never ran.
 */
export interface EngineReport {
  /** The `--engine` value as requested: "auto" | "betterleaks" | "patterns". */
  requested: string;
  /** The engine whose findings are in this result. */
  used: ResolvedEngine;
  /** betterleaks was wanted (auto or explicit) but did not contribute. */
  degraded: boolean;
  /** Why it degraded (unavailable, stale, timed out, crashed). */
  reason?: string;
}

/**
 * Build the initial engine report from the requested engine and the engine
 * `selectEngine` resolved to. A resolution of `patterns` when betterleaks was
 * wanted (explicit or via `auto`) is a degradation; `selectReason` explains it.
 * Scan-time failures (a timeout mid-scan) further mutate this report in the
 * scanners below.
 */
export function buildEngineReport(
  requested: string,
  resolved: ResolvedEngine,
  selectReason: string | null = null,
): EngineReport {
  const wantedBetterleaks = requested === "auto" || requested === "betterleaks";
  const degraded = wantedBetterleaks && resolved === "patterns";
  return {
    requested,
    used: resolved,
    degraded,
    reason: degraded ? (selectReason ?? "betterleaks unavailable; used the patterns engine") : undefined,
  };
}

/** Record a scan-time fall-back to the patterns engine on the report. */
function markDegraded(report: EngineReport | undefined, reason: string): void {
  if (!report) return;
  report.used = "patterns";
  report.degraded = true;
  report.reason = reason;
}

/**
 * The engine report for the git-diff modes (`--diff` / `--range` / `--staged`),
 * which scan added lines with the patterns engine by design (betterleaks'
 * whole-file `dir` scan is incompatible with a line scope). Only an explicit
 * `--engine betterleaks` is a degradation here; `auto` is satisfied by patterns.
 */
function diffModeReport(opts: ScanOpts): EngineReport {
  const requested = opts.engine || "auto";
  const degraded = requested === "betterleaks";
  return {
    requested,
    used: "patterns",
    degraded,
    reason: degraded
      ? "diff/range/staged modes scan changed lines with the patterns engine"
      : undefined,
  };
}

/**
 * Select scan engine based on availability and user preference.
 *
 * `auto` (the default) resolves to `both` whenever betterleaks is available
 * and usable — rafter then runs both engines and unions their findings
 * (sable-j85), so a miss in one (betterleaks 1.1.x does not detect AWS access
 * keys — sable-h2y) is still caught by the other. It degrades to
 * `patterns`-only when betterleaks is absent or a stale binary can't be
 * refreshed. Explicit `--engine betterleaks` / `--engine patterns` stay
 * single-engine.
 *
 * `autoUpdate` (default true) controls sable-o4k behavior: when the resolved
 * engine is betterleaks but the managed binary is stale, auto-update it before
 * scanning. The caller resolves this from `--no-auto-update` and the
 * `scan.auto_update_betterleaks` config key.
 */
export async function selectEngine(
  preference: string,
  quiet: boolean,
  autoUpdate = true,
): Promise<{ engine: ResolvedEngine; reason: string | null }> {
  if (preference === "patterns") {
    return { engine: "patterns", reason: null };
  }

  if (preference === "betterleaks") {
    const bl = new BetterleaksScanner();
    const available = await bl.isAvailable();
    if (!available) {
      if (!quiet) {
        console.error(fmt.warning("Betterleaks requested but not available, using patterns"));
      }
      return { engine: "patterns", reason: "betterleaks requested but not available" };
    }
    return ensureBetterleaksUsable(quiet, autoUpdate);
  }

  if (preference !== "auto") {
    console.error(`Invalid engine: ${preference}. Valid values: auto, betterleaks, patterns`);
    process.exit(2);
  }

  // Auto mode: run BOTH engines when betterleaks is usable; otherwise patterns.
  const bl = new BetterleaksScanner();
  const available = await bl.isAvailable();
  if (!available) return { engine: "patterns", reason: "betterleaks not available" };

  const usable = await ensureBetterleaksUsable(quiet, autoUpdate);
  return usable.engine === "betterleaks"
    ? { engine: "both", reason: null }
    : { engine: "patterns", reason: usable.reason };
}

/**
 * sable-o4k — guard against a stale rafter-managed betterleaks binary silently
 * returning zero findings (a leftover binary from an older rafter parses fine
 * with `version` but emits a JSON shape the current parser rejects).
 *
 * When the managed binary is stale we auto-update it to the pinned version
 * (default on; opt out with `--no-auto-update` or `scan.auto_update_betterleaks:
 * false`). In an interactive TTY we confirm first. If the update is disabled,
 * declined, or fails, we degrade to the patterns engine and print a CTA rather
 * than scanning with a binary that yields nothing.
 */
async function ensureBetterleaksUsable(
  quiet: boolean,
  autoUpdate: boolean,
): Promise<{ engine: "betterleaks" | "patterns"; reason: string | null }> {
  const bm = new BinaryManager();
  if (!(await bm.isManagedBetterleaksStale())) return { engine: "betterleaks", reason: null };

  const current = await bm.getBetterleaksVersion();
  const cta = "Fix manually with: rafter agent update-betterleaks";
  const stale = `Stale betterleaks binary (${current}; expected v${BETTERLEAKS_VERSION})`;

  if (!autoUpdate) {
    if (!quiet) {
      console.error(fmt.warning(`${stale}. Auto-update is off — using the patterns engine for this scan. ${cta}`));
    }
    return { engine: "patterns", reason: `${stale}; auto-update off` };
  }

  // Only prompt when there's a human at a TTY; otherwise auto-update proceeds
  // (default on) so non-interactive runs aren't left with a broken engine.
  if (process.stdin.isTTY && !quiet) {
    const ok = await askYesNo(`${stale}. Update it now?`, true);
    if (!ok) {
      console.error(fmt.warning(`Skipped — using the patterns engine for this scan. ${cta}`));
      return { engine: "patterns", reason: `${stale}; update declined` };
    }
  }

  if (!quiet) console.error(fmt.info(`Updating betterleaks to v${BETTERLEAKS_VERSION}...`));
  try {
    await bm.downloadBetterleaks((m) => { if (!quiet) console.error(`   ${m}`); }, BETTERLEAKS_VERSION);
    if (!quiet) console.error(fmt.success(`Betterleaks updated to v${BETTERLEAKS_VERSION}.`));
    return { engine: "betterleaks", reason: null };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (!quiet) {
      console.error(fmt.warning(`Betterleaks update failed (${msg}) — using the patterns engine for this scan. ${cta}`));
    }
    return { engine: "patterns", reason: `betterleaks update failed (${msg})` };
  }
}

/**
 * Resolve whether stale-binary auto-update is enabled, from the CLI flag
 * (`--no-auto-update` → `opts.autoUpdate === false`) and the
 * `scan.auto_update_betterleaks` config key. Either opting out disables it.
 */
export function autoUpdateEnabled(
  opts: { autoUpdate?: boolean },
  scanCfg?: { autoUpdateBetterleaks?: boolean },
): boolean {
  return opts.autoUpdate !== false && scanCfg?.autoUpdateBetterleaks !== false;
}

/**
 * Scan a file with selected engine
 */
export async function scanFile(
  filePath: string,
  engine: ResolvedEngine,
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }>; autoUpdateBetterleaks?: boolean },
  report?: EngineReport,
): Promise<ScanResult[]> {
  const runPatterns = (): ScanResult[] => {
    const scanner = new RegexScanner(scanCfg?.customPatterns);
    const result = scanner.scanFile(filePath);
    // Keep the result when it has findings OR could not be read (sable-ilbx),
    // so a permission-denied file is not reported as a clean scan.
    return result.matches.length > 0 || result.readError ? [result] : [];
  };

  if (engine === "both") {
    // sable-j85 — kick off betterleaks (async subprocess) first, run the
    // synchronous regex scan while it works, then union. A betterleaks failure
    // degrades to patterns-only rather than losing the scan.
    const blPromise = (async (): Promise<ScanResult[]> => {
      try {
        const result = await new BetterleaksScanner().scanFile(filePath);
        return result.matches.length > 0 ? [result] : [];
      } catch (e) {
        console.error(fmt.warning("Betterleaks scan failed, using patterns only for this run"));
        markDegraded(report, errorText(e));
        return [];
      }
    })();
    const patternsResults = runPatterns();
    return unionScanResults(await blPromise, patternsResults);
  }

  if (engine === "betterleaks") {
    try {
      const bl = new BetterleaksScanner();
      const result = await bl.scanFile(filePath);
      return result.matches.length > 0 ? [result] : [];
    } catch (e) {
      console.error(fmt.warning("Betterleaks scan failed, falling back to patterns"));
      markDegraded(report, errorText(e));
      return runPatterns();
    }
  }

  return runPatterns();
}

/** An engine failure's message, e.g. "Betterleaks scan failed (timed out after 60s)". */
function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Scan a directory with selected engine
 */
export async function scanDirectory(
  dirPath: string,
  engine: ResolvedEngine,
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }>; autoUpdateBetterleaks?: boolean },
  history?: boolean,
  respectGitignore?: boolean,
  report?: EngineReport,
): Promise<ScanResult[]> {
  // respectGitignore default is true. Both engines honor it: the patterns
  // engine via RegexScanner.scanDirectory, betterleaks by scanning only the
  // files git does not ignore (BetterleaksScanner.scanDirectory, #262).
  // sable-28lv — with --history BOTH engines read the commit history. The
  // patterns engine used to scan the working tree instead, so without
  // betterleaks `--history` reported a clean history it had never read.
  let repoRoot: string | null = null;
  if (history) {
    try {
      repoRoot = gitRepoRoot(dirPath);
    } catch (e) {
      console.error(`Error: ${errorText(e)}`);
      process.exit(2);
    }
  }

  const runPatterns = async (): Promise<ScanResult[]> => {
    if (!history) {
      return new RegexScanner(scanCfg?.customPatterns).scanDirectory(dirPath, {
        excludePaths: scanCfg?.excludePaths,
        respectGitignore,
      });
    }
    try {
      return await scanGitHistory(dirPath, scanCfg?.customPatterns);
    } catch (e) {
      console.error(`Error: ${errorText(e)}`);
      process.exit(2);
    }
  };
  // `betterleaks git` reports paths relative to the repo root; make them
  // absolute like every other scan, so the union merges the two engines.
  const runBetterleaks = async (): Promise<ScanResult[]> => {
    const found = await new BetterleaksScanner().scanDirectory(dirPath, { useGit: history ?? false, respectGitignore });
    return repoRoot ? found.map((r) => ({ ...r, file: path.resolve(repoRoot!, r.file) })) : found;
  };

  let results: ScanResult[];
  if (engine === "both") {
    // sable-j85 — start betterleaks (async subprocess) first, run the patterns
    // engine while it runs, then union. The exclude-paths post-filter below
    // applies to the merged set.
    const blPromise = runBetterleaks().catch((e): ScanResult[] => {
      console.error(fmt.warning(`${errorText(e)}; using patterns only for this run`));
      markDegraded(report, errorText(e));
      return [];
    });
    const patternsResults = await runPatterns();
    results = unionScanResults(await blPromise, patternsResults);
  } else if (engine === "betterleaks") {
    try {
      results = await runBetterleaks();
    } catch (e) {
      console.error(fmt.warning(`${errorText(e)}; falling back to patterns`));
      markDegraded(report, errorText(e));
      results = await runPatterns();
    }
  } else {
    results = await runPatterns();
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
  scanCfg?: { excludePaths?: string[]; customPatterns?: Array<{ name: string; regex: string; severity: string }>; ignore?: ScanIgnoreRule[]; autoUpdateBetterleaks?: boolean },
  suppressions: Suppression[] = [],
): Promise<void> {
  const { watch } = await import("chokidar");
  const logger = new AuditLogger();

  const engine = (await selectEngine(opts.engine || "auto", opts.quiet || false, autoUpdateEnabled(opts, scanCfg))).engine;

  if (!opts.quiet) {
    console.error(fmt.info(`Watching ${watchPath} for changes (${engineLabel(engine)}). Press Ctrl+C to exit.`));
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
 * Record that a scan ran, so `rafter agent audit` has something in it.
 *
 * `rafter secrets` told the user "Run 'rafter agent audit' to see the security
 * log" and the log was always empty, because only command interception ever
 * wrote to it — three of seven beta users followed that hint and hit a dead
 * end, one of them immediately after a correct and useful scan result. The
 * first thing a careful person does with a security finding is look for the
 * record of it.
 *
 * Counts and pattern NAMES only — never a matched value, not even redacted.
 * The audit log is a postmortem artifact that outlives the terminal, so it
 * must not become a second place secrets live.
 */
function logScanToAudit(results: ScanResult[], context?: string): void {
  try {
    const totalMatches = results.reduce((n, r) => n + r.matches.length, 0);
    const patterns = [...new Set(results.flatMap((r) => r.matches.map((m) => m.pattern.name)))].sort();
    new AuditLogger().log({
      eventType: "scan_executed",
      securityCheck: {
        passed: totalMatches === 0,
        reason: totalMatches === 0
          ? "Secret scan completed with no findings"
          : `Secret scan found ${totalMatches} secret(s) in ${results.length} file(s)`,
        details: {
          filesWithFindings: results.length,
          totalMatches,
          patterns,
          ...(context ? { context } : {}),
        },
      },
      resolution: { actionTaken: totalMatches === 0 ? "allowed" : "blocked" },
    });
  } catch {
    // Never let audit logging break a scan — the scan result is the product.
  }
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
