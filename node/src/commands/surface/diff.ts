import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { Command } from "commander";

import { diffProperties, type DiffCoverage } from "../../core/surface/differ.js";
import { KIND_SPECS } from "../../core/surface/kind-specs.js";
import { EXTRACTORS } from "../../core/surface/registry.js";
import {
  canonicalJson,
  sortUnanalyzed,
  transitionToWire,
  type JsonValue,
} from "../../core/surface/serialize.js";
import type {
  Extractor,
  Property,
  SurfaceSeverity,
  Transition,
  Unanalyzed,
} from "../../core/surface/model.js";
import {
  BaseTreeReader,
  EMPTY_TREE_OID,
  InvalidRefError,
  RefResolutionError,
} from "../../utils/git-tree.js";
import {
  baseUnresolvedEnvelope,
  renderBaseUnresolved,
  renderText,
  type RenderModel,
} from "./render.js";

const NOTE = "Attack-surface diff: a delta of security properties between two trees, not a "
  + "findings list. `change` is structural (added/removed/modified); `danger` is semantic and is "
  + "the only thing severity attaches to. An empty `transitions` array with "
  + "`coverage.inconclusive: false` means the analyzed surface is unchanged — it does not mean "
  + "the code is safe.";

const SCHEMA_VERSION = 1;
const SEVERITY_ORDER = ["low", "medium", "high", "critical"] as const;
const FORMATS = ["text", "json"] as const;
const FAIL_ON = ["low", "medium", "high", "critical", "none"] as const;
const ON_INCONCLUSIVE = ["exit", "warn"] as const;

export type Severity = (typeof SEVERITY_ORDER)[number];
export type FailOn = (typeof FAIL_ON)[number];

export interface SurfaceDiffOptions {
  base: string;
  head: string | null;
  format: "text" | "json";
  failOn: FailOn;
  minSeverity: Severity;
  onInconclusive: "exit" | "warn";
  includeDecreased: boolean;
  all: boolean;
  explain: boolean;
  fetchBase: boolean;
  quiet: boolean;
}

/** Exit 2 and exit 3 are raised, never returned — that is how 3 > 2 > 4 > 1 > 0 stays true. */
export class SurfaceCliError extends Error {
  constructor(
    message: string,
    readonly exitCode: number,
    readonly code: string,
    /** Machine-readable envelope for stdout under --json. Exit 3 only — see execute(). */
    readonly details: JsonValue | null = null,
  ) {
    super(message);
    this.name = "SurfaceCliError";
  }
}

export interface SurfaceDiffOutcome {
  exitCode: number;
  report: JsonValue;
  model: RenderModel;
  /** stderr status messages; suppressed by --quiet. */
  status: string[];
}

function severityRank(severity: string): number {
  return SEVERITY_ORDER.indexOf(severity as Severity);
}

function assertChoice<T extends string>(
  value: string,
  choices: readonly T[],
  flag: string,
): T {
  if (!(choices as readonly string[]).includes(value)) {
    throw new SurfaceCliError(
      `Invalid value for ${flag}: ${JSON.stringify(value)}. Expected one of: ${choices.join(", ")}`,
      2,
      "invalid_flag",
    );
  }
  return value as T;
}

/**
 * Synchronous writes: the action handler calls process.exit(), which can truncate
 * an async pipe write. The JSON report is large enough for that to matter.
 */
function writeSync(fd: 1 | 2, text: string): void {
  try {
    fs.writeSync(fd, text);
  } catch {
    (fd === 1 ? process.stdout : process.stderr).write(text);
  }
}

/** Composed here rather than reused from git-tree so both runtimes emit the same bytes. */
function invalidRef(ref: string): SurfaceCliError {
  return new SurfaceCliError(`Invalid git ref: ${JSON.stringify(ref)}`, 2, "invalid_ref");
}

function isGitRepo(repoPath: string): boolean {
  try {
    execFileSync("git", ["rev-parse", "--git-dir"], { cwd: repoPath, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function fetchBaseRef(repoPath: string, ref: string): boolean {
  try {
    execFileSync(
      "git",
      ["fetch", "--no-tags", "--depth=1", "--end-of-options", "origin", ref],
      { cwd: repoPath, stdio: "ignore" },
    );
    return true;
  } catch {
    return false;
  }
}

/** Runs every extractor over one side's files. An extractor crash is exit 2, never a silent pass. */
function runExtractors(
  extractors: readonly Extractor[],
  files: ReadonlyMap<string, string>,
  side: "base" | "head",
  changed: ReadonlySet<string>,
): { properties: Property[]; unanalyzed: Unanalyzed[] } {
  const properties: Property[] = [];
  const unanalyzed: Unanalyzed[] = [];
  for (const extractor of extractors) {
    const subset = new Map<string, string>();
    for (const [file, content] of files) {
      if (extractor.candidate(file, Buffer.byteLength(content, "utf8"))) subset.set(file, content);
    }
    if (subset.size === 0) continue;
    let result;
    try {
      result = extractor.extract(subset);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new SurfaceCliError(
        `Extractor '${extractor.id}' failed on the ${side} side: ${detail}`,
        2,
        "extractor_error",
      );
    }
    properties.push(...result.properties);
    // The extractor knows the file; only the caller knows the side and the hint set.
    for (const item of result.unanalyzed) {
      unanalyzed.push({ ...item, side, changed: changed.has(item.file) });
    }
  }
  return { properties, unanalyzed };
}

function countAnalyzed(
  files: ReadonlyMap<string, string>,
  unanalyzed: readonly Unanalyzed[],
): number {
  const failed = new Set(unanalyzed.map((item) => item.file));
  return [...files.keys()].filter((file) => !failed.has(file)).length;
}

function summarize(
  transitions: readonly Transition[],
  minSeverity: Severity,
): Record<string, JsonValue> {
  const count = (predicate: (transition: Transition) => boolean): number =>
    transitions.filter(predicate).length;
  let highest: SurfaceSeverity = null;
  for (const transition of transitions) {
    if (transition.severity === null) continue;
    if (highest === null || severityRank(transition.severity) > severityRank(highest)) {
      highest = transition.severity;
    }
  }
  return {
    increased: count((transition) => transition.danger === "increased"),
    decreased: count((transition) => transition.danger === "decreased"),
    incomparable: count((transition) => transition.danger === "incomparable"),
    unchanged: count((transition) => transition.danger === "unchanged"),
    unknown: count((transition) => transition.danger === "unknown"),
    added: count((transition) => transition.change === "added"),
    removed: count((transition) => transition.change === "removed"),
    modified: count((transition) => transition.change === "modified"),
    highest_severity: highest,
    reportable: count((transition) => transition.severity !== null
      && severityRank(transition.severity) >= severityRank(minSeverity)),
  };
}

export function runSurfaceDiff(
  repoPath: string,
  options: SurfaceDiffOptions,
  extractors: readonly Extractor[] = EXTRACTORS,
): SurfaceDiffOutcome {
  if (!fs.existsSync(repoPath) || !fs.statSync(repoPath).isDirectory()) {
    throw new SurfaceCliError(`Path not found: ${repoPath}`, 2, "path_not_found");
  }
  if (!isGitRepo(repoPath)) {
    throw new SurfaceCliError(`Not a git repository: ${repoPath}`, 2, "not_a_repo");
  }

  const reader = new BaseTreeReader(repoPath);
  const status: string[] = [];

  let baseOid: string;
  try {
    baseOid = resolveBase(reader, repoPath, options, status);
  } catch (error) {
    if (error instanceof InvalidRefError) throw invalidRef(options.base);
    throw error;
  }

  let headOid: string | null = null;
  if (options.head !== null) {
    try {
      headOid = reader.resolveRef(options.head);
    } catch (error) {
      if (error instanceof InvalidRefError) throw invalidRef(options.head);
      if (error instanceof RefResolutionError) {
        throw new SurfaceCliError(
          `Cannot resolve head ref '${options.head}' — no such commit in this repository.`,
          2,
          "invalid_ref",
        );
      }
      throw error;
    }
  }

  // Changed paths are a hint for §5 R4 and rendering only — never a filter on extraction (§4.1).
  // If the hint cannot be computed, assume everything changed: an inconclusive gate is the
  // conservative failure, a silent clean is not.
  let changed: Set<string>;
  let changedHintFailed = false;
  try {
    changed = reader.changedPaths(baseOid, headOid ?? undefined);
  } catch {
    changed = new Set();
    changedHintFailed = true;
    status.push("Could not compute the changed-file hint; treating every candidate as changed.");
  }

  const candidate = (file: string, sizeBytes: number): boolean =>
    extractors.some((extractor) => extractor.candidate(file, sizeBytes));

  const baseRead = reader.readTreeCandidates(baseOid, candidate, changed, "base");
  const headRead = headOid === null
    ? reader.readWorkTreeCandidates(candidate, changed)
    : reader.readTreeCandidates(headOid, candidate, changed, "head");

  const baseExtract = runExtractors(extractors, baseRead.files, "base", changed);
  const headExtract = runExtractors(extractors, headRead.files, "head", changed);

  const unanalyzed: Unanalyzed[] = [
    ...baseRead.unanalyzed,
    ...headRead.unanalyzed,
    ...baseExtract.unanalyzed,
    ...headExtract.unanalyzed,
  ].map((item) => (changedHintFailed ? { ...item, changed: true } : item));

  // The differ appends its own coverage records (duplicate keys), so the flags below are
  // computed from the post-diff list, not the pre-diff one.
  const coverage: DiffCoverage = { unanalyzed };
  const transitions = diffProperties(
    baseExtract.properties,
    headExtract.properties,
    KIND_SPECS,
    coverage,
  );

  const sortedUnanalyzed = sortUnanalyzed(coverage.unanalyzed);
  const degraded = sortedUnanalyzed.length > 0;
  const inconclusive = sortedUnanalyzed.some((item) => item.changed);

  const baseLabel = baseOid === EMPTY_TREE_OID ? "EMPTY_TREE" : options.base;
  const headLabel = options.head ?? "WORKTREE";

  const report: JsonValue = {
    _note: NOTE,
    schema_version: SCHEMA_VERSION,
    base: { ref: baseLabel, resolved: baseOid },
    head: { ref: headLabel, resolved: headOid },
    summary: summarize(transitions, options.minSeverity),
    transitions: transitions.map(transitionToWire),
    coverage: {
      analyzed: countAnalyzed(baseRead.files, baseExtract.unanalyzed)
        + countAnalyzed(headRead.files, headExtract.unanalyzed),
      degraded,
      inconclusive,
      unanalyzed: sortedUnanalyzed.map((item) => ({
        file: item.file,
        side: item.side,
        reason: item.reason,
        detail: item.detail,
        changed: item.changed,
      })),
    },
  };

  const gating = options.failOn === "none"
    ? []
    : transitions.filter((transition) => transition.severity !== null
      && (transition.danger === "increased" || transition.danger === "incomparable")
      && severityRank(transition.severity) >= severityRank(options.failOn));

  let exitCode = 0;
  if (gating.length > 0) exitCode = 1;
  if (inconclusive && options.onInconclusive === "exit") exitCode = 4;

  if (inconclusive && options.onInconclusive === "warn") {
    status.push("Inconclusive result downgraded to a warning by --on-inconclusive warn.");
  }

  return {
    exitCode,
    report,
    status,
    model: {
      baseLabel: baseOid === EMPTY_TREE_OID ? "empty tree" : options.base,
      headLabel: options.head ?? "working tree",
      transitions,
      unanalyzed: sortedUnanalyzed,
      degraded,
      inconclusive,
    },
  };
}

function resolveBase(
  reader: BaseTreeReader,
  repoPath: string,
  options: SurfaceDiffOptions,
  status: string[],
): string {
  try {
    return reader.resolveRef(options.base);
  } catch (error) {
    if (!(error instanceof RefResolutionError)) throw error;
    // An unreachable base must never become an empty base — that reports the whole
    // surface as newly appeared (§4.4).
    if (options.fetchBase) {
      status.push(`Fetching base ref '${options.base}' (--fetch-base)…`);
      if (fetchBaseRef(repoPath, options.base)) {
        try {
          return reader.resolveRef("FETCH_HEAD");
        } catch {
          /* fall through to exit 3 */
        }
      }
    }
    let shallow = false;
    try {
      shallow = reader.isShallow();
    } catch {
      shallow = false;
    }
    throw new SurfaceCliError(
      renderBaseUnresolved(options.base, shallow),
      3,
      "base_unresolved",
      baseUnresolvedEnvelope(options.base, shallow) as JsonValue,
    );
  }
}

export function createSurfaceDiffCommand(): Command {
  const command = new Command("diff")
    .description("Diff the security-relevant attack surface between two trees")
    .argument("[path]", "Repository path (default: current directory)")
    .option("--base <ref>", "Base ref", "HEAD")
    .option("--head <ref>", "Head ref (default: the working tree)")
    .option("--format <format>", "Output format: text or json", "text")
    .option("--json", "Alias for --format json")
    .option("--fail-on <severity>", "Exit-1 threshold: low, medium, high, critical, none", "high")
    .option("--min-severity <severity>", "Display floor: low, medium, high, critical", "low")
    .option("--on-inconclusive <mode>", "exit or warn (default: exit, or warn with --fail-on none)")
    .option("--include-decreased", "Show transitions that became safer")
    .option("--all", "Include severity-null transitions")
    .option("--explain", "Enumerate unanalyzed files")
    .option("--fetch-base", "Permit one narrow git fetch to resolve the base")
    .option("--quiet", "Suppress stderr status messages")
    .action((pathArg: string | undefined, opts: Record<string, unknown>) => {
      let exitCode: number;
      try {
        exitCode = execute(pathArg, opts);
      } catch (error) {
        if (error instanceof SurfaceCliError) {
          writeSync(2, `${error.message}\n`);
          process.exit(error.exitCode);
        }
        const detail = error instanceof Error ? error.message : String(error);
        writeSync(2, `Attack-surface diff failed: ${detail}\n`);
        process.exit(2);
      }
      process.exit(exitCode);
    });

  // Commander exits 1 on a malformed invocation; §6.3 says an invalid flag is exit 2.
  command.exitOverride((error) => {
    if (error.exitCode === 0) process.exit(0);
    process.exit(2);
  });
  return command;
}

function execute(pathArg: string | undefined, opts: Record<string, unknown>): number {
  const format = opts.json === true
    ? "json"
    : assertChoice(String(opts.format ?? "text"), FORMATS, "--format");
  const failOn = assertChoice(String(opts.failOn ?? "high"), FAIL_ON, "--fail-on");
  const minSeverity = assertChoice(
    String(opts.minSeverity ?? "low"),
    SEVERITY_ORDER,
    "--min-severity",
  );
  const onInconclusive = opts.onInconclusive === undefined
    ? (failOn === "none" ? "warn" : "exit")
    : assertChoice(String(opts.onInconclusive), ON_INCONCLUSIVE, "--on-inconclusive");

  const options: SurfaceDiffOptions = {
    base: String(opts.base ?? "HEAD"),
    head: opts.head === undefined ? null : String(opts.head),
    format,
    failOn,
    minSeverity,
    onInconclusive,
    includeDecreased: opts.includeDecreased === true,
    all: opts.all === true,
    explain: opts.explain === true,
    fetchBase: opts.fetchBase === true,
    quiet: opts.quiet === true,
  };

  const repoPath = path.resolve(pathArg ?? process.cwd());
  let outcome: SurfaceDiffOutcome;
  try {
    outcome = runSurfaceDiff(repoPath, options);
  } catch (error) {
    // Exit 3 only. §4.4 point 4 asks for a machine-readable failure specifically
    // here; exit 2 stays on stderr because it covers cases — an invalid --format
    // among them — where the CLI fails before the output mode is even resolved.
    if (error instanceof SurfaceCliError && error.exitCode === 3 && error.details !== null
      && format === "json") {
      writeSync(1, `${canonicalJson(error.details)}\n`);
    }
    throw error;
  }

  // stdout carries the result and nothing else; every status message is stderr.
  if (format === "json") {
    writeSync(1, `${canonicalJson(outcome.report)}\n`);
  } else {
    writeSync(1, renderText(outcome.model, {
      minSeverity: options.minSeverity,
      includeDecreased: options.includeDecreased,
      all: options.all,
      explain: options.explain,
      onInconclusive: options.onInconclusive,
    }));
  }
  if (!options.quiet) {
    for (const line of outcome.status) writeSync(2, `${line}\n`);
  }
  return outcome.exitCode;
}
