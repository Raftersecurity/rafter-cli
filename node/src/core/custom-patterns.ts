/**
 * Load custom secret patterns from ~/.rafter/patterns/
 * and suppression rules from .rafterignore + .rafter.yml ignore section.
 */

import fs from "fs";
import path from "path";
import { minimatch } from "minimatch";
import { Pattern, PatternMatch } from "./pattern-engine.js";
import { getRafterDir } from "./config-defaults.js";
import type { ScanIgnoreRule } from "./config-schema.js";

// ---------------------------------------------------------------------------
// Custom pattern loading
// ---------------------------------------------------------------------------

/**
 * Load user-defined patterns from ~/.rafter/patterns/*.txt and *.json.
 *
 * .txt  — one regex per line (comments with # ignored)
 * .json — array of {name, pattern, severity?} objects
 *
 * Returns Pattern[] merged with DEFAULT_SECRET_PATTERNS by callers.
 */
export function loadCustomPatterns(): Pattern[] {
  const patternsDir = path.join(getRafterDir(), "patterns");
  if (!fs.existsSync(patternsDir)) return [];

  const results: Pattern[] = [];

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(patternsDir, { withFileTypes: true });
  } catch {
    return [];
  }

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const file = path.join(patternsDir, entry.name);
    const ext = path.extname(entry.name).toLowerCase();

    if (ext === ".txt") {
      results.push(...loadTxtPatterns(file));
    } else if (ext === ".json") {
      results.push(...loadJsonPatterns(file));
    }
  }

  return results;
}

function loadTxtPatterns(file: string): Pattern[] {
  try {
    const lines = fs.readFileSync(file, "utf-8").split("\n");
    const patterns: Pattern[] = [];
    for (const raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      patterns.push({
        name: `Custom (${path.basename(file, ".txt")})`,
        regex: line,
        severity: "high",
      });
    }
    return patterns;
  } catch {
    return [];
  }
}

function loadJsonPatterns(file: string): Pattern[] {
  try {
    const data = JSON.parse(fs.readFileSync(file, "utf-8"));
    if (!Array.isArray(data)) return [];
    const patterns: Pattern[] = [];
    for (const entry of data) {
      if (typeof entry.pattern !== "string" || !entry.pattern) continue;
      try {
        new RegExp(entry.pattern);
      } catch {
        console.error(`Warning: skipping custom pattern in ${path.basename(file)} — invalid regex: ${entry.pattern}`);
        continue;
      }
      const severity = entry.severity ?? "high";
      if (!["low", "medium", "high", "critical"].includes(severity)) {
        console.error(`Warning: skipping custom pattern in ${path.basename(file)} — invalid severity: ${severity}`);
        continue;
      }
      patterns.push({
        name: entry.name ?? `Custom (${path.basename(file, ".json")})`,
        regex: entry.pattern,
        severity: severity as Pattern["severity"],
        description: entry.description,
      });
    }
    return patterns;
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// .rafterignore suppression
// ---------------------------------------------------------------------------

export interface Suppression {
  /** Glob pattern matching file paths to suppress, e.g. "tests/**" */
  pathGlob: string;
  /** Optional pattern name to suppress, e.g. "generic-api-key". Empty = suppress all patterns for matching files. */
  patternName?: string;
  /** Human-readable rationale (from .rafter.yml `reason`). */
  reason?: string;
  /** Where the suppression was defined — surfaced in JSON output. */
  source?: ".rafterignore" | ".rafter.yml";
}

export interface SuppressedFinding {
  file: string;
  line: number | null;
  column: number | null;
  rule: string;
  severity: string;
  reason: string | null;
  source: string;
}

/**
 * Parse .rafterignore from the given directory (project root).
 *
 * Format — one entry per line:
 *   path/glob                     → suppress all findings in matching files
 *   path/glob:pattern-name        → suppress specific pattern in matching files
 *
 * Lines starting with # are comments.
 */
export function loadSuppressions(projectRoot: string = process.cwd()): Suppression[] {
  const file = path.join(projectRoot, ".rafterignore");
  if (!fs.existsSync(file)) return [];

  const suppressions: Suppression[] = [];
  try {
    const lines = fs.readFileSync(file, "utf-8").split("\n");
    for (const raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const colonIdx = line.indexOf(":");
      if (colonIdx === -1) {
        suppressions.push({ pathGlob: line, source: ".rafterignore" });
      } else {
        suppressions.push({
          pathGlob: line.slice(0, colonIdx).trim(),
          patternName: line.slice(colonIdx + 1).trim() || undefined,
          source: ".rafterignore",
        });
      }
    }
  } catch {
    // ignore unreadable .rafterignore
  }
  return suppressions;
}

/**
 * Convert .rafter.yml ignore rules into the flat Suppression list used at scan time.
 * Each entry's path globs cross-product with its rule names.
 */
export function policyIgnoreToSuppressions(rules: ScanIgnoreRule[] | undefined): Suppression[] {
  if (!rules || rules.length === 0) return [];
  const out: Suppression[] = [];
  for (const rule of rules) {
    if (!Array.isArray(rule.paths) || rule.paths.length === 0) continue;
    const ruleNames = Array.isArray(rule.rules) && rule.rules.length > 0 ? rule.rules : [undefined];
    for (const pathGlob of rule.paths) {
      for (const ruleName of ruleNames) {
        out.push({
          pathGlob,
          patternName: ruleName,
          reason: rule.reason,
          source: ".rafter.yml",
        });
      }
    }
  }
  return out;
}

/**
 * Find the first matching suppression for a finding, or null. First-match wins so
 * users can put more specific entries earlier and rely on stable precedence.
 */
export function findSuppression(
  filePath: string,
  patternName: string,
  suppressions: Suppression[]
): Suppression | null {
  for (const s of suppressions) {
    if (matchGlob(s.pathGlob, filePath)) {
      if (!s.patternName || s.patternName.toLowerCase() === patternName.toLowerCase()) {
        return s;
      }
    }
  }
  return null;
}

/**
 * Split scan results into kept matches and structured suppressed findings.
 * Used by the scan command for engine-agnostic suppression.
 */
export function applySuppressions<R extends { file: string; matches: PatternMatch[] }>(
  results: R[],
  suppressions: Suppression[],
): { results: R[]; suppressed: SuppressedFinding[] } {
  if (suppressions.length === 0) return { results, suppressed: [] };
  const suppressed: SuppressedFinding[] = [];
  const filtered: R[] = [];
  for (const r of results) {
    const kept: PatternMatch[] = [];
    for (const m of r.matches) {
      const hit = findSuppression(r.file, m.pattern.name, suppressions);
      if (hit) {
        suppressed.push({
          file: r.file,
          line: m.line ?? null,
          column: m.column ?? null,
          rule: m.pattern.name,
          severity: m.pattern.severity,
          reason: hit.reason ?? null,
          source: hit.source ?? ".rafterignore",
        });
      } else {
        kept.push(m);
      }
    }
    if (kept.length > 0) {
      filtered.push({ ...r, matches: kept });
    }
  }
  return { results: filtered, suppressed };
}

/**
 * Returns true if a finding should be suppressed.
 */
export function isSuppressed(
  filePath: string,
  patternName: string,
  suppressions: Suppression[]
): boolean {
  for (const s of suppressions) {
    if (matchGlob(s.pathGlob, filePath)) {
      if (!s.patternName || s.patternName.toLowerCase() === patternName.toLowerCase()) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Match a file path against a glob pattern using minimatch.
 *
 * Uses `matchBase` so bare patterns like "*.env" match against the basename
 * (e.g. "config/.env"), and `dot` so dotfiles are included. Also tries
 * matching the glob against any suffix of the path so that relative globs
 * like `tests/fixtures/**` match absolute paths under any project root.
 */
function matchGlob(glob: string, filePath: string): boolean {
  const g = glob.replace(/\\/g, "/");
  const f = filePath.replace(/\\/g, "/");
  if (minimatch(f, g, { dot: true, matchBase: true })) return true;
  // Auto-anchor relative globs to "anywhere in the path" so that `tests/**`
  // matches `/abs/project/tests/foo`. Skip if the user already anchored.
  if (g.startsWith("/") || g.startsWith("**/") || g.startsWith("**")) return false;
  return minimatch(f, "**/" + g, { dot: true });
}
