/**
 * Load custom secret patterns from ~/.rafter/patterns/
 * and suppression rules from .rafterignore.
 */

import fs from "fs";
import path from "path";
import { Pattern } from "./pattern-engine.js";
import { getRafterDir } from "./config-defaults.js";

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
      if (typeof entry.pattern !== "string") continue;
      patterns.push({
        name: entry.name ?? `Custom (${path.basename(file, ".json")})`,
        regex: entry.pattern,
        severity: (entry.severity as Pattern["severity"]) ?? "high",
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
        suppressions.push({ pathGlob: line });
      } else {
        suppressions.push({
          pathGlob: line.slice(0, colonIdx).trim(),
          patternName: line.slice(colonIdx + 1).trim() || undefined,
        });
      }
    }
  } catch {
    // ignore unreadable .rafterignore
  }
  return suppressions;
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
 * Minimal glob matcher: supports * (within segment) and ** (cross-segment).
 * Not full micromatch — covers the 90% case for .rafterignore.
 */
function matchGlob(glob: string, filePath: string): boolean {
  // Normalise separators
  const g = glob.replace(/\\/g, "/");
  const f = filePath.replace(/\\/g, "/");

  // Escape regex special chars except * which we handle specially
  const escaped = g
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\x00") // placeholder for **
    .replace(/\*/g, "[^/]*")  // * = anything within one segment
    .replace(/\x00/g, ".*");  // ** = anything including /

  try {
    return new RegExp(`(^|/)${escaped}(/|$)`).test(f);
  } catch {
    return false;
  }
}
