import path from "path";
import { AddedDiffLine } from "../utils/git-diff.js";
import { RegexScanner, ScanResult } from "./regex-scanner.js";

/**
 * Scan only added/modified lines from a parsed git diff (+ side).
 * Uses the patterns engine — git line scope is incompatible with betterleaks'
 * whole-file `dir` scan (same as the PreToolUse staged hook).
 */
export function scanAddedDiffLines(
  addedLines: AddedDiffLine[],
  repoRoot: string,
  customPatterns?: Array<{ name: string; regex: string; severity: string }>,
): ScanResult[] {
  if (addedLines.length === 0) return [];

  const scanner = new RegexScanner(customPatterns);
  const byFile = new Map<string, ScanResult["matches"]>();

  for (const { file, line, text } of addedLines) {
    const absPath = path.resolve(repoRoot, file);
    const matches = scanner.scanLine(text, line);
    if (matches.length === 0) continue;
    const existing = byFile.get(absPath) ?? [];
    existing.push(...matches);
    byFile.set(absPath, existing);
  }

  return [...byFile.entries()].map(([file, matches]) => ({ file, matches }));
}
