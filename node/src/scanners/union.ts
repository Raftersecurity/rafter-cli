import { ScanResult } from "./regex-scanner.js";
import { PatternMatch } from "../core/pattern-engine.js";

/**
 * Merge findings from the betterleaks and patterns engines into one result
 * set (sable-j85).
 *
 * `auto` mode now runs BOTH engines because each misses what the other
 * catches: betterleaks 1.1.x does not detect AWS access keys (sable-h2y),
 * while the regex patterns lack betterleaks's entropy/context heuristics.
 * Running only one silently degrades coverage; the union restores it.
 *
 * Dedup: two findings are "the same secret" when they share
 * `(file, line, column, matched-text)`. The key is deliberately conservative
 * — it errs toward keeping both findings rather than collapsing two genuinely
 * distinct secrets (e.g. the same token value pasted twice on one line at
 * different columns), because dropping a real finding is a security
 * regression for a scanner. The flip side: when the two engines extract
 * slightly different text/columns for the same secret it is reported twice
 * (once per engine) rather than merged — safe over-reporting, not a miss.
 * When both engines DO agree on `(line, column, text)` we keep the betterleaks
 * match — its `RuleID`-style `pattern.name` is the canonical id — and record
 * both engines in `engines`. Ordering is deterministic: betterleaks findings
 * first (in betterleaks's own order), then any patterns-only findings, grouped
 * by the file each first appeared in.
 */
export function unionScanResults(
  betterleaks: ScanResult[],
  patterns: ScanResult[],
): ScanResult[] {
  const fileOrder: string[] = [];
  const byFile = new Map<string, Map<string, PatternMatch>>();

  const ingest = (results: ScanResult[], engine: string): void => {
    for (const r of results) {
      let fileMap = byFile.get(r.file);
      if (!fileMap) {
        fileMap = new Map();
        byFile.set(r.file, fileMap);
        fileOrder.push(r.file);
      }
      for (const m of r.matches) {
        // `line` and `column` are always digits (or "?"), so the first two
        // spaces unambiguously delimit them from the matched secret — no key
        // collisions even when the secret itself contains spaces. Column is
        // part of the key so two distinct secrets sharing a line+text but
        // sitting at different columns are NOT collapsed.
        const key = `${m.line ?? "?"} ${m.column ?? "?"} ${m.match}`;
        const existing = fileMap.get(key);
        if (existing) {
          if (!existing.engines!.includes(engine)) existing.engines!.push(engine);
        } else {
          fileMap.set(key, { ...m, engines: [engine] });
        }
      }
    }
  };

  ingest(betterleaks, "betterleaks");
  ingest(patterns, "patterns");

  return fileOrder.map((file) => ({
    file,
    matches: Array.from(byFile.get(file)!.values()),
  }));
}
