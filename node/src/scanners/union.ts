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
 * `(file, line, column)`, or `(file, line, column, matched-text)` when the
 * position is unknown. Distinct secrets on one line (the same token pasted
 * twice) sit at different columns and are both kept, because dropping a real
 * finding is a security regression for a scanner. When both engines report a
 * position we keep the betterleaks
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
  // Carry a read failure through the union (sable-ilbx): a file one engine
  // could not open must still be reported as unreadable, not dropped.
  const readErrorByFile = new Map<string, string>();

  const ingest = (results: ScanResult[], engine: string): void => {
    for (const r of results) {
      let fileMap = byFile.get(r.file);
      if (!fileMap) {
        fileMap = new Map();
        byFile.set(r.file, fileMap);
        fileOrder.push(r.file);
      }
      if (r.readError && !readErrorByFile.has(r.file)) {
        readErrorByFile.set(r.file, r.readError);
      }
      for (const m of r.matches) {
        // Two secrets cannot start at the same line and column, so a known
        // position alone identifies the secret: the engines extract different
        // text for it (betterleaks a whole PEM block, the regex pattern only
        // its header). Without a position, fall back to the matched text.
        const key = m.line != null && m.column != null
          ? `${m.line} ${m.column}`
          : `${m.line ?? "?"} ${m.column ?? "?"} ${m.match}`;
        const existing = fileMap.get(key);
        if (existing) {
          if (!existing.engines!.includes(engine)) existing.engines!.push(engine);
          if (!existing.ruleNames!.includes(m.pattern.name)) existing.ruleNames!.push(m.pattern.name);
        } else {
          fileMap.set(key, { ...m, engines: [engine], ruleNames: [m.pattern.name] });
        }
      }
    }
  };

  ingest(betterleaks, "betterleaks");
  ingest(patterns, "patterns");

  return fileOrder.map((file) => {
    const out: ScanResult = {
      file,
      matches: Array.from(byFile.get(file)!.values()),
    };
    const readError = readErrorByFile.get(file);
    if (readError) out.readError = readError;
    return out;
  });
}
