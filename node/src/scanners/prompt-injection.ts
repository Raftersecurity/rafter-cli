/**
 * PromptInjectionDetector — EXPERIMENTAL.
 *
 * See docs/research/prompt-injection-detector.md for the full design,
 * threat model, and known limitations. Pattern-based, English-only,
 * trivially bypassable by paraphrase. Do not rely on this as a sole
 * line of defense.
 */

import {
  ALL_TEXT_PATTERNS,
  HIDDEN_UNICODE_RANGES,
  InjectionCategory,
  InjectionPattern,
  InjectionSeverity,
} from "./prompt-injection-patterns.js";

export interface InjectionFinding {
  category: InjectionCategory;
  severity: InjectionSeverity;
  pattern: string;
  evidence: string;
  offset: number;
  description: string;
}

export type InjectionVerdict = "clean" | "suspicious" | "likely_injection";

export interface InjectionScanResult {
  findings: InjectionFinding[];
  score: number;
  verdict: InjectionVerdict;
}

export interface InjectionScanOptions {
  /** Cap input length (chars) — default 1 MB. */
  maxLength?: number;
  /** Decode and re-scan base64 chunks ≥ this length. -1 to disable. Default 40. */
  base64MinLength?: number;
  /** Minimum severity to include. Default 'low'. */
  minSeverity?: InjectionSeverity;
}

const SEVERITY_WEIGHT: Record<InjectionSeverity, number> = {
  low: 5,
  medium: 15,
  high: 35,
  critical: 60,
};

const SEVERITY_RANK: Record<InjectionSeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

const DEFAULT_MAX_LENGTH = 1_000_000;
const DEFAULT_BASE64_MIN = 40;
const DECODED_CHUNK_CAP = 4096;
const EVIDENCE_WINDOW = 60;

const BASE64_CHUNK_RE = /[A-Za-z0-9+/]{40,}={0,2}/g;
const COMMON_DATA_URI_RE = /^data:[^;]+;base64,/i;

export class PromptInjectionDetector {
  private patterns: InjectionPattern[];

  constructor(patterns: InjectionPattern[] = ALL_TEXT_PATTERNS) {
    this.patterns = patterns;
  }

  scan(text: string, opts: InjectionScanOptions = {}): InjectionScanResult {
    const maxLength = opts.maxLength ?? DEFAULT_MAX_LENGTH;
    const base64Min = opts.base64MinLength ?? DEFAULT_BASE64_MIN;
    const minSeverity = opts.minSeverity ?? "low";
    const minRank = SEVERITY_RANK[minSeverity];

    const input = text.length > maxLength ? text.slice(0, maxLength) : text;
    const findings: InjectionFinding[] = [];

    this.scanTextPatterns(input, findings);
    this.scanHiddenUnicode(input, findings);
    if (base64Min > 0) {
      this.scanEncodedPayloads(input, base64Min, findings);
    }

    const filtered = findings.filter(f => SEVERITY_RANK[f.severity] >= minRank);
    const dedup = dedupeFindings(filtered);
    const score = aggregateScore(dedup);
    const verdict = scoreToVerdict(score);
    return { findings: dedup, score, verdict };
  }

  private scanTextPatterns(text: string, out: InjectionFinding[]): void {
    for (const p of this.patterns) {
      const re = p.regex.global ? p.regex : new RegExp(p.regex.source, p.regex.flags + "g");
      let m: RegExpExecArray | null;
      let safety = 0;
      while ((m = re.exec(text)) !== null) {
        if (safety++ > 100) break;
        const offset = m.index;
        out.push({
          category: p.category,
          severity: p.severity,
          pattern: p.name,
          evidence: snippet(text, offset, m[0].length),
          offset,
          description: p.description,
        });
        if (m[0].length === 0) re.lastIndex++;
      }
    }
  }

  private scanHiddenUnicode(text: string, out: InjectionFinding[]): void {
    // Walk codepoints. Track whether each suspect char sits inside a word
    // (between two letter/digit chars) — that's the high-signal case.
    let i = 0;
    const len = text.length;
    while (i < len) {
      const cp = text.codePointAt(i)!;
      const charLen = cp > 0xffff ? 2 : 1;

      for (const range of HIDDEN_UNICODE_RANGES) {
        if (!range.test(cp)) continue;

        if (range.name === "zero_width_in_word") {
          const prev = i > 0 ? text.codePointAt(i - 1) ?? 0 : 0;
          const next = i + charLen < len ? text.codePointAt(i + charLen) ?? 0 : 0;
          if (!isWordChar(prev) || !isWordChar(next)) {
            i += charLen;
            continue;
          }
        }

        out.push({
          category: "hidden_unicode",
          severity: range.severity,
          pattern: range.name,
          evidence: snippet(text, i, charLen),
          offset: i,
          description: `Hidden Unicode codepoint U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        });
        break;
      }

      i += charLen;
    }
  }

  private scanEncodedPayloads(text: string, minLen: number, out: InjectionFinding[]): void {
    const re = new RegExp(`[A-Za-z0-9+/]{${minLen},}={0,2}`, "g");
    let m: RegExpExecArray | null;
    let safety = 0;
    while ((m = re.exec(text)) !== null) {
      if (safety++ > 50) break;
      const chunk = m[0].slice(0, DECODED_CHUNK_CAP);
      // Skip data: URIs (image embeds, fonts) — common false-positive.
      const before = text.slice(Math.max(0, m.index - 24), m.index);
      if (COMMON_DATA_URI_RE.test(before + "...")) continue;
      let decoded: string;
      try {
        decoded = Buffer.from(chunk, "base64").toString("utf-8");
      } catch {
        continue;
      }
      // Skip obviously binary decodes — too many non-printables.
      if (!isMostlyPrintable(decoded)) continue;
      // Re-scan decoded text against text patterns; bubble up findings.
      const inner = new PromptInjectionDetector(this.patterns);
      const innerResult = inner.scan(decoded, { base64MinLength: -1 });
      for (const f of innerResult.findings) {
        out.push({
          category: "encoded_payload",
          severity: stepDownSeverity(f.severity),
          pattern: `base64_${f.pattern}`,
          evidence: snippet(text, m.index, Math.min(m[0].length, 40)),
          offset: m.index,
          description: `Decoded base64 contains ${f.pattern}: ${f.description}`,
        });
      }
    }
    void BASE64_CHUNK_RE; // silence unused; we build the regex with minLen above
  }
}

function snippet(text: string, offset: number, matchLen: number): string {
  const start = Math.max(0, offset - Math.floor((EVIDENCE_WINDOW - matchLen) / 2));
  const end = Math.min(text.length, start + EVIDENCE_WINDOW);
  return text.slice(start, end).replace(/\s+/g, " ").trim();
}

function isWordChar(cp: number): boolean {
  // ASCII letters/digits/underscore + common letter ranges. Cheap and good
  // enough for "is this zero-width inside a word?"
  if (cp === 0x5f) return true;
  if (cp >= 0x30 && cp <= 0x39) return true;
  if (cp >= 0x41 && cp <= 0x5a) return true;
  if (cp >= 0x61 && cp <= 0x7a) return true;
  // Latin-1, Latin-Extended-A
  if (cp >= 0xc0 && cp <= 0x024f) return true;
  return false;
}

function isMostlyPrintable(s: string): boolean {
  if (!s) return false;
  let printable = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++;
  }
  return printable / s.length > 0.85;
}

function stepDownSeverity(s: InjectionSeverity): InjectionSeverity {
  // Decoded findings are noisier; one notch lower than source severity.
  if (s === "critical") return "high";
  if (s === "high") return "medium";
  if (s === "medium") return "low";
  return "low";
}

function dedupeFindings(findings: InjectionFinding[]): InjectionFinding[] {
  const seen = new Set<string>();
  const out: InjectionFinding[] = [];
  for (const f of findings) {
    const key = `${f.category}:${f.pattern}:${f.offset}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

function aggregateScore(findings: InjectionFinding[]): number {
  let score = 0;
  for (const f of findings) score += SEVERITY_WEIGHT[f.severity];
  return Math.min(100, score);
}

function scoreToVerdict(score: number): InjectionVerdict {
  if (score >= 50) return "likely_injection";
  if (score >= 15) return "suspicious";
  return "clean";
}
