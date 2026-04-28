/**
 * Shared prompt-shield detection + rewriting helpers used by:
 *   - rafter hook user-prompt-submit (Claude Code, Codex)
 *   - rafter hook before-model       (Gemini CLI — full body rewrite)
 *
 * Keep this pure: no I/O, no env-writer calls. Callers are responsible for
 * persistence so they can share .env state across multiple text fields in a
 * single hook invocation.
 */

import { RegexScanner } from "../scanners/regex-scanner.js";
import {
  PROMPT_SHIELD_PATTERNS,
  PromptShieldPattern,
  DEFAULT_PATTERN_ENV_NAMES,
  CREDENTIAL_KEYWORD_RE,
} from "../scanners/prompt-shield-patterns.js";

export interface DetectedSecret {
  /** Pattern name for audit / display. */
  patternName: string;
  /** Suggested env var basename. */
  envBaseName: string;
  /** The actual secret value to persist. */
  value: string;
}

/**
 * Run all prompt-shield + default-secret patterns against `text`, returning
 * one DetectedSecret per unique (pattern, value) pair. Skips obvious
 * placeholders (e.g. `<your-key>`).
 */
export function detectSecrets(text: string): DetectedSecret[] {
  if (!text) return [];
  const seen = new Set<string>();
  const out: DetectedSecret[] = [];

  // 1. Prompt-shield patterns (capture-group aware)
  for (const p of PROMPT_SHIELD_PATTERNS) {
    const re = freshRegex(p.regex);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const value = m[p.valueGroup];
      if (!value || isLikelyPlaceholder(value)) continue;
      // Assignment-style: gate on credential keyword in the LHS identifier.
      if (p.name === "Inline credential assignment") {
        const lhs = m[1] || "";
        if (!CREDENTIAL_KEYWORD_RE.test(lhs)) continue;
      }
      const key = `${p.name}\x00${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        patternName: p.name,
        envBaseName: deriveEnvName(p, m),
        value,
      });
      if (re.lastIndex === m.index) re.lastIndex++;
    }
  }

  // 2. Default secret patterns (full match = value)
  const scanner = new RegexScanner();
  for (const match of scanner.scanText(text)) {
    const value = match.match;
    if (!value || isLikelyPlaceholder(value)) continue;
    const baseName = DEFAULT_PATTERN_ENV_NAMES[match.pattern.name] || "RAFTER_SECRET";
    const key = `${match.pattern.name}\x00${value}`;
    if (seen.has(key)) continue;
    // Skip if a prompt-shield pattern already captured this exact value.
    if (out.some((prior) => prior.value === value)) continue;
    seen.add(key);
    out.push({ patternName: match.pattern.name, envBaseName: baseName, value });
  }

  return out;
}

/**
 * Replace each detected secret literal in `text` with `$<name>` (the env-var
 * reference shape). Longest values first so substring overlaps don't break
 * shorter values mid-substitution.
 */
export function replaceSecretsWithRefs(
  text: string,
  detected: DetectedSecret[],
  valueToName: Map<string, string>
): string {
  if (!text || detected.length === 0) return text;
  const ordered = [...detected].sort((a, b) => b.value.length - a.value.length);
  let out = text;
  for (const d of ordered) {
    const name = valueToName.get(d.value);
    if (!name) continue;
    out = splitAndJoin(out, d.value, `$${name}`);
  }
  return out;
}

/** Plain-string replace-all without regex special-char escaping. */
function splitAndJoin(haystack: string, needle: string, replacement: string): string {
  if (!needle) return haystack;
  return haystack.split(needle).join(replacement);
}

function deriveEnvName(p: PromptShieldPattern, m: RegExpExecArray): string {
  if (p.name === "Inline credential assignment" && m[1]) return m[1];
  return p.envBaseName;
}

function isLikelyPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  if (lower.includes("xxx") && lower.length < 16) return true;
  if (lower === "your-secret" || lower === "your_secret") return true;
  if (lower === "changeme" || lower === "change-me") return true;
  if (/^<.+>$/.test(value)) return true;
  if (/^\$\{?[A-Z_][A-Z0-9_]*\}?$/.test(value)) return true;
  if (/^example/.test(lower)) return true;
  return false;
}

function freshRegex(re: RegExp): RegExp {
  return new RegExp(re.source, re.flags);
}
