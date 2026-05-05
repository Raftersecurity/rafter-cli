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
      // Assignment-style: gate on credential keyword in the LHS identifier.
      // If the gate fails, the regex has already greedy-consumed the value
      // (which may contain a real inner credential assignment, e.g.
      // `--from-literal=DB_PASSWORD=...`). Reset lastIndex to right after
      // the LHS so the inner assignment can be re-tried.
      if (p.name === "Inline credential assignment") {
        const lhs = m[1] || "";
        if (!CREDENTIAL_KEYWORD_RE.test(lhs)) {
          re.lastIndex = m.index + lhs.length;
          continue;
        }
      }
      const rawValue = m[p.valueGroup];
      // Trim trailing sentence-ending punctuation that the regex value
      // class does not reject. Without this, prompts like
      // `(DB_PASSWORD=hunter2andmore)` capture `hunter2andmore)`.
      const value = rawValue ? rawValue.replace(/[.?!)\]}]+$/, "") : rawValue;
      if (!value || value.length < 6 || isLikelyPlaceholder(value)) {
        if (re.lastIndex === m.index) re.lastIndex++;
        continue;
      }
      // Assignment-style: drop identifier-shaped RHS values (rc-wk5).
      // LHS having a credential keyword is too weak a signal alone — devs
      // write `api_key_header_name=X-Api-Key`, `auth_token_type=opaque`,
      // `password_hash_algorithm=argon2id`. Reject the value if it looks
      // like a config token rather than a credential. See
      // looksLikeIdentifierConfig for the exact shape.
      if (p.name === "Inline credential assignment" && looksLikeIdentifierConfig(value)) {
        if (re.lastIndex === m.index) re.lastIndex++;
        continue;
      }
      const key = `${p.name}\x00${value}`;
      if (seen.has(key)) {
        if (re.lastIndex === m.index) re.lastIndex++;
        continue;
      }
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

// Placeholder values are filtered before persistence so the user doesn't end
// up with `.env` entries like `DB_PASSWORD=changeme`. Each rule is
// whole-string anchored so real secrets that happen to contain a
// placeholder substring (e.g. `Mxxx2024aB`, `example4Hunter2`) pass.
const PLACEHOLDER_LITERALS = new Set([
  "changeme", "change-me",
  "replace-me", "replaceme", "replace-this",
  "fixme", "placeholder", "redacted",
  "your-secret", "your_secret",
  "your-key", "your_key",
  "your-token", "your_token",
  "your-password", "your_password",
  "your-api-key", "your_api_key",
  "your-api-secret", "your_api_secret",
]);

function isLikelyPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  // `xxx`/`xxxx`/… as the *whole* value (with an optional suffix like
  // `-secret`/`_token`). The earlier substring rule dropped real-looking
  // values that happened to contain `xxx`, e.g. `Mxxx2024aB`.
  if (/^x{3,}([-_][a-z]+)?$/.test(lower)) return true;
  if (PLACEHOLDER_LITERALS.has(lower)) return true;
  if (/^<.+>$/.test(value)) return true;
  if (/^\$\{?[A-Z_][A-Z0-9_]*\}?$/.test(value)) return true;
  // `example` as a whole token, optionally with a credential-shape suffix
  // (`example-key`, `example_token`, `example-api-key`). The earlier prefix
  // rule dropped real values like `example4Hunter2!` or `examplezone-9`.
  if (/^example([-_]?(key|secret|token|value|password|placeholder|api[-_]?key|api[-_]?secret))?$/.test(lower)) return true;
  return false;
}

function freshRegex(re: RegExp): RegExp {
  return new RegExp(re.source, re.flags);
}

/**
 * RHS gate for "Inline credential assignment" (rc-wk5). True when the value
 * looks like a config token (header name, enum, algorithm name) rather than
 * a credential. Three conditions must all hold:
 *
 *   1. Identifier-shaped: starts with a letter, otherwise only [A-Za-z0-9_-].
 *      Values starting with a digit (e.g. `9abcdefghij`) or containing
 *      symbols (e.g. `p@ss!word#42`) are NOT identifier-shaped, so they pass.
 *   2. Length < 12. Real passwords ≥ 12 chars pass regardless of shape.
 *   3. ≤ 1 digit. Real passwords with embedded digits (`hunter2andmore`,
 *      `qwerty1234abcd`, even short `abc123`) usually have multiple digits;
 *      identifier-style names typically have at most one digit
 *      (`argon2id`, `pbkdf2`).
 */
function looksLikeIdentifierConfig(value: string): boolean {
  if (value.length >= 12) return false;
  if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(value)) return false;
  const digitCount = (value.match(/\d/g) || []).length;
  return digitCount <= 1;
}
