export interface Pattern {
  name: string;
  regex: string;
  severity: "low" | "medium" | "high" | "critical";
  description?: string;
}

export interface PatternMatch {
  pattern: Pattern;
  match: string;
  line?: number;
  column?: number;
  redacted?: string;
  /**
   * Which scan engine(s) surfaced this finding (sable-j85). Set only when a
   * scan runs more than one engine (`auto` mode → `both`). Single-engine
   * scans leave it undefined — the engine is already implied by `--engine`.
   */
  engines?: string[];
}

const GENERIC_PATTERN_NAMES = new Set(["Generic API Key", "Generic Secret"]);
const VARIABLE_NAME_RE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;
const LOWERCASE_IDENT_RE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;
const QUOTED_VALUE_RE = /['"]([^'"]+)['"]/;

/**
 * Matches an environment-assignment prefix in a command line: an identifier
 * followed immediately by `=` and a run of non-whitespace (the value). Used to
 * find `NAME=VALUE` tokens like `RAFTER_API_KEY=<secret> rafter ...` so their
 * value can be redacted before the command is written to the audit log.
 */
const ENV_ASSIGN_RE = /(^|\s)([A-Za-z_][A-Za-z0-9_]*)=(\S+)/g;

/**
 * A `NAME` in a `NAME=VALUE` assignment is treated as secret-bearing when it
 * ends in a credential-suggesting word (e.g. RAFTER_API_KEY, GITHUB_TOKEN,
 * DB_PASSWORD, AUTH). Values behind such names are redacted even when they
 * don't match any known secret pattern (that's the whole point — the value of
 * a bespoke API key won't match a built-in pattern, but it's still a secret).
 * Plain names like FOO or NODE_ENV do not match, so `FOO=bar` is left intact.
 */
const SECRET_ENV_NAME_RE = /(?:^|_)(KEY|TOKEN|SECRET|SECRETS|PASSWORD|PASSWD|PWD|API[_-]?KEY|ACCESS[_-]?KEY|CREDENTIALS?|AUTH)$/i;

export class PatternEngine {
  private patterns: Pattern[];

  constructor(patterns: Pattern[]) {
    this.patterns = patterns;
  }

  /**
   * Scan text for pattern matches
   */
  scan(text: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const pattern of this.patterns) {
      const regex = this.createRegex(pattern.regex);
      let match;

      while ((match = regex.exec(text)) !== null) {
        if (this.isFalsePositive(pattern, match[0])) continue;
        matches.push({
          pattern,
          match: match[0],
          redacted: this.redact(match[0])
        });
      }
    }

    return matches;
  }

  /**
   * Scan text with line/column information
   */
  scanWithPosition(text: string): PatternMatch[] {
    const matches: PatternMatch[] = [];
    const lines = text.split("\n");

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];

      for (const pattern of this.patterns) {
        const regex = this.createRegex(pattern.regex);
        let match;

        while ((match = regex.exec(line)) !== null) {
          if (this.isFalsePositive(pattern, match[0])) continue;
          matches.push({
            pattern,
            match: match[0],
            line: lineNum + 1,
            column: match.index + 1,
            redacted: this.redact(match[0])
          });
        }
      }
    }

    return matches;
  }

  /**
   * Redact text by replacing sensitive patterns.
   *
   * Two layers, both additive:
   *  1. Env-assignment redaction: any `NAME=VALUE` whose NAME looks
   *     secret-bearing has its VALUE masked, even if the VALUE matches no
   *     known pattern. This catches leaks like `RAFTER_API_KEY=<key> rafter …`
   *     in a logged command line, where the key's shape is unknown.
   *  2. Pattern-based redaction: values that match a built-in secret pattern
   *     are masked wherever they appear.
   */
  redactText(text: string): string {
    let redacted = this.redactEnvAssignments(text);

    for (const pattern of this.patterns) {
      const regex = this.createRegex(pattern.regex);
      redacted = redacted.replace(regex, (match) =>
        this.isFalsePositive(pattern, match) ? match : this.redact(match)
      );
    }

    return redacted;
  }

  /**
   * Mask the VALUE of every `NAME=VALUE` token whose NAME looks
   * secret-bearing. Non-secret names (FOO, NODE_ENV, …) are left untouched.
   */
  private redactEnvAssignments(text: string): string {
    return text.replace(ENV_ASSIGN_RE, (full, prefix: string, name: string, value: string) =>
      SECRET_ENV_NAME_RE.test(name) ? `${prefix}${name}=${this.redact(value)}` : full
    );
  }

  /**
   * Check if text contains any sensitive patterns
   */
  hasMatches(text: string): boolean {
    return this.scan(text).length > 0;
  }

  /**
   * Get patterns by severity
   */
  getPatternsBySeverity(severity: "low" | "medium" | "high" | "critical"): Pattern[] {
    return this.patterns.filter(p => p.severity === severity);
  }

  /**
   * Check if a match from a generic pattern looks like a variable name
   * rather than an actual secret value.
   */
  private isFalsePositive(pattern: Pattern, matchText: string): boolean {
    if (!GENERIC_PATTERN_NAMES.has(pattern.name)) return false;
    const m = QUOTED_VALUE_RE.exec(matchText);
    if (!m) return false;
    const value = m[1];
    if (VARIABLE_NAME_RE.test(value)) return true;
    if (LOWERCASE_IDENT_RE.test(value)) return true;
    return false;
  }

  /**
   * Create RegExp from pattern string, extracting inline flags
   */
  private createRegex(patternStr: string): RegExp {
    // Extract inline flags like (?i) and convert to JS flags
    let flags = "g";
    let pattern = patternStr;

    // Check for case-insensitive flag
    if (pattern.startsWith("(?i)")) {
      flags += "i";
      pattern = pattern.substring(4);
    }

    try {
      return new RegExp(pattern, flags);
    } catch (e) {
      // If pattern is invalid, return a regex that matches nothing
      console.error(`Invalid regex pattern: ${patternStr}`);
      return /(?!)/;
    }
  }

  /**
   * Redact a single match
   */
  private redact(match: string): string {
    if (match.length <= 8) {
      return "*".repeat(match.length);
    }
    // Show first 4 and last 4 chars, redact middle
    const visibleChars = 4;
    const start = match.substring(0, visibleChars);
    const end = match.substring(match.length - visibleChars);
    const middle = "*".repeat(match.length - (visibleChars * 2));
    return start + middle + end;
  }
}
