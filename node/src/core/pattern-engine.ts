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
}

const GENERIC_PATTERN_NAMES = new Set(["Generic API Key", "Generic Secret"]);
const VARIABLE_NAME_RE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;
const LOWERCASE_IDENT_RE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;
const QUOTED_VALUE_RE = /['"]([^'"]+)['"]/;

interface CompiledPattern {
  pattern: Pattern;
  regex: RegExp;
}

export class PatternEngine {
  private patterns: Pattern[];
  private compiled: CompiledPattern[];

  constructor(patterns: Pattern[]) {
    this.patterns = patterns;
    // Compile each pattern's regex once. Malformed patterns are skipped
    // with a stderr warning so a single bad regex can't take down the engine.
    this.compiled = [];
    for (const pattern of patterns) {
      const regex = this.createRegex(pattern.regex);
      if (regex === null) continue;
      this.compiled.push({ pattern, regex });
    }
  }

  /**
   * Scan text for pattern matches
   */
  scan(text: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const { pattern, regex } of this.compiled) {
      regex.lastIndex = 0;
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

      for (const { pattern, regex } of this.compiled) {
        regex.lastIndex = 0;
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
   * Redact text by replacing sensitive patterns
   */
  redactText(text: string): string {
    let redacted = text;

    for (const { pattern, regex } of this.compiled) {
      regex.lastIndex = 0;
      redacted = redacted.replace(regex, (match) =>
        this.isFalsePositive(pattern, match) ? match : this.redact(match)
      );
    }

    return redacted;
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
   * Create RegExp from pattern string, extracting inline flags.
   * Returns null if the pattern is malformed (logs a warning).
   */
  private createRegex(patternStr: string): RegExp | null {
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
      // Skip malformed patterns rather than crashing the engine
      console.error(`Invalid regex pattern: ${patternStr}`);
      return null;
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
