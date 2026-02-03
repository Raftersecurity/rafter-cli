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

    for (const pattern of this.patterns) {
      const regex = this.createRegex(pattern.regex);
      redacted = redacted.replace(regex, (match) => this.redact(match));
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
