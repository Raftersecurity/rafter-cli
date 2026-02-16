import fs from "fs";
import path from "path";
import { PatternEngine, PatternMatch, Pattern } from "../core/pattern-engine.js";
import { DEFAULT_SECRET_PATTERNS } from "./secret-patterns.js";

export interface ScanResult {
  file: string;
  matches: PatternMatch[];
}

export class RegexScanner {
  private engine: PatternEngine;

  constructor(customPatterns?: Array<{ name: string; regex: string; severity: string }>) {
    const patterns: Pattern[] = [...DEFAULT_SECRET_PATTERNS];
    if (customPatterns) {
      for (const cp of customPatterns) {
        patterns.push({
          name: cp.name,
          regex: cp.regex,
          severity: cp.severity as Pattern["severity"],
        });
      }
    }
    this.engine = new PatternEngine(patterns);
  }

  /**
   * Scan a single file for secrets
   */
  scanFile(filePath: string): ScanResult {
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      const matches = this.engine.scanWithPosition(content);

      return {
        file: filePath,
        matches
      };
    } catch (e) {
      // If file can't be read (binary, permissions, etc.), return empty matches
      return {
        file: filePath,
        matches: []
      };
    }
  }

  /**
   * Scan multiple files
   */
  scanFiles(filePaths: string[]): ScanResult[] {
    const results: ScanResult[] = [];

    for (const filePath of filePaths) {
      const result = this.scanFile(filePath);
      if (result.matches.length > 0) {
        results.push(result);
      }
    }

    return results;
  }

  /**
   * Scan a directory recursively
   */
  scanDirectory(dirPath: string, options?: {
    exclude?: string[];
    excludePaths?: string[];
    maxDepth?: number;
  }): ScanResult[] {
    const exclude = options?.exclude || [
      "node_modules",
      ".git",
      "dist",
      "build",
      ".next",
      "coverage",
      ".vscode",
      ".idea"
    ];

    // Merge policy excludePaths into the exclude list
    if (options?.excludePaths) {
      for (const ep of options.excludePaths) {
        // Strip trailing slashes for directory name matching
        const cleaned = ep.replace(/\/+$/, "");
        if (!exclude.includes(cleaned)) {
          exclude.push(cleaned);
        }
      }
    }

    const files = this.walkDirectory(dirPath, exclude, options?.maxDepth || 10);
    return this.scanFiles(files);
  }

  /**
   * Scan text content directly
   */
  scanText(text: string): PatternMatch[] {
    return this.engine.scan(text);
  }

  /**
   * Redact secrets from text
   */
  redact(text: string): string {
    return this.engine.redactText(text);
  }

  /**
   * Check if text contains secrets
   */
  hasSecrets(text: string): boolean {
    return this.engine.hasMatches(text);
  }

  /**
   * Walk directory and collect file paths
   */
  private walkDirectory(dir: string, exclude: string[], maxDepth: number, currentDepth = 0): string[] {
    if (currentDepth >= maxDepth) {
      return [];
    }

    const files: string[] = [];

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        // Skip excluded directories
        if (exclude.includes(entry.name)) {
          continue;
        }

        if (entry.isDirectory()) {
          files.push(...this.walkDirectory(fullPath, exclude, maxDepth, currentDepth + 1));
        } else if (entry.isFile()) {
          // Skip binary files by extension
          if (!this.isBinaryFile(entry.name)) {
            files.push(fullPath);
          }
        }
      }
    } catch (e) {
      // Skip directories we can't read
    }

    return files;
  }

  /**
   * Check if file is likely binary based on extension
   */
  private isBinaryFile(filename: string): boolean {
    const binaryExtensions = [
      ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
      ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
      ".zip", ".tar", ".gz", ".rar", ".7z",
      ".exe", ".dll", ".so", ".dylib",
      ".mp3", ".mp4", ".avi", ".mov",
      ".woff", ".woff2", ".ttf", ".eot",
      ".pyc", ".class", ".o", ".a"
    ];

    const ext = path.extname(filename).toLowerCase();
    return binaryExtensions.includes(ext);
  }
}
