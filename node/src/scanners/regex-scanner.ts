import { spawnSync } from "child_process";
import fs from "fs";
import path from "path";
import { PatternEngine, PatternMatch, Pattern } from "../core/pattern-engine.js";
import { DEFAULT_SECRET_PATTERNS } from "./secret-patterns.js";
import { loadCustomPatterns } from "../core/custom-patterns.js";

export interface ScanResult {
  file: string;
  matches: PatternMatch[];
}

export class RegexScanner {
  private engine: PatternEngine;

  constructor(customPatterns?: Array<{ name: string; regex: string; severity: string }>) {
    const patterns: Pattern[] = [...DEFAULT_SECRET_PATTERNS, ...loadCustomPatterns()];
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
   * Scan a single file for secrets. Suppression is applied at the scan
   * command boundary (engine-agnostic), not here.
   */
  scanFile(filePath: string): ScanResult {
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      const matches = this.engine.scanWithPosition(content);
      return { file: filePath, matches };
    } catch (e) {
      return { file: filePath, matches: [] };
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
    /**
     * Honor `.gitignore` (and `.git/info/exclude`, global excludes file,
     * nested .gitignores) when filtering scanned files. Default true.
     * Implemented by shelling out to `git check-ignore --stdin --no-index`
     * inside the scan root's git work tree — exact git semantics, zero deps.
     * Silently falls back to no-op when the scan root is outside a git repo
     * or git is missing.
     */
    respectGitignore?: boolean;
  }): ScanResult[] {
    const exclude = options?.exclude || [
      "node_modules",
      ".git",
      "dist",
      "build",
      ".next",
      "coverage",
      ".vscode",
      ".idea",
      // Vendored / virtual-env / generated dirs that cause false positives
      "vendor",
      ".venv",
      "venv",
      "__pycache__",
      ".tox",
      ".mypy_cache",
      ".pytest_cache",
      "results",
      ".terraform",
      "bower_components"
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
    const filtered = options?.respectGitignore === false
      ? files
      : filterGitIgnored(files, dirPath);
    return this.scanFiles(filtered);
  }

  /**
   * Scan text content directly
   */
  scanText(text: string): PatternMatch[] {
    return this.engine.scan(text);
  }

  /**
   * Scan a single line at a known file line number (git diff + side).
   */
  scanLine(text: string, lineNumber: number): PatternMatch[] {
    return this.engine.scanWithPosition(text).map((m) => ({
      ...m,
      line: lineNumber,
    }));
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
        // Skip symlinks to prevent traversal outside intended scope
        if (entry.isSymbolicLink()) {
          continue;
        }

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

/**
 * Filter out files that git would ignore relative to `scanRoot`.
 *
 * Uses `git check-ignore --stdin --no-index` inside the scan root's work
 * tree so every gitignore semantic git itself supports (nested .gitignores,
 * negations, .git/info/exclude, the configured global excludes file, the
 * `gitignore` pattern grammar) is honored exactly. Zero new dependencies —
 * if git isn't installed or the scan root sits outside a work tree, returns
 * the input unchanged.
 *
 * Batched: all candidate paths are piped through one subprocess.
 */
function filterGitIgnored(files: string[], scanRoot: string): string[] {
  if (files.length === 0) return files;

  // Locate the git work tree that owns scanRoot. Bail out (no filter) if
  // scanRoot is outside a repo or git is missing — the user's `rafter
  // secrets <dir>` invocation against a non-repo should not error.
  const probe = spawnSync("git", ["-C", scanRoot, "rev-parse", "--show-toplevel"], {
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 5000,
  });
  if (probe.status !== 0) return files;
  const workTree = probe.stdout.trim();
  if (!workTree) return files;

  // Send the candidate file list to `git check-ignore --stdin`. It echoes
  // back (on stdout) only the paths that match a gitignore rule. Use null
  // delimiters (`-z`) on input and output so paths with spaces, newlines, or
  // any other shell metacharacter survive intact. `--no-index` makes git
  // evaluate rules without consulting the index (so an untracked file in a
  // freshly-cloned repo is still classified).
  //
  // The paths in `files` are absolute. `git check-ignore` accepts paths
  // relative to the work tree OR absolute paths within it; we pass through
  // unchanged.
  const stdin = files.join("\0") + "\0";
  const result = spawnSync(
    "git",
    ["-C", workTree, "check-ignore", "--stdin", "--no-index", "-z"],
    {
      input: stdin,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"],
      timeout: 30_000,
      maxBuffer: 64 * 1024 * 1024,
    }
  );
  // Exit codes: 0 = at least one path matched; 1 = no paths matched;
  // 128 = error (corrupt repo, bad flag, etc.). Treat 128 as "no filter" so
  // a broken environment doesn't break a scan.
  if (result.status !== 0 && result.status !== 1) return files;

  const ignored = new Set<string>();
  if (result.stdout) {
    for (const p of result.stdout.split("\0")) {
      if (p) ignored.add(p);
    }
  }
  if (ignored.size === 0) return files;
  return files.filter((f) => !ignored.has(f));
}
