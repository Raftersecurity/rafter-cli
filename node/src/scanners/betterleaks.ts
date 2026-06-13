import { execFile } from "child_process";
import { promisify } from "util";
import { BinaryManager } from "../utils/binary-manager.js";
import { PatternMatch } from "../core/pattern-engine.js";
import fs from "fs";
import os from "os";
import path from "path";

const execFileAsync = promisify(execFile);

/**
 * Subset of betterleaks JSON report fields we actually consume.
 * Git-history-only fields (Commit, Author, Email, Date, Message) are absent
 * when scanning with the `dir` subcommand, so they're typed optional.
 */
interface BetterleaksResult {
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  File: string;
  SymlinkFile?: string;
  Commit?: string;
  Entropy?: number;
  Author?: string;
  Email?: string;
  Date?: string;
  Message?: string;
  Tags: string[];
  RuleID: string;
  Fingerprint?: string;
}

export interface BetterleaksScanResult {
  file: string;
  matches: PatternMatch[];
}

export class BetterleaksScanner {
  private binaryManager: BinaryManager;
  private resolvedPath: string | null = null;

  constructor() {
    this.binaryManager = new BinaryManager();
  }

  /**
   * Resolve the betterleaks binary to use. Prefer the rafter-managed binary at
   * ~/.rafter/bin/betterleaks; otherwise fall back to one on PATH (e.g. Homebrew).
   * Cached after first lookup.
   */
  private async resolveBinary(): Promise<string | null> {
    if (this.resolvedPath !== null) return this.resolvedPath || null;
    if (this.binaryManager.isBetterleaksInstalled()) {
      const managed = this.binaryManager.getBetterleaksPath();
      if (await this.binaryManager.verifyBetterleaks()) {
        this.resolvedPath = managed;
        return managed;
      }
    }
    const onPath = this.binaryManager.findBetterleaksOnPath();
    if (onPath) {
      const ok = await this.binaryManager.verifyBetterleaksVerbose(onPath);
      if (ok.ok) {
        this.resolvedPath = onPath;
        return onPath;
      }
    }
    this.resolvedPath = "";
    return null;
  }

  async isAvailable(): Promise<boolean> {
    return (await this.resolveBinary()) !== null;
  }

  /**
   * Scan a single file with Betterleaks (uses `dir` subcommand on a single path).
   */
  async scanFile(filePath: string): Promise<BetterleaksScanResult> {
    const blPath = await this.resolveBinary();
    if (!blPath) {
      throw new Error("Betterleaks not available");
    }

    // mkdtempSync atomically creates a private 0700 dir, so the report path
    // can't be pre-created/symlinked by another user on the shared tmpdir —
    // avoids the TOCTOU race a predictable Date.now() filename allowed (CWE-367).
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "betterleaks-"));
    const tmpReport = path.join(tmpDir, "report.json");

    try {
      // `--` ensures a target path beginning with `-` isn't parsed as a flag by betterleaks.
      await execFileAsync(
        blPath, ["dir", "-f", "json", "--report-path", tmpReport, "--", filePath],
        { timeout: 60000 }
      );

      if (!fs.existsSync(tmpReport)) {
        return { file: filePath, matches: [] };
      }

      const results = this.parseResults(tmpReport);

      return {
        file: filePath,
        matches: results.map(r => this.convertToPatternMatch(r))
      };
    } catch (e: any) {
      // Betterleaks exits with --exit-code (default 1) when leaks found — read report before cleanup
      if (e.code === 1 && fs.existsSync(tmpReport)) {
        const results = this.parseResults(tmpReport);

        return {
          file: filePath,
          matches: results.map(r => this.convertToPatternMatch(r))
        };
      }

      throw new Error(`Betterleaks scan failed: ${e.message}`);
    } finally {
      // Best-effort cleanup — a cleanup failure must never mask the scan's
      // real result or its original error.
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
  }

  async scanFiles(filePaths: string[]): Promise<BetterleaksScanResult[]> {
    const results: BetterleaksScanResult[] = [];

    for (const filePath of filePaths) {
      try {
        const result = await this.scanFile(filePath);
        if (result.matches.length > 0) {
          results.push(result);
        }
      } catch {
        // Skip files that can't be scanned
      }
    }

    return results;
  }

  /**
   * Scan a directory. With useGit=true, scans git history (`betterleaks git`);
   * otherwise scans the filesystem (`betterleaks dir`).
   */
  async scanDirectory(dirPath: string, opts?: { useGit?: boolean }): Promise<BetterleaksScanResult[]> {
    const blPath = await this.resolveBinary();
    if (!blPath) {
      throw new Error("Betterleaks not available");
    }

    // Private 0700 dir, atomically created — see scanFile for the TOCTOU rationale (CWE-367).
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "betterleaks-"));
    const tmpReport = path.join(tmpDir, "report.json");
    const subcommand = opts?.useGit ? "git" : "dir";

    try {
      // `--` ensures a target path beginning with `-` isn't parsed as a flag by betterleaks.
      await execFileAsync(
        blPath, [subcommand, "-f", "json", "--report-path", tmpReport, "--", dirPath],
        { timeout: 60000 }
      );

      if (!fs.existsSync(tmpReport)) {
        return [];
      }

      const results = this.parseResults(tmpReport);

      return this.groupByFile(results);
    } catch (e: any) {
      if (fs.existsSync(tmpReport)) {
        const results = this.parseResults(tmpReport);

        if (e.code === 1) {
          return this.groupByFile(results);
        }
      }

      throw new Error(`Betterleaks scan failed: ${e.message}`);
    } finally {
      // Best-effort cleanup — a cleanup failure must never mask the scan's
      // real result or its original error.
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
  }

  private parseResults(reportPath: string): BetterleaksResult[] {
    try {
      const content = fs.readFileSync(reportPath, "utf-8");
      if (!content.trim()) {
        return [];
      }
      const parsed = JSON.parse(content);
      if (!Array.isArray(parsed)) {
        // sable-o4k — a stale/incompatible binary emits a non-array shape and
        // would otherwise silently yield zero findings. The managed binary is
        // auto-updated upstream; this covers a stale binary on PATH, which we
        // can't safely overwrite — so point the user at the fix.
        console.error("[rafter] Warning: Betterleaks output is not an array — possible version mismatch. Run: rafter agent update-betterleaks");
        return [];
      }
      return parsed;
    } catch (e) {
      console.error(`[rafter] Warning: Failed to parse Betterleaks report: ${e instanceof Error ? e.message : e}`);
      return [];
    }
  }

  private convertToPatternMatch(result: BetterleaksResult): PatternMatch {
    const severity = this.getSeverity(result.RuleID, result.Tags);

    return {
      pattern: {
        name: result.RuleID || result.Description,
        regex: "",
        severity,
        description: result.Description
      },
      match: result.Secret || result.Match,
      line: result.StartLine,
      column: result.StartColumn,
      redacted: this.redact(result.Secret || result.Match)
    };
  }

  private getSeverity(ruleID: string, tags: string[]): "low" | "medium" | "high" | "critical" {
    const lowerID = ruleID.toLowerCase();

    if (lowerID.includes("private-key") ||
        lowerID.includes("password") ||
        lowerID.includes("database") ||
        lowerID.includes("access-token") ||
        lowerID.includes("secret-key") ||
        lowerID.endsWith("-pat") ||
        (tags.includes("key") && tags.includes("secret"))) {
      return "critical";
    }

    if (lowerID.includes("api-key") ||
        lowerID.includes("-token") ||
        lowerID.startsWith("token-") ||
        tags.includes("api")) {
      return "high";
    }

    if (lowerID.includes("generic") ||
        tags.includes("generic")) {
      return "medium";
    }

    return "high";
  }

  private redact(match: string): string {
    if (match.length <= 8) {
      return "*".repeat(match.length);
    }
    const visibleChars = 4;
    const start = match.substring(0, visibleChars);
    const end = match.substring(match.length - visibleChars);
    const middle = "*".repeat(match.length - (visibleChars * 2));
    return start + middle + end;
  }

  private groupByFile(results: BetterleaksResult[]): BetterleaksScanResult[] {
    const grouped = new Map<string, PatternMatch[]>();

    for (const result of results) {
      const file = result.File;
      if (!grouped.has(file)) {
        grouped.set(file, []);
      }
      grouped.get(file)!.push(this.convertToPatternMatch(result));
    }

    return Array.from(grouped.entries()).map(([file, matches]) => ({
      file,
      matches
    }));
  }
}
