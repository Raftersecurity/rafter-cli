import { execFile } from "child_process";
import { promisify } from "util";
import { randomBytes } from "crypto";
import { BinaryManager } from "../utils/binary-manager.js";
import { PatternMatch } from "../core/pattern-engine.js";
import fs from "fs";
import os from "os";
import path from "path";

const execFileAsync = promisify(execFile);

interface GitleaksResult {
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  File: string;
  SymlinkFile: string;
  Commit: string;
  Entropy: number;
  Author: string;
  Email: string;
  Date: string;
  Message: string;
  Tags: string[];
  RuleID: string;
  Fingerprint: string;
}

export interface GitleaksScanResult {
  file: string;
  matches: PatternMatch[];
}

export class GitleaksScanner {
  private binaryManager: BinaryManager;

  constructor() {
    this.binaryManager = new BinaryManager();
  }

  /**
   * Check if Gitleaks is available
   */
  async isAvailable(): Promise<boolean> {
    if (!this.binaryManager.isGitleaksInstalled()) {
      return false;
    }
    return await this.binaryManager.verifyGitleaks();
  }

  /**
   * Scan a file with Gitleaks
   */
  async scanFile(filePath: string): Promise<GitleaksScanResult> {
    if (!await this.isAvailable()) {
      throw new Error("Gitleaks not available");
    }

    const gitleaksPath = this.binaryManager.getGitleaksPath();
    const tmpReport = path.join(os.tmpdir(), `gitleaks-${Date.now()}-${randomBytes(6).toString("hex")}.json`);

    try {
      // Run gitleaks detect on file
      await execFileAsync(
        gitleaksPath, ["detect", "--no-git", "-f", "json", "-r", tmpReport, "-s", filePath],
        { timeout: 30000 }
      );

      // If no leaks found, gitleaks exits 0 with empty report
      if (!fs.existsSync(tmpReport)) {
        return { file: filePath, matches: [] };
      }

      const results = this.parseResults(tmpReport);

      // Clean up report
      fs.unlinkSync(tmpReport);

      // Convert to our format
      return {
        file: filePath,
        matches: results.map(r => this.convertToPatternMatch(r))
      };
    } catch (e: any) {
      // Gitleaks exits with code 1 when leaks found — read report before cleanup
      if (e.code === 1 && fs.existsSync(tmpReport)) {
        const results = this.parseResults(tmpReport);
        fs.unlinkSync(tmpReport);

        return {
          file: filePath,
          matches: results.map(r => this.convertToPatternMatch(r))
        };
      }

      // Clean up report for non-leak errors
      if (fs.existsSync(tmpReport)) {
        fs.unlinkSync(tmpReport);
      }

      throw new Error(`Gitleaks scan failed: ${e.message}`);
    }
  }

  /**
   * Scan multiple files
   */
  async scanFiles(filePaths: string[]): Promise<GitleaksScanResult[]> {
    const results: GitleaksScanResult[] = [];

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
   * Scan a directory
   */
  async scanDirectory(dirPath: string): Promise<GitleaksScanResult[]> {
    if (!await this.isAvailable()) {
      throw new Error("Gitleaks not available");
    }

    const gitleaksPath = this.binaryManager.getGitleaksPath();
    const tmpReport = path.join(os.tmpdir(), `gitleaks-${Date.now()}-${randomBytes(6).toString("hex")}.json`);

    try {
      // Run gitleaks detect on directory
      await execFileAsync(
        gitleaksPath, ["detect", "--no-git", "-f", "json", "-r", tmpReport, "-s", dirPath],
        { timeout: 60000 }
      );

      // No leaks found
      if (!fs.existsSync(tmpReport)) {
        return [];
      }

      const results = this.parseResults(tmpReport);
      fs.unlinkSync(tmpReport);

      // Group by file
      return this.groupByFile(results);
    } catch (e: any) {
      // Clean up report
      if (fs.existsSync(tmpReport)) {
        const results = this.parseResults(tmpReport);
        fs.unlinkSync(tmpReport);

        // Gitleaks exits 1 when leaks found
        if (e.code === 1) {
          return this.groupByFile(results);
        }
      }

      throw new Error(`Gitleaks scan failed: ${e.message}`);
    }
  }

  /**
   * Parse Gitleaks JSON report
   */
  private parseResults(reportPath: string): GitleaksResult[] {
    try {
      const content = fs.readFileSync(reportPath, "utf-8");
      if (!content.trim()) {
        return [];
      }
      return JSON.parse(content);
    } catch {
      return [];
    }
  }

  /**
   * Convert Gitleaks result to our PatternMatch format
   */
  private convertToPatternMatch(result: GitleaksResult): PatternMatch {
    // Map Gitleaks severity to our levels
    const severity = this.getSeverity(result.RuleID, result.Tags);

    return {
      pattern: {
        name: result.RuleID || result.Description,
        regex: "", // Gitleaks doesn't expose the regex
        severity,
        description: result.Description
      },
      match: result.Secret || result.Match,
      line: result.StartLine,
      column: result.StartColumn,
      redacted: this.redact(result.Secret || result.Match)
    };
  }

  /**
   * Determine severity from Gitleaks rule ID and tags
   */
  private getSeverity(ruleID: string, tags: string[]): "low" | "medium" | "high" | "critical" {
    const lowerID = ruleID.toLowerCase();

    // Critical: Private keys, passwords, database credentials, access tokens
    if (lowerID.includes("private-key") ||
        lowerID.includes("password") ||
        lowerID.includes("database") ||
        lowerID.includes("access-token") ||
        lowerID.includes("secret-key") ||
        lowerID.includes("-pat") ||
        (tags.includes("key") && tags.includes("secret"))) {
      return "critical";
    }

    // High: API keys, generic tokens
    if (lowerID.includes("api-key") ||
        lowerID.includes("token") ||
        tags.includes("api")) {
      return "high";
    }

    // Medium: Generic secrets
    if (lowerID.includes("generic") ||
        tags.includes("generic")) {
      return "medium";
    }

    // Default to high for safety
    return "high";
  }

  /**
   * Redact a secret
   */
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

  /**
   * Group results by file
   */
  private groupByFile(results: GitleaksResult[]): GitleaksScanResult[] {
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
