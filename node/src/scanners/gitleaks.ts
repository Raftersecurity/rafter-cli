import { execFile } from "child_process";
import { promisify } from "util";
import { randomBytes } from "crypto";
import { BinaryManager } from "../utils/binary-manager.js";
import { PatternMatch, fingerprintFor } from "../core/pattern-engine.js";
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
  async scanDirectory(dirPath: string, opts?: { useGit?: boolean }): Promise<GitleaksScanResult[]> {
    if (!await this.isAvailable()) {
      throw new Error("Gitleaks not available");
    }

    const gitleaksPath = this.binaryManager.getGitleaksPath();
    const tmpReport = path.join(os.tmpdir(), `gitleaks-${Date.now()}-${randomBytes(6).toString("hex")}.json`);

    try {
      const args = ["detect", "-f", "json", "-r", tmpReport, "-s", dirPath];
      if (!opts?.useGit) {
        args.splice(1, 0, "--no-git");
      }
      // Run gitleaks detect on directory
      await execFileAsync(
        gitleaksPath, args,
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
      const parsed = JSON.parse(content);
      if (!Array.isArray(parsed)) {
        console.error("[rafter] Warning: Gitleaks output is not an array — possible version mismatch");
        return [];
      }
      return parsed;
    } catch (e) {
      console.error(`[rafter] Warning: Failed to parse Gitleaks report: ${e instanceof Error ? e.message : e}`);
      return [];
    }
  }

  /**
   * Convert Gitleaks result to our PatternMatch format
   */
  private convertToPatternMatch(result: GitleaksResult): PatternMatch {
    // Map Gitleaks severity to our levels
    const severity = this.getSeverity(result.RuleID, result.Tags);
    const confidence = this.getConfidence(result.RuleID, result.Entropy);
    const remediation = this.getRemediation(result.RuleID, result.Tags);
    const secret = result.Secret || result.Match;
    const redacted = this.redact(secret);

    return {
      pattern: {
        name: result.RuleID || result.Description,
        regex: "", // Gitleaks doesn't expose the regex
        severity,
        confidence,
        description: result.Description,
        remediation,
      },
      match: secret,
      line: result.StartLine,
      column: result.StartColumn,
      redacted,
      entropy: result.Entropy,
      // Always compute our own stable hash; Gitleaks's Fingerprint format is
      // `<file>:<rule>:<line>` which leaks path data and isn't a hash.
      fingerprint: fingerprintFor(result.File || "", result.RuleID || result.Description, redacted),
    };
  }

  /**
   * Confidence tier based on Gitleaks rule ID + entropy
   */
  private getConfidence(ruleID: string, entropy: number): "low" | "medium" | "high" {
    const id = (ruleID || "").toLowerCase();
    if (id.includes("generic") || id.startsWith("token-")) {
      if (entropy >= 4.5) return "medium";
      return "low";
    }
    return "high";
  }

  /**
   * Remediation suggestion based on Gitleaks rule ID + tags
   */
  private getRemediation(ruleID: string, tags: string[]): string {
    const id = (ruleID || "").toLowerCase();
    const t = tags.map(x => x.toLowerCase());
    if (id.includes("private-key") || t.includes("private-key")) {
      return "Generate a new keypair, deploy the new public key, and revoke the old one. Never commit private keys; use ssh-agent or a KMS for storage.";
    }
    if (id.includes("aws") || id.includes("gcp") || id.includes("azure")) {
      return "Rotate the credential in the provider's console immediately. Reference via env var or a secret manager. Git history retains the secret — rotation is mandatory.";
    }
    if (id.includes("database") || id.includes("postgres") || id.includes("mysql") || id.includes("mongo")) {
      return "Rotate database credentials immediately. Reference via env var or a secret manager. Audit access logs for unauthorized use.";
    }
    if (id.includes("jwt")) {
      return "If real, rotate the JWT signing key — every token signed with the old key is now untrusted. If example/test data, move to a fixture not committed to git.";
    }
    return "Revoke the credential at the issuer, generate a new one, and reference via env var or secret manager. Git history retains the secret — rotation is mandatory.";
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
        lowerID.endsWith("-pat") ||
        (tags.includes("key") && tags.includes("secret"))) {
      return "critical";
    }

    // High: API keys, generic tokens
    if (lowerID.includes("api-key") ||
        lowerID.includes("-token") ||
        lowerID.startsWith("token-") ||
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
