import { execFile, spawnSync } from "child_process";
import { promisify } from "util";
import { BinaryManager } from "../utils/binary-manager.js";
import { PatternMatch } from "../core/pattern-engine.js";
import fs from "fs";
import os from "os";
import path from "path";

const execFileAsync = promisify(execFile);

/** Per-invocation timeout for the betterleaks subprocess. */
const SCAN_TIMEOUT_MS = 60_000;

/**
 * Budget for the path arguments of one `betterleaks dir` call. Windows caps a
 * whole command line at 32,767 characters; elsewhere the limit is far larger.
 */
const ARG_CHARS_PER_CALL = process.platform === "win32" ? 24_000 : 500_000;

/** Config env vars betterleaks consults before the target's own .toml. */
const CONFIG_ENV_VARS = [
  "BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML",
];

/**
 * Files under `dirPath` that git does not ignore (tracked, plus untracked and
 * not ignored), as absolute paths. Returns null when `dirPath` is not inside a
 * git work tree or git is unavailable, so the caller scans the directory whole.
 */
export function gitVisibleFiles(dirPath: string): string[] | null {
  const r = spawnSync(
    "git",
    ["-C", dirPath, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "."],
    { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"], timeout: 30_000, maxBuffer: 256 * 1024 * 1024 },
  );
  if (r.status !== 0 || typeof r.stdout !== "string") return null;
  const files = new Set<string>();
  for (const rel of r.stdout.split("\0")) {
    if (!rel) continue;
    const abs = path.join(dirPath, rel);
    try {
      // Skip deleted-but-tracked paths, submodule dirs and symlinks (betterleaks
      // does not follow symlinks by default either).
      if (fs.lstatSync(abs).isFile()) files.add(abs);
    } catch {
      // deleted from the work tree
    }
  }
  return [...files];
}

/** Split `paths` into groups whose joined length stays under `budget` chars. */
function chunkByLength(paths: string[], budget: number): string[][] {
  const chunks: string[][] = [];
  let cur: string[] = [];
  let len = 0;
  for (const p of paths) {
    if (cur.length > 0 && len + p.length + 1 > budget) {
      chunks.push(cur);
      cur = [];
      len = 0;
    }
    cur.push(p);
    len += p.length + 1;
  }
  if (cur.length > 0) chunks.push(cur);
  return chunks;
}

/** Name why a betterleaks subprocess failed: a timeout reads differently from a crash. */
function describeFailure(e: any): string {
  if (e?.killed && e?.signal) return `timed out after ${SCAN_TIMEOUT_MS / 1000}s`;
  if (typeof e?.code === "number") return `exit ${e.code}`;
  return e?.message ?? String(e);
}

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
        { timeout: SCAN_TIMEOUT_MS }
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
   *
   * `betterleaks dir` has no notion of .gitignore, so given a directory it
   * walks node_modules, build output and local secret stores (.env) alike:
   * slow enough to hit the timeout on an ordinary checkout, and noisy (#262).
   * With respectGitignore (the default, matching the patterns engine) and a
   * target inside a git work tree, it is handed git's own list of non-ignored
   * files instead.
   */
  async scanDirectory(
    dirPath: string,
    opts?: { useGit?: boolean; respectGitignore?: boolean },
  ): Promise<BetterleaksScanResult[]> {
    const blPath = await this.resolveBinary();
    if (!blPath) {
      throw new Error("Betterleaks not available");
    }

    if (opts?.useGit) {
      return this.groupByFile(await this.runDir(blPath, "git", [dirPath], []));
    }

    const files = opts?.respectGitignore === false ? null : gitVisibleFiles(dirPath);
    if (files === null) {
      return this.groupByFile(await this.runDir(blPath, "dir", [dirPath], []));
    }

    // Given file paths instead of a directory, betterleaks no longer finds the
    // target's own .betterleaks.toml / .gitleaks.toml, so pass it explicitly
    // unless an env var already chooses the config (it outranks the file).
    const configArgs: string[] = [];
    if (!CONFIG_ENV_VARS.some((v) => process.env[v])) {
      const cfg = [".betterleaks.toml", ".gitleaks.toml"]
        .map((n) => path.join(dirPath, n))
        .find((p) => fs.existsSync(p));
      if (cfg) configArgs.push("-c", cfg);
    }

    const findings: BetterleaksResult[] = [];
    for (const chunk of chunkByLength(files, ARG_CHARS_PER_CALL)) {
      findings.push(...(await this.runDir(blPath, "dir", chunk, configArgs)));
    }
    return this.groupByFile(findings);
  }

  /** One betterleaks invocation; returns its findings or throws with the cause. */
  private async runDir(
    blPath: string,
    subcommand: "dir" | "git",
    targets: string[],
    extraArgs: string[],
  ): Promise<BetterleaksResult[]> {
    // Private 0700 dir, atomically created — see scanFile for the TOCTOU rationale (CWE-367).
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "betterleaks-"));
    const tmpReport = path.join(tmpDir, "report.json");

    try {
      // `--` ensures a target path beginning with `-` isn't parsed as a flag by betterleaks.
      await execFileAsync(
        blPath,
        [subcommand, ...extraArgs, "-f", "json", "--report-path", tmpReport, "--", ...targets],
        { timeout: SCAN_TIMEOUT_MS, maxBuffer: 64 * 1024 * 1024 }
      );

      if (!fs.existsSync(tmpReport)) {
        return [];
      }
      return this.parseResults(tmpReport);
    } catch (e: any) {
      if (e.code === 1 && fs.existsSync(tmpReport)) {
        return this.parseResults(tmpReport);
      }

      throw new Error(`Betterleaks scan failed (${describeFailure(e)})`);
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
      // #217 — betterleaks >=1.1.2 writes the literal `null` (not `[]`) for a
      // clean scan via the `dir`/`git` subcommands we invoke. That is a valid
      // empty result, not a version mismatch, so it must not reach the warning
      // branch below — otherwise every clean file scanned emits warning noise.
      if (parsed === null) {
        return [];
      }
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
