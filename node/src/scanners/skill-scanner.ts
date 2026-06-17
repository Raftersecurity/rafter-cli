/**
 * Optional DEEP skill-review engine — wraps the external `skill-scanner` CLI.
 *
 * Parity with `python/rafter_cli/scanners/skill_scanner.py` (bead sable-7g7).
 * This is the **couple, don't swap** integration: the zero-dependency
 * deterministic quick scan stays the default for `rafter agent audit-skill`;
 * passing `--deep` shells out to Cisco AI Defense's `skill-scanner`
 * (pip: `cisco-ai-skill-scanner`) for a deeper pass covering prompt injection,
 * taint/dataflow, YARA and .pyc integrity — the blind spots the regex quick
 * scan cannot see.
 *
 * Design mirrors `betterleaks.ts`: an external tool both runtimes shell out to
 * and whose JSON we parse. Critically, we invoke **only the offline/static
 * default analyzers** (static + bytecode + pipeline). We never pass
 * `--use-llm`, `--use-virustotal`, `--use-aidefense` or `--use-behavioral`, so
 * nothing leaves the machine — preserving Rafter's offline / no-telemetry
 * promise. The FORBIDDEN_FLAGS invariant is asserted by the vitest suite.
 *
 * Observed `skill-scanner` version: 2.0.11.
 */
import { execFile, execSync } from "child_process";
import { promisify } from "util";
import path from "path";
import fs from "fs";
import { askYesNo } from "../utils/prompt.js";

const execFileAsync = promisify(execFile);

/** PyPI package providing the external CLI, and the version we pin (mirrors
 * SKILL_SCANNER_VERSION in the Python side / BETTERLEAKS_VERSION). */
export const SKILL_SCANNER_PACKAGE = "cisco-ai-skill-scanner";
export const SKILL_SCANNER_VERSION = "2.0.11";

/** skill-scanner severity (UPPERCASE) -> our tier (lowercase). skill-scanner
 * also emits INFO, mapped to "low" (informational, e.g. missing-license). */
const SEVERITY_MAP: Record<string, string> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "low",
};

/** Severities that count as actionable findings for exit-code purposes.
 * INFO/low policy hints do NOT flip the exit code (matches the quick scan). */
const FINDING_SEVERITIES = new Set(["critical", "high", "medium"]);

/** Network/LLM/cloud flags that must NEVER appear in our argv. Enforced by a
 * test so a regression that flips on a remote analyzer fails the suite. */
export const FORBIDDEN_FLAGS = [
  "--use-llm",
  "--use-virustotal",
  "--use-aidefense",
  "--use-behavioral",
  "--vt-api-key",
  "--aidefense-api-key",
];

export const INSTALL_HINT =
  "skill-scanner not found. The --deep engine requires Cisco AI Defense's " +
  "skill-scanner. Install it with the managed installer:\n" +
  "    rafter agent update-skill-scanner\n" +
  "  (or manually: uv tool install cisco-ai-skill-scanner)\n" +
  "Then re-run with --deep.";

export interface DeepFinding {
  ruleId: string;
  severity: string; // our tier: critical/high/medium/low
  category: string;
  title: string;
  description: string;
  file: string | null;
  line: number | null;
  snippet: string | null;
  analyzer: string;
}

export interface DeepScanResult {
  available: boolean;
  findings: DeepFinding[];
  maxSeverity: string | null;
  analyzersUsed: string[];
  error: string;
  raw: Record<string, unknown> | null;
}

export function hasFindings(result: DeepScanResult): boolean {
  return result.findings.some((f) => FINDING_SEVERITIES.has(f.severity));
}

interface BuildArgvOpts {
  skillFile?: string | null;
  lenient?: boolean;
}

export class SkillScanner {
  private resolvedPath: string | null = null;

  /** Locate the `skill-scanner` launcher on PATH (uv tool / pip --user both
   * place it there). Cached after first lookup. */
  private resolvePath(): string | null {
    if (this.resolvedPath !== null) return this.resolvedPath || null;
    const cmd =
      process.platform === "win32" ? "where skill-scanner" : "which skill-scanner";
    try {
      const result = execSync(cmd, { timeout: 5000, encoding: "utf-8" });
      const found = result.trim().split("\n")[0].trim();
      this.resolvedPath = found || "";
      return found || null;
    } catch {
      this.resolvedPath = "";
      return null;
    }
  }

  isAvailable(): boolean {
    return this.resolvePath() !== null;
  }

  /**
   * Construct the OFFLINE-SAFE argv for a skill-scanner scan.
   *
   * Guarantees (asserted by tests): no flag in FORBIDDEN_FLAGS is ever added,
   * so only the default static/bytecode/pipeline analyzers run, all offline.
   * `--format json` for a machine-parseable object; `--fail-on-severity medium`
   * so the exit code reflects findings (skill-scanner otherwise exits 0 even on
   * CRITICAL).
   */
  static buildArgv(targetDir: string, opts: BuildArgvOpts = {}): string[] {
    const argv = [
      "scan",
      targetDir,
      "--format",
      "json",
      "--fail-on-severity",
      "medium",
    ];
    if (opts.skillFile) {
      argv.push("--skill-file", opts.skillFile);
    }
    if (opts.lenient) {
      argv.push("--lenient");
    }
    return argv;
  }

  /**
   * Run an offline deep scan for a skill file or directory. skill-scanner only
   * scans a *directory*, so when given a file we scan its parent directory and
   * point --skill-file at the filename (plus --lenient for robustness).
   */
  async scanPath(skillPath: string): Promise<DeepScanResult> {
    const binary = this.resolvePath();
    if (!binary) {
      return {
        available: false,
        findings: [],
        maxSeverity: null,
        analyzersUsed: [],
        error: INSTALL_HINT,
        raw: null,
      };
    }

    let targetDir: string;
    let skillFile: string | null;
    let lenient: boolean;
    const isDir = fs.existsSync(skillPath) && fs.statSync(skillPath).isDirectory();
    if (isDir) {
      targetDir = skillPath;
      skillFile = null;
      lenient = false;
    } else {
      targetDir = path.dirname(skillPath);
      skillFile = path.basename(skillPath);
      lenient = true;
    }

    const argv = SkillScanner.buildArgv(targetDir, { skillFile, lenient });

    let stdout = "";
    try {
      const res = await execFileAsync(binary, argv, {
        timeout: 120_000,
        maxBuffer: 32 * 1024 * 1024,
      });
      stdout = (res.stdout || "").trim();
    } catch (e: unknown) {
      // skill-scanner exits non-zero (1) when findings hit the --fail-on-severity
      // floor; the JSON report is still on stdout in that case. execFile rejects
      // on non-zero exit, so recover stdout from the error object.
      const err = e as { stdout?: string; killed?: boolean; signal?: string; message?: string };
      if (err.killed || err.signal === "SIGTERM") {
        return errorResult("skill-scanner scan timed out");
      }
      stdout = (err.stdout || "").trim();
      if (!stdout) {
        return errorResult(`skill-scanner invocation failed: ${err.message || e}`);
      }
    }

    if (!stdout) {
      return errorResult("skill-scanner produced no JSON output");
    }

    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(stdout);
    } catch (e) {
      return errorResult(`failed to parse skill-scanner JSON: ${e}`);
    }

    return SkillScanner.map(parsed);
  }

  static map(parsed: Record<string, unknown>): DeepScanResult {
    const rawFindings = Array.isArray(parsed.findings) ? parsed.findings : [];
    const findings: DeepFinding[] = rawFindings.map((f: Record<string, unknown>) => {
      const rawSev = String(f.severity ?? "").toUpperCase();
      const tier = SEVERITY_MAP[rawSev] ?? "low";
      return {
        ruleId: String(f.rule_id ?? f.id ?? "unknown"),
        severity: tier,
        category: String(f.category ?? ""),
        title: String(f.title ?? ""),
        description: String(f.description ?? ""),
        file: (f.file_path as string) ?? null,
        line: (f.line_number as number) ?? null,
        snippet: (f.snippet as string) ?? null,
        analyzer: String(f.analyzer ?? ""),
      };
    });

    const rawMax = parsed.max_severity;
    const maxSeverity = rawMax ? SEVERITY_MAP[String(rawMax).toUpperCase()] ?? null : null;
    const analyzersUsed = Array.isArray(parsed.analyzers_used)
      ? (parsed.analyzers_used as string[])
      : [];

    return {
      available: true,
      findings,
      maxSeverity,
      analyzersUsed,
      error: "",
      raw: parsed,
    };
  }
}

function errorResult(error: string): DeepScanResult {
  return {
    available: true,
    findings: [],
    maxSeverity: null,
    analyzersUsed: [],
    error,
    raw: null,
  };
}

export interface InstallResult {
  ok: boolean;
  message: string;
  via: string; // "uv" | "pip" | ""
}

/**
 * Managed installer for the optional `skill-scanner` deep engine.
 *
 * skill-scanner is a HEAVY PyPI package (litellm, fastapi, yara-x, …), so we
 * install it ISOLATED rather than into any shared environment:
 *   1. `uv tool install cisco-ai-skill-scanner==<version>` (preferred) — uv
 *      builds a dedicated venv and exposes a `skill-scanner` launcher on PATH.
 *   2. Fallback `python3 -m pip install --user cisco-ai-skill-scanner==<version>`.
 *
 * Security posture (mirrors the betterleaks installer's intent): pinned version,
 * list-form `execFile` (never a shell — no command injection), user-scoped, no
 * elevation. Integrity relies on TLS-to-PyPI + the version pin (a single-binary
 * SHA256 pin like betterleaks' is not possible over a pip transitive tree
 * without a lockfile — documented limitation, not a regression).
 */
export class SkillScannerInstaller {
  static uvPath(): string | null {
    const cmd = process.platform === "win32" ? "where uv" : "which uv";
    try {
      const result = execSync(cmd, { timeout: 5000, encoding: "utf-8" });
      const found = result.trim().split("\n")[0].trim();
      return found || null;
    } catch {
      return null;
    }
  }

  /** Construct the (list-form) install command + argv. Version is pinned with
   * `==` so it can never be read as extra arguments. */
  static buildInstall(
    version: string,
    uv: string | null,
  ): { cmd: string; argv: string[] } {
    const spec = `${SKILL_SCANNER_PACKAGE}==${version}`;
    if (uv) {
      return { cmd: uv, argv: ["tool", "install", "--force", spec] };
    }
    return {
      cmd: process.platform === "win32" ? "python" : "python3",
      argv: ["-m", "pip", "install", "--user", "--upgrade", spec],
    };
  }

  async install(
    version: string = SKILL_SCANNER_VERSION,
    onProgress?: (msg: string) => void,
  ): Promise<InstallResult> {
    const uv = SkillScannerInstaller.uvPath();
    const via = uv ? "uv" : "pip";
    const { cmd, argv } = SkillScannerInstaller.buildInstall(version, uv);
    if (onProgress) {
      onProgress(`Installing ${SKILL_SCANNER_PACKAGE}==${version} via ${via}…`);
    }
    try {
      await execFileAsync(cmd, argv, {
        timeout: 900_000, // heavy transitive tree; allow generous build time
        maxBuffer: 32 * 1024 * 1024,
      });
    } catch (e: unknown) {
      const err = e as { stderr?: string; stdout?: string; message?: string };
      const tail = (err.stderr || err.stdout || err.message || String(e)).trim().slice(-800);
      return { ok: false, message: `installer failed: ${tail || "(no output)"}`, via };
    }

    // Verify the launcher is now reachable.
    const checkCmd =
      process.platform === "win32" ? "where skill-scanner" : "which skill-scanner";
    try {
      const result = execSync(checkCmd, { timeout: 5000, encoding: "utf-8" });
      const found = result.trim().split("\n")[0].trim();
      if (found) return { ok: true, message: found, via };
    } catch {
      /* fall through */
    }
    return {
      ok: false,
      message:
        "install reported success but `skill-scanner` is not on PATH. If you " +
        "used the pip fallback, ensure your user-site bin directory is on PATH.",
      via,
    };
  }
}

/** Severity tiers, low→high, used to escalate a report's severity by deep
 * findings. Mirrors the order used by skill review. */
const _TIER_ORDER = ["clean", "low", "medium", "high", "critical"];

/**
 * The highest **actionable** tier (medium/high/critical) among a deep result's
 * findings, or "clean". low/INFO findings are reported but never escalate the
 * overall severity / exit code — matching the quick-scan contract.
 */
export function deepSeverityTier(result: DeepScanResult): string {
  let tier = "clean";
  for (const f of result.findings) {
    if (FINDING_SEVERITIES.has(f.severity) && _TIER_ORDER.indexOf(f.severity) > _TIER_ORDER.indexOf(tier)) {
      tier = f.severity;
    }
  }
  return tier;
}

/** Count of actionable (medium+) deep findings. */
export function deepActionableCount(result: DeepScanResult): number {
  return result.findings.filter((f) => FINDING_SEVERITIES.has(f.severity)).length;
}

/**
 * Resolve a usable SkillScanner for an opt-in --deep run, making it **easy**:
 * if the engine isn't installed and we're on an interactive TTY (and not in
 * --json mode), offer to install it in place. Returns a ready scanner, or null
 * when it's unavailable and the caller should print the install hint + exit 2.
 */
export async function ensureSkillScanner(opts: { json?: boolean } = {}): Promise<SkillScanner | null> {
  let scanner = new SkillScanner();
  if (scanner.isAvailable()) return scanner;

  const interactive = !!process.stdin.isTTY && !opts.json;
  if (interactive) {
    process.stderr.write("\nThe --deep engine (skill-scanner) is not installed.\n");
    const yes = await askYesNo(
      "Install it now? (heavy third-party package, isolated via uv/pip)",
      false,
    );
    if (yes) {
      const result = await new SkillScannerInstaller().install(
        SKILL_SCANNER_VERSION,
        (m) => process.stderr.write(`  ${m}\n`),
      );
      if (result.ok) {
        scanner = new SkillScanner();
        if (scanner.isAvailable()) {
          process.stderr.write(`skill-scanner installed (${result.via}).\n`);
          return scanner;
        }
      } else {
        process.stderr.write(`Install failed: ${result.message}\n`);
      }
    }
  }
  return null;
}
