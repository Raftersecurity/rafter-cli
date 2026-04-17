import { Command } from "commander";
import fs from "fs";
import path from "path";
import os from "os";
import { spawnSync } from "child_process";
import { PatternEngine } from "../../core/pattern-engine.js";
import { DEFAULT_SECRET_PATTERNS } from "../../scanners/secret-patterns.js";
import { fmt } from "../../utils/formatter.js";
import {
  discoverInstalledSkills,
  SKILL_PLATFORMS,
  SkillPlatform,
} from "./registry.js";

interface HighRiskCommand {
  command: string;
  file: string;
  line: number;
}

interface ObfuscationHit {
  kind:
    | "base64-blob"
    | "hex-escape-rope"
    | "zero-width-char"
    | "bidi-override"
    | "html-comment-imperative";
  file: string;
  line: number;
  sample: string;
}

interface SecretHit {
  pattern: string;
  severity: string;
  file: string;
  line: number | null;
  redacted: string;
}

interface FileInventoryEntry {
  path: string;
  bytes: number;
  kind: "text" | "binary";
}

interface FrontmatterInfo {
  file: string;
  name?: string;
  version?: string;
  allowedTools?: string[];
  description?: string;
}

export interface SkillReviewReport {
  target: {
    input: string;
    kind: "file" | "directory" | "git-url";
    resolvedPath: string;
  };
  frontmatter: FrontmatterInfo[];
  secrets: SecretHit[];
  urls: string[];
  highRiskCommands: HighRiskCommand[];
  obfuscation: ObfuscationHit[];
  inventory: {
    textFiles: number;
    binaryFiles: number;
    suspiciousFiles: FileInventoryEntry[];
  };
  summary: {
    severity: "clean" | "low" | "medium" | "high" | "critical";
    findings: number;
    reasons: string[];
  };
}

const TEXT_EXT = new Set([
  ".md",
  ".mdx",
  ".mdc",
  ".txt",
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".py",
  ".sh",
  ".bash",
  ".zsh",
  ".rb",
  ".go",
  ".rs",
  ".java",
  ".kt",
  ".swift",
  ".html",
  ".css",
  ".ini",
  ".env",
  ".cfg",
  ".conf",
]);

const SUSPICIOUS_EXT = new Set([
  ".so",
  ".dylib",
  ".dll",
  ".node",
  ".exe",
  ".wasm",
  ".bin",
]);

const MAX_FILE_BYTES = 2 * 1024 * 1024; // 2 MiB — anything larger gets treated as binary
const MAX_FILES = 2000; // hard cap to avoid runaway traversal

const HIGH_RISK_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /rm\s+-rf\s+\/(?!\w)/gi, name: "rm -rf /" },
  { pattern: /sudo\s+rm/gi, name: "sudo rm" },
  { pattern: /curl[^|]*\|\s*(?:ba)?sh/gi, name: "curl | sh" },
  { pattern: /wget[^|]*\|\s*(?:ba)?sh/gi, name: "wget | sh" },
  { pattern: /iwr[^|]*\|\s*iex/gi, name: "iwr | iex" },
  { pattern: /eval\s*\(/gi, name: "eval()" },
  { pattern: /exec\s*\(/gi, name: "exec()" },
  { pattern: /Function\s*\(\s*['"`]/g, name: "new Function(...)" },
  { pattern: /chmod\s+777/gi, name: "chmod 777" },
  { pattern: /:\(\)\{\s*:\|:&\s*\};:/g, name: "fork bomb" },
  { pattern: /dd\s+if=\/dev\/(?:zero|random)\s+of=\/dev/gi, name: "dd to device" },
  { pattern: /\bmkfs(?:\.\w+)?\b/gi, name: "mkfs (format)" },
  { pattern: /base64\s+-d[^|]*\|\s*(?:ba)?sh/gi, name: "base64 decode | sh" },
  { pattern: /\b(?:crontab|systemctl|launchctl)\s+(?:-e|edit|enable|load)/gi, name: "persistence primitive" },
];

const ZERO_WIDTH_RE = /[\u200B-\u200F\u2060\uFEFF]/g;
const BIDI_RE = /[\u202A-\u202E\u2066-\u2069]/g;
const BASE64_BLOB_RE = /[A-Za-z0-9+/]{200,}={0,2}/g;
const HEX_ROPE_RE = /(?:\\x[0-9a-fA-F]{2}){8,}/g;
const URL_RE = /https?:\/\/[^\s<>"'`)]+/gi;

function isGitUrl(input: string): boolean {
  if (input.startsWith("git@")) return true;
  if (input.endsWith(".git")) return true;
  if (/^(https?|ssh):\/\//.test(input) && /github\.com|gitlab\.com|bitbucket\.org|codeberg\.org/.test(input)) {
    return true;
  }
  return false;
}

function cloneShallow(url: string): string {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-skill-review-"));
  const result = spawnSync("git", ["clone", "--depth", "1", "--quiet", url, tmp], {
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 60_000,
  });
  if (result.status !== 0) {
    const err = (result.stderr ?? "").toString().trim() || "git clone failed";
    try {
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch {
      // ignore
    }
    throw new Error(`Failed to clone ${url}: ${err}`);
  }
  return tmp;
}

function looksBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 4096);
  for (let i = 0; i < n; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

function walkFiles(root: string): string[] {
  const out: string[] = [];
  const stack: string[] = [root];
  while (stack.length && out.length < MAX_FILES) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === ".git" || entry.name === "node_modules" || entry.name === ".venv") continue;
        stack.push(full);
      } else if (entry.isFile()) {
        out.push(full);
        if (out.length >= MAX_FILES) break;
      }
    }
  }
  return out;
}

function parseFrontmatter(content: string): Record<string, string> {
  const match = content.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return {};
  const out: Record<string, string> = {};
  for (const line of match[1].split("\n")) {
    const m = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (!m) continue;
    let val = m[2].trim();
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
    else if (val.startsWith("'") && val.endsWith("'")) val = val.slice(1, -1);
    out[m[1]] = val;
  }
  return out;
}

function parseAllowedTools(raw: string | undefined): string[] | undefined {
  if (!raw) return undefined;
  const trimmed = raw.trim();
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return trimmed
      .slice(1, -1)
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return trimmed.split(/[,\s]+/).filter(Boolean);
}

function lineOf(content: string, index: number): number {
  return content.substring(0, index).split("\n").length;
}

function scanContent(
  relPath: string,
  content: string,
  patternEngine: PatternEngine,
  report: SkillReviewReport,
): void {
  for (const pm of patternEngine.scan(content)) {
    report.secrets.push({
      pattern: pm.pattern.name,
      severity: pm.pattern.severity,
      file: relPath,
      line: pm.line ?? null,
      redacted: pm.redacted ?? "",
    });
  }

  for (const m of content.match(URL_RE) ?? []) {
    // Strip trailing punctuation (common in markdown prose).
    const cleaned = m.replace(/[).,;:]+$/, "");
    report.urls.push(cleaned);
  }

  for (const { pattern, name } of HIGH_RISK_PATTERNS) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(content)) !== null) {
      report.highRiskCommands.push({
        command: name,
        file: relPath,
        line: lineOf(content, m.index),
      });
    }
  }

  for (const re of [ZERO_WIDTH_RE, BIDI_RE]) {
    re.lastIndex = 0;
    const m = re.exec(content);
    if (m) {
      report.obfuscation.push({
        kind: re === ZERO_WIDTH_RE ? "zero-width-char" : "bidi-override",
        file: relPath,
        line: lineOf(content, m.index),
        sample: `U+${m[0].charCodeAt(0).toString(16).padStart(4, "0").toUpperCase()}`,
      });
    }
  }

  BASE64_BLOB_RE.lastIndex = 0;
  let bm: RegExpExecArray | null;
  while ((bm = BASE64_BLOB_RE.exec(content)) !== null) {
    report.obfuscation.push({
      kind: "base64-blob",
      file: relPath,
      line: lineOf(content, bm.index),
      sample: `${bm[0].length} chars`,
    });
  }

  HEX_ROPE_RE.lastIndex = 0;
  let hm: RegExpExecArray | null;
  while ((hm = HEX_ROPE_RE.exec(content)) !== null) {
    report.obfuscation.push({
      kind: "hex-escape-rope",
      file: relPath,
      line: lineOf(content, hm.index),
      sample: `${hm[0].length} chars`,
    });
  }

  // HTML comments with imperative verbs hidden in markdown.
  const HTML_IMPERATIVE_RE =
    /<!--[\s\S]{0,400}?\b(ignore|disregard|pretend|you are|system:|assistant:)\b[\s\S]{0,400}?-->/gi;
  HTML_IMPERATIVE_RE.lastIndex = 0;
  let cm: RegExpExecArray | null;
  while ((cm = HTML_IMPERATIVE_RE.exec(content)) !== null) {
    report.obfuscation.push({
      kind: "html-comment-imperative",
      file: relPath,
      line: lineOf(content, cm.index),
      sample: cm[0].slice(0, 80).replace(/\s+/g, " "),
    });
  }
}

function summarize(report: SkillReviewReport): void {
  const reasons: string[] = [];
  let sev: SkillReviewReport["summary"]["severity"] = "clean";

  const highestSecret = report.secrets.reduce<string | null>(
    (acc, s) => {
      const order = ["low", "medium", "high", "critical"];
      if (!acc) return s.severity;
      return order.indexOf(s.severity) > order.indexOf(acc) ? s.severity : acc;
    },
    null,
  );

  if (report.secrets.length > 0) {
    reasons.push(`${report.secrets.length} secret finding(s)`);
    sev = (highestSecret as SkillReviewReport["summary"]["severity"]) ?? "high";
  }
  if (report.highRiskCommands.length > 0) {
    reasons.push(`${report.highRiskCommands.length} high-risk command(s)`);
    if (sev === "clean" || sev === "low") sev = "high";
  }
  const hardObf = report.obfuscation.filter(
    (o) => o.kind === "bidi-override" || o.kind === "html-comment-imperative",
  );
  if (hardObf.length > 0) {
    reasons.push(`${hardObf.length} hard obfuscation signal(s)`);
    sev = "critical";
  }
  const softObf = report.obfuscation.filter(
    (o) =>
      o.kind === "zero-width-char" ||
      o.kind === "base64-blob" ||
      o.kind === "hex-escape-rope",
  );
  if (softObf.length > 0) {
    reasons.push(`${softObf.length} obfuscation signal(s)`);
    if (sev === "clean") sev = "medium";
  }
  if (report.inventory.suspiciousFiles.length > 0) {
    reasons.push(`${report.inventory.suspiciousFiles.length} suspicious file(s)`);
    if (sev === "clean" || sev === "low") sev = "medium";
  }

  report.summary = {
    severity: sev,
    findings:
      report.secrets.length +
      report.highRiskCommands.length +
      report.obfuscation.length +
      report.inventory.suspiciousFiles.length,
    reasons,
  };
}

function buildReport(rootInput: string, resolvedPath: string, kind: "file" | "directory" | "git-url"): SkillReviewReport {
  const report: SkillReviewReport = {
    target: { input: rootInput, kind, resolvedPath },
    frontmatter: [],
    secrets: [],
    urls: [],
    highRiskCommands: [],
    obfuscation: [],
    inventory: { textFiles: 0, binaryFiles: 0, suspiciousFiles: [] },
    summary: { severity: "clean", findings: 0, reasons: [] },
  };

  const patternEngine = new PatternEngine(DEFAULT_SECRET_PATTERNS);
  const urlSet = new Set<string>();

  const files = kind === "file" ? [resolvedPath] : walkFiles(resolvedPath);

  for (const file of files) {
    const relPath = path.relative(kind === "file" ? path.dirname(resolvedPath) : resolvedPath, file) || path.basename(file);
    let stat: fs.Stats;
    try {
      stat = fs.statSync(file);
    } catch {
      continue;
    }
    if (!stat.isFile()) continue;

    const ext = path.extname(file).toLowerCase();
    if (SUSPICIOUS_EXT.has(ext)) {
      report.inventory.suspiciousFiles.push({ path: relPath, bytes: stat.size, kind: "binary" });
      report.inventory.binaryFiles += 1;
      continue;
    }
    if (stat.size > MAX_FILE_BYTES) {
      report.inventory.suspiciousFiles.push({ path: relPath, bytes: stat.size, kind: "binary" });
      report.inventory.binaryFiles += 1;
      continue;
    }

    let buf: Buffer;
    try {
      buf = fs.readFileSync(file);
    } catch {
      continue;
    }

    if (looksBinary(buf)) {
      report.inventory.binaryFiles += 1;
      if (!TEXT_EXT.has(ext)) {
        report.inventory.suspiciousFiles.push({ path: relPath, bytes: stat.size, kind: "binary" });
      }
      continue;
    }

    report.inventory.textFiles += 1;
    const content = buf.toString("utf-8");

    if (path.basename(file).toLowerCase() === "skill.md") {
      const fm = parseFrontmatter(content);
      report.frontmatter.push({
        file: relPath,
        name: fm.name,
        version: fm.version,
        description: fm.description,
        allowedTools: parseAllowedTools(fm["allowed-tools"]),
      });
    }

    scanContent(relPath, content, patternEngine, report);
  }

  for (const u of report.urls) urlSet.add(u);
  report.urls = [...urlSet].sort();
  report.inventory.suspiciousFiles.sort((a, b) => a.path.localeCompare(b.path));

  summarize(report);
  return report;
}

function renderText(report: SkillReviewReport): void {
  console.log(fmt.header(`Skill review: ${report.target.input}`));
  console.log(fmt.divider());
  const fm = report.frontmatter[0];
  if (fm?.name) {
    const ver = fm.version ? ` v${fm.version}` : "";
    console.log(`Skill: ${fm.name}${ver}`);
    if (fm.allowedTools && fm.allowedTools.length > 0) {
      console.log(`allowed-tools: ${fm.allowedTools.join(", ")}`);
    }
  }
  console.log(
    `Files: ${report.inventory.textFiles} text, ${report.inventory.binaryFiles} binary, ${report.inventory.suspiciousFiles.length} suspicious`,
  );
  console.log();

  const line = (ok: boolean, label: string, detail?: string) =>
    console.log(
      `${ok ? fmt.success(label) : fmt.warning(label)}${detail ? `  ${detail}` : ""}`,
    );

  line(report.secrets.length === 0, `Secrets: ${report.secrets.length}`);
  if (report.secrets.length > 0) {
    for (const s of report.secrets.slice(0, 5)) {
      console.log(`   - [${s.severity}] ${s.pattern} at ${s.file}${s.line ? `:${s.line}` : ""}`);
    }
    if (report.secrets.length > 5) console.log(`   ... and ${report.secrets.length - 5} more`);
  }

  line(report.highRiskCommands.length === 0, `High-risk commands: ${report.highRiskCommands.length}`);
  for (const c of report.highRiskCommands.slice(0, 5)) {
    console.log(`   - ${c.command} at ${c.file}:${c.line}`);
  }
  if (report.highRiskCommands.length > 5) {
    console.log(`   ... and ${report.highRiskCommands.length - 5} more`);
  }

  line(report.obfuscation.length === 0, `Obfuscation signals: ${report.obfuscation.length}`);
  for (const o of report.obfuscation.slice(0, 5)) {
    console.log(`   - ${o.kind} at ${o.file}:${o.line} (${o.sample})`);
  }
  if (report.obfuscation.length > 5) {
    console.log(`   ... and ${report.obfuscation.length - 5} more`);
  }

  line(
    report.inventory.suspiciousFiles.length === 0,
    `Suspicious files: ${report.inventory.suspiciousFiles.length}`,
  );
  for (const f of report.inventory.suspiciousFiles.slice(0, 5)) {
    console.log(`   - ${f.path} (${f.bytes} bytes)`);
  }

  line(report.urls.length === 0, `External URLs: ${report.urls.length}`);
  for (const u of report.urls.slice(0, 8)) {
    console.log(`   - ${u}`);
  }
  if (report.urls.length > 8) console.log(`   ... and ${report.urls.length - 8} more`);

  console.log();
  const sev = report.summary.severity.toUpperCase();
  const label = `Overall: ${sev}`;
  if (report.summary.severity === "clean") console.log(fmt.success(label));
  else if (report.summary.severity === "critical" || report.summary.severity === "high")
    console.error(fmt.error(label));
  else console.log(fmt.warning(label));
  if (report.summary.reasons.length > 0) {
    console.log(`  ${report.summary.reasons.join(", ")}`);
  }
  console.log();
  console.log(
    fmt.info(
      "Deterministic checks only. Pair with the `rafter-skill-review` skill for provenance / prompt-injection / data-practices review.",
    ),
  );
}

export function runSkillReview(
  input: string,
  opts: { format?: "json" | "text"; json?: boolean },
): { report: SkillReviewReport; exitCode: number } {
  let resolved = input;
  let kind: "file" | "directory" | "git-url";
  let cleanup: string | null = null;

  if (isGitUrl(input)) {
    try {
      resolved = cloneShallow(input);
    } catch (e) {
      console.error(fmt.error(`${e instanceof Error ? e.message : String(e)}`));
      return { report: null as unknown as SkillReviewReport, exitCode: 2 };
    }
    cleanup = resolved;
    kind = "git-url";
  } else if (!fs.existsSync(input)) {
    console.error(fmt.error(`Not found: ${input}`));
    return { report: null as unknown as SkillReviewReport, exitCode: 2 };
  } else {
    const stat = fs.statSync(input);
    resolved = path.resolve(input);
    kind = stat.isDirectory() ? "directory" : "file";
  }

  try {
    const report = buildReport(input, resolved, kind);
    const format = opts.json ? "json" : opts.format ?? "text";
    if (format === "json") {
      console.log(JSON.stringify(report, null, 2));
    } else {
      renderText(report);
    }
    const exitCode = report.summary.severity === "clean" ? 0 : 1;
    return { report, exitCode };
  } finally {
    if (cleanup) {
      try {
        fs.rmSync(cleanup, { recursive: true, force: true });
      } catch {
        // non-fatal
      }
    }
  }
}

export interface InstalledSkillEntry {
  platform: SkillPlatform;
  skill: string;
  path: string;
  report: SkillReviewReport;
}

export interface InstalledReviewReport {
  target: { mode: "installed"; agent: SkillPlatform | "all" };
  installations: InstalledSkillEntry[];
  summary: {
    totalSkills: number;
    severityCounts: Record<"clean" | "low" | "medium" | "high" | "critical", number>;
    platformCounts: Record<string, number>;
    findings: number;
    worst: "clean" | "low" | "medium" | "high" | "critical";
  };
}

const SEVERITY_ORDER: ReadonlyArray<
  "clean" | "low" | "medium" | "high" | "critical"
> = ["clean", "low", "medium", "high", "critical"];

export function runSkillReviewInstalled(opts: {
  agent?: string;
}): { report: InstalledReviewReport; exitCode: number } {
  let filter: SkillPlatform | undefined;
  if (opts.agent) {
    const a = opts.agent as SkillPlatform;
    if (!SKILL_PLATFORMS.includes(a)) {
      throw new Error(
        `Unknown agent: ${opts.agent}. Known: ${SKILL_PLATFORMS.join(", ")}`,
      );
    }
    filter = a;
  }
  const discovered = discoverInstalledSkills(filter);
  const installations: InstalledSkillEntry[] = [];
  const severityCounts: InstalledReviewReport["summary"]["severityCounts"] = {
    clean: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  const platformCounts: Record<string, number> = {};
  let findings = 0;
  let worst: (typeof SEVERITY_ORDER)[number] = "clean";

  for (const d of discovered) {
    const report = buildReport(d.path, d.path, "file");
    installations.push({
      platform: d.platform,
      skill: d.name,
      path: d.path,
      report,
    });
    severityCounts[report.summary.severity] += 1;
    platformCounts[d.platform] = (platformCounts[d.platform] ?? 0) + 1;
    findings += report.summary.findings;
    if (
      SEVERITY_ORDER.indexOf(report.summary.severity) >
      SEVERITY_ORDER.indexOf(worst)
    ) {
      worst = report.summary.severity;
    }
  }

  const aggregate: InstalledReviewReport = {
    target: { mode: "installed", agent: filter ?? "all" },
    installations,
    summary: {
      totalSkills: installations.length,
      severityCounts,
      platformCounts,
      findings,
      worst,
    },
  };

  // Exit 1 iff any HIGH or CRITICAL finding (per rf-61x contract). Lower
  // severities do not fail the audit — use `rafter skill review <path>` for
  // a stricter per-skill gate.
  const exitCode =
    severityCounts.high + severityCounts.critical > 0 ? 1 : 0;
  return { report: aggregate, exitCode };
}

function renderInstalledSummary(report: InstalledReviewReport): void {
  console.log(fmt.header(`Installed skill audit`));
  console.log(fmt.divider());
  const agent = report.target.agent;
  console.log(`Agent filter: ${agent}`);
  console.log(`Skills audited: ${report.summary.totalSkills}`);
  console.log();

  if (report.installations.length === 0) {
    console.log(
      fmt.info("No installed skills found across the requested platform(s)."),
    );
    return;
  }

  // Column widths — clamp platform col at "claude-code" length (11) and skill
  // col at 28 so the table stays readable on 80-col terminals.
  const platW = 11;
  const skillW = 28;
  const sevW = 8;
  const head =
    "PLATFORM".padEnd(platW) +
    "  " +
    "SKILL".padEnd(skillW) +
    "  " +
    "SEVERITY".padEnd(sevW) +
    "  " +
    "FINDINGS";
  console.log(head);
  console.log("-".repeat(head.length));
  for (const row of report.installations) {
    const skill =
      row.skill.length > skillW ? row.skill.slice(0, skillW - 1) + "…" : row.skill;
    const sev = row.report.summary.severity;
    const findings = row.report.summary.findings;
    const line =
      row.platform.padEnd(platW) +
      "  " +
      skill.padEnd(skillW) +
      "  " +
      sev.padEnd(sevW) +
      "  " +
      String(findings);
    if (sev === "critical" || sev === "high") console.error(fmt.error(line));
    else if (sev === "medium" || sev === "low") console.log(fmt.warning(line));
    else console.log(fmt.success(line));
  }
  console.log();
  const sc = report.summary.severityCounts;
  console.log(
    `Totals: ${sc.clean} clean · ${sc.low} low · ${sc.medium} medium · ${sc.high} high · ${sc.critical} critical`,
  );
  if (sc.high + sc.critical > 0) {
    console.error(
      fmt.error(
        `Worst severity: ${report.summary.worst.toUpperCase()} — review flagged skills before trusting them.`,
      ),
    );
  } else {
    console.log(
      fmt.success(`Worst severity: ${report.summary.worst.toUpperCase()}`),
    );
  }
}

export function createReviewCommand(): Command {
  return new Command("review")
    .description("Security review of a skill / plugin / extension before installing it (path or git URL), or --installed to audit every skill on this machine")
    .argument("[path-or-url]", "Local path (file or directory) OR git URL (https/ssh/.git). Omit when using --installed.")
    .option("--json", "Emit JSON report to stdout (shortcut for --format json)")
    .option("--format <format>", "Output format: text | json", "text")
    .option(
      "--installed",
      "Audit every installed skill across detected agent skill directories instead of a path",
    )
    .option(
      "--agent <name>",
      `Restrict --installed to a single agent. One of: ${SKILL_PLATFORMS.join(", ")}`,
    )
    .option(
      "--summary",
      "Print a terse human-readable table instead of JSON (only with --installed)",
    )
    .action(
      (
        input: string | undefined,
        opts: {
          json?: boolean;
          format?: "text" | "json";
          installed?: boolean;
          agent?: string;
          summary?: boolean;
        },
      ) => {
        if (opts.installed) {
          if (input) {
            console.error(
              fmt.error(
                "Cannot pass both <path-or-url> and --installed. Use one.",
              ),
            );
            process.exit(1);
          }
          let result: ReturnType<typeof runSkillReviewInstalled>;
          try {
            result = runSkillReviewInstalled({ agent: opts.agent });
          } catch (e) {
            console.error(fmt.error(`${e instanceof Error ? e.message : String(e)}`));
            process.exit(1);
          }
          if (opts.summary) {
            renderInstalledSummary(result.report);
          } else {
            console.log(JSON.stringify(result.report, null, 2));
          }
          process.exit(result.exitCode);
        }

        if (!input) {
          console.error(
            fmt.error(
              "Missing <path-or-url>. Pass a path / git URL, or use --installed to audit installed skills.",
            ),
          );
          process.exit(2);
        }
        const { exitCode } = runSkillReview(input, opts);
        process.exit(exitCode);
      },
    );
}
