import { Command } from "commander";
import { CommandInterceptor, CommandEvaluation } from "../../core/command-interceptor.js";
import { RegexScanner, ScanResult } from "../../scanners/regex-scanner.js";
import { AuditLogger } from "../../core/audit-logger.js";
import { ConfigManager } from "../../core/config-manager.js";
import { applySuppressions, Suppression } from "../../core/custom-patterns.js";
import { resolveHookControl, HookControl } from "../../core/hook-control.js";
import { collectSuppressions, applyExcludePaths } from "../agent/scan.js";
import { scanAddedDiffLines } from "../../scanners/git-diff-scan.js";
import { parseUnifiedDiffAddedLines } from "../../utils/git-diff.js";
import type { ScanIgnoreRule } from "../../core/config-schema.js";
import { execSync, ExecSyncOptionsWithStringEncoding } from "child_process";
import fs from "fs";
import path from "path";

/**
 * Subset of `cfg.agent.scan` the hook consumes. The hook is patterns-only by
 * design (no betterleaks subprocess — it runs on every tool call and must stay
 * fast), so betterleaks version skew can never affect it. It still honors the
 * same `.rafter.yml` policy the CLI does — custom patterns, `exclude_paths`,
 * and `ignore` suppressions — so the hook and `rafter secrets` agree (sable-55u).
 */
type HookScanCfg = {
  customPatterns?: Array<{ name: string; regex: string; severity: string }>;
  excludePaths?: string[];
  ignore?: ScanIgnoreRule[];
};

/**
 * Load the policy-merged scan config + suppression list the same way scan.ts
 * does, so hook decisions match `rafter secrets`. Policy discovery and
 * `.rafterignore` loading key off `process.cwd()`; `cwd` lets tests point the
 * lookup at a temp repo without a process-wide chdir leaking across tests.
 */
function loadScanConfig(cwd: string = process.cwd()): {
  scanCfg: HookScanCfg | undefined;
  suppressions: Suppression[];
} {
  const prev = process.cwd();
  const restore = path.resolve(cwd) !== path.resolve(prev);
  if (restore) {
    try { process.chdir(cwd); } catch { /* ignore — fall back to current cwd */ }
  }
  try {
    const cfg = new ConfigManager().loadWithPolicy();
    const scanCfg = cfg.agent?.scan as HookScanCfg | undefined;
    return { scanCfg, suppressions: collectSuppressions(scanCfg?.ignore) };
  } finally {
    if (restore) {
      try { process.chdir(prev); } catch { /* ignore */ }
    }
  }
}

type HookFormat = "claude" | "cursor" | "gemini" | "windsurf";

interface HookInput {
  session_id?: string;
  tool_name: string;
  tool_input: Record<string, any>;
}

interface HookDecision {
  decision: "allow" | "deny";
  reason?: string;
}

const RISK_LABELS: Record<string, string> = {
  critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW",
};

const RISK_DESCRIPTIONS: Record<string, string> = {
  critical: "irreversible system damage",
  high: "significant system changes",
  medium: "moderate risk operation",
  low: "minimal risk",
};

function formatBlockedMessage(command: string, evaluation: CommandEvaluation): string {
  const cmdDisplay = command.length > 60 ? command.slice(0, 60) + "..." : command;
  const rule = evaluation.matchedPattern ?? "policy violation";
  const label = RISK_LABELS[evaluation.riskLevel] ?? evaluation.riskLevel.toUpperCase();
  const desc = RISK_DESCRIPTIONS[evaluation.riskLevel] ?? "";
  return `\u2717 Rafter blocked: ${cmdDisplay}\n  Rule: ${rule}\n  Risk: ${label}\u2014${desc}`;
}

function formatApprovalMessage(command: string, evaluation: CommandEvaluation): string {
  const cmdDisplay = command.length > 60 ? command.slice(0, 60) + "..." : command;
  const rule = evaluation.matchedPattern ?? "policy match";
  const label = RISK_LABELS[evaluation.riskLevel] ?? evaluation.riskLevel.toUpperCase();
  const desc = RISK_DESCRIPTIONS[evaluation.riskLevel] ?? "";
  return `\u26a0 Rafter: approval required\n  Command: ${cmdDisplay}\n  Rule: ${rule}\n  Risk: ${label}\u2014${desc}\n\nTo approve: rafter agent exec --approve "${command}"\nTo configure: rafter agent config set agent.riskLevel minimal`;
}

export function createHookPretoolCommand(): Command {
  return new Command("pretool")
    .description("PreToolUse hook handler (reads stdin, writes JSON decision to stdout)")
    // Tolerate extra flags/args the host harness appends to the hook command
    // (e.g. Claude Code adds `--hook-json <data>`). Hook input comes from stdin,
    // so anything else is unused — discard it instead of erroring out.
    .allowUnknownOption()
    .allowExcessArguments()
    .option("--format <format>", "Output format: claude (default, also Codex/Continue), cursor, gemini, windsurf", "claude")
    .action(async (opts) => {
      const format = (opts.format || "claude") as HookFormat;
      try {
        const input = await readStdin();
        let raw: Record<string, any>;

        try {
          raw = JSON.parse(input);
        } catch {
          // Can't parse → fail open
          writeDecision({ decision: "allow" }, format);
          return;
        }

        // Validate payload is an object with expected shape
        if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
          writeDecision({ decision: "allow" }, format);
          return;
        }

        const payload = normalizeInput(raw, format);
        const decision = evaluateToolCall(payload);
        writeDecision(decision, format);
      } catch {
        // Any unexpected error → fail open
        writeDecision({ decision: "allow" }, format);
      }
    });
}

/**
 * Normalize platform-specific stdin JSON into a common HookInput shape.
 *
 * Claude/Codex/Continue: { tool_name, tool_input: { command } }
 * Cursor:                { hook_event_name, command, cwd }
 * Gemini:                { tool_name, tool_input: { command } }  (same as Claude)
 * Windsurf:              { agent_action_name, tool_info: { command_line, cwd } }
 */
function normalizeInput(raw: Record<string, any>, format: HookFormat): HookInput {
  if (format === "cursor") {
    // Cursor sends { command, cwd, hook_event_name, ... }
    const command = raw.command || "";
    const eventName = raw.hook_event_name || "";
    // beforeShellExecution → Bash, beforeMCPExecution → tool name from payload
    const toolName = eventName === "beforeShellExecution" ? "Bash"
      : eventName === "beforeReadFile" ? "Read"
      : eventName === "afterFileEdit" ? "Write"
      : raw.tool_name || "unknown";
    return {
      session_id: raw.conversation_id,
      tool_name: toolName,
      tool_input: eventName === "beforeShellExecution" ? { command } : (raw.tool_input || {}),
    };
  }

  if (format === "windsurf") {
    // Windsurf sends { agent_action_name, tool_info: { command_line, cwd } }
    const toolInfo = raw.tool_info || {};
    const actionName = raw.agent_action_name || "";
    const toolName = actionName.includes("run_command") ? "Bash"
      : actionName.includes("write_code") ? "Write"
      : actionName.includes("read_code") ? "Read"
      : actionName.includes("mcp_tool_use") ? (toolInfo.mcp_tool_name || "unknown")
      : "unknown";
    return {
      session_id: raw.trajectory_id,
      tool_name: toolName,
      tool_input: toolName === "Bash" ? { command: toolInfo.command_line || "" } : toolInfo,
    };
  }

  // Claude, Codex, Continue, Gemini — all use { tool_name, tool_input }
  return {
    session_id: raw.session_id,
    tool_name: raw.tool_name || "",
    tool_input: raw.tool_input || {},
  };
}

function evaluateToolCall(payload: HookInput): HookDecision {
  const { tool_name, tool_input } = payload;

  // Honor the (trusted-source-only) hook off-switch before doing any work.
  // Master switch off → allow everything; otherwise the two concerns are gated
  // independently inside evaluateBash (command policy + git-commit secret scan).
  const control = resolveHookControl();
  if (!control.hookEnabled) return { decision: "allow" };

  if (tool_name === "Bash") {
    return evaluateBash(tool_input?.command || "", control);
  }

  if (tool_name === "Write" || tool_name === "Edit") {
    if (!control.secretScanEnabled) return { decision: "allow" };
    return evaluateWrite(tool_input || {});
  }

  return { decision: "allow" };
}

function evaluateBash(command: string, control: HookControl): HookDecision {
  const audit = new AuditLogger();

  // Command-risk interception — gated by commandPolicy. When disabled, skip the
  // block/approval logic but still fall through to the staged-secret scan below
  // (a user may keep secret scanning while silencing command prompts).
  if (control.commandPolicyEnabled) {
    const interceptor = new CommandInterceptor();
    const evaluation = interceptor.evaluate(command);

    // Blocked — hard deny
    if (!evaluation.allowed && !evaluation.requiresApproval) {
      audit.logCommandIntercepted(command, false, "blocked", evaluation.reason);
      return {
        decision: "deny",
        reason: formatBlockedMessage(command, evaluation),
      };
    }

    // Requires approval — deny (agent can't provide interactive approval)
    if (evaluation.requiresApproval) {
      audit.logCommandIntercepted(command, false, "blocked", evaluation.reason);
      return {
        decision: "deny",
        reason: formatApprovalMessage(command, evaluation),
      };
    }
  }

  // Git commit/push — scan staged files for secrets. Gated by secretScan so the
  // git-commit secret check survives `commandPolicy` being disabled on its own.
  const trimmed = command.trim();
  if (control.secretScanEnabled && (trimmed.startsWith("git commit") || trimmed.startsWith("git push"))) {
    const scanResult = scanStagedFiles();
    if (scanResult.secretsFound) {
      // Audit per file so the log records WHICH file + pattern, not a bare count.
      for (const r of scanResult.findings) {
        const rel = path.relative(scanResult.repoRoot, r.file) || path.basename(r.file);
        const names = [...new Set(r.matches.map((m) => m.pattern.name))];
        audit.logSecretDetected(rel, names.join(", "), "blocked");
      }
      return {
        decision: "deny",
        reason: formatStagedSecretReason(scanResult),
      };
    }
  }

  audit.logCommandIntercepted(command, true, "allowed");
  return { decision: "allow" };
}

function evaluateWrite(toolInput: Record<string, any>): HookDecision {
  // Write uses "content", Edit uses "new_string"
  const content = toolInput.content || toolInput.new_string || "";
  if (!content) {
    return { decision: "allow" };
  }

  // Route through the same config pipeline as scan.ts so the hook honors
  // custom patterns, exclude_paths, and ignore rules from .rafter.yml.
  const { scanCfg, suppressions } = loadScanConfig();
  const scanner = new RegexScanner(scanCfg?.customPatterns);
  const matches = scanner.scanText(content);
  if (matches.length === 0) {
    return { decision: "allow" };
  }

  const filePath = toolInput.file_path || "file content";
  // Apply exclude_paths + suppressions keyed on the target file path, so a
  // write to a policy-excluded path is allowed (matching `rafter secrets`).
  const afterExclude = applyExcludePaths(
    [{ file: filePath, matches }],
    scanCfg?.excludePaths,
    process.cwd(),
  );
  const { results: kept } = applySuppressions(afterExclude, suppressions);
  const keptMatches = kept[0]?.matches ?? [];
  if (keptMatches.length === 0) {
    return { decision: "allow" };
  }

  const names = [...new Set(keptMatches.map((m) => m.pattern.name))];
  const audit = new AuditLogger();
  audit.logSecretDetected(filePath, names.join(", "), "blocked");
  return {
    decision: "deny",
    reason: `Secret detected in ${filePath}: ${names.join(", ")}`,
  };
}

interface StagedScanResult {
  secretsFound: boolean;
  count: number;
  files: number;
  /** Per-file findings kept after exclude_paths + suppressions. */
  findings: ScanResult[];
  /** Repo root, for rendering finding paths relative to the user's tree. */
  repoRoot: string;
}

/**
 * Scan the git staged files for secrets, routed through the SAME config-aware
 * pipeline as `rafter secrets --staged` (sable-55u). The hook previously ran
 * RegexScanner directly on the raw staged list with no config — no custom
 * patterns, no exclude_paths, no suppressions — so it phantom-blocked commits
 * on findings the CLI would suppress. Now it loads `.rafter.yml`, applies
 * exclude_paths and ignore rules, and reports which file + pattern matched.
 *
 * Still patterns-only (no betterleaks): the hook is on the hot path and must
 * stay fast, and betterleaks version skew therefore cannot affect it.
 *
 * `cwd` exists for tests; production callers use the inherited process cwd.
 */
export function scanStagedFiles(cwd: string = process.cwd()): StagedScanResult {
  const gitOpts: ExecSyncOptionsWithStringEncoding = {
    cwd, encoding: "utf-8", stdio: ["pipe", "pipe", "ignore"],
  };
  const empty: StagedScanResult = {
    secretsFound: false, count: 0, files: 0, findings: [], repoRoot: cwd,
  };
  try {
    const repoRoot = execSync("git rev-parse --show-toplevel", gitOpts).trim() || cwd;

    const patch = execSync(
      "git diff -U0 --no-color --cached --diff-filter=ACM",
      gitOpts,
    ).trim();
    if (!patch) {
      return { ...empty, repoRoot };
    }

    const addedLines = parseUnifiedDiffAddedLines(patch);
    if (addedLines.length === 0) {
      return { ...empty, repoRoot };
    }

    const { scanCfg, suppressions } = loadScanConfig(cwd);
    const raw = scanAddedDiffLines(addedLines, repoRoot, scanCfg?.customPatterns);

    const afterExclude = applyExcludePaths(raw, scanCfg?.excludePaths, repoRoot);
    const { results: kept } = applySuppressions(afterExclude, suppressions);
    const count = kept.reduce((sum, r) => sum + r.matches.length, 0);

    return {
      secretsFound: kept.length > 0,
      count,
      files: kept.length,
      findings: kept,
      repoRoot,
    };
  } catch {
    return empty;
  }
}

/** Cap on individual findings listed in a deny reason before truncating. */
const MAX_REASON_FINDINGS = 10;

/**
 * Render a deny reason that names each offending file + pattern (+ line when
 * known) instead of a bare count, so the agent knows what to fix without a
 * second `rafter secrets` run. Truncates long lists.
 */
export function formatStagedSecretReason(scan: StagedScanResult): string {
  const lines: string[] = [];
  let shown = 0;
  outer: for (const r of scan.findings) {
    const rel = path.relative(scan.repoRoot, r.file) || path.basename(r.file);
    for (const m of r.matches) {
      if (shown >= MAX_REASON_FINDINGS) {
        lines.push(`  …and ${scan.count - shown} more`);
        break outer;
      }
      const loc = m.line ? `:${m.line}` : "";
      lines.push(`  ${rel}${loc} — ${m.pattern.name}`);
      shown++;
    }
  }
  return [
    `${scan.count} secret(s) detected in ${scan.files} staged file(s):`,
    ...lines,
    "Hook scan is pattern-only (betterleaks version is irrelevant). " +
      "Run 'rafter secrets --staged' for full detail, or add an exclude_paths/ignore rule to .rafter.yml if this is a false positive.",
  ].join("\n");
}

// Bound the stdin read so a hung/never-closing stdin can't wedge the hook.
// Overridable via env (milliseconds) as an operator safety valve / for tests.
function stdinTimeoutMs(): number {
  const n = Number(process.env.RAFTER_HOOK_STDIN_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? n : 5000;
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    const onData = (chunk: string) => { data += chunk; };
    const finish = () => {
      clearTimeout(timeout);
      process.stdin.removeListener("data", onData);
      process.stdin.removeListener("end", finish);
      process.stdin.removeListener("error", finish);
      // A piped stdin with no EOF stays in flowing mode and keeps the Node
      // event loop alive indefinitely — even after we resolve. Pause it so the
      // process can exit once the decision is written (was a hard hang on the
      // timeout path: output emitted at 5s but the process never exited).
      process.stdin.pause();
      resolve(data);
    };
    const timeout = setTimeout(finish, stdinTimeoutMs());
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", onData);
    process.stdin.on("end", finish);
    process.stdin.on("error", finish);
    process.stdin.resume();
  });
}

function writeDecision(decision: HookDecision, format: HookFormat): void {
  const isDeny = decision.decision === "deny";
  const reason = decision.reason ?? "";

  switch (format) {
    case "cursor": {
      // Cursor: { permission: "allow"|"deny"|"ask", agentMessage?, userMessage? }
      const output: Record<string, any> = {
        permission: isDeny ? "deny" : "allow",
      };
      if (isDeny && reason) {
        output.agentMessage = reason;
        output.userMessage = reason;
      }
      process.stdout.write(JSON.stringify(output) + "\n");
      break;
    }

    case "gemini": {
      // Gemini: {} for allow, { decision: "deny", reason: "..." } for deny
      if (isDeny) {
        process.stdout.write(JSON.stringify({ decision: "deny", reason }) + "\n");
      } else {
        process.stdout.write("{}\n");
      }
      break;
    }

    case "windsurf": {
      // Windsurf: exit 0 for allow, exit 2 + stderr for deny
      if (isDeny) {
        process.stderr.write(reason + "\n");
        process.exit(2);
      }
      // Allow: exit 0 (no output needed)
      break;
    }

    default: {
      // Claude Code / Codex / Continue.dev: hookSpecificOutput envelope
      const output = {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: isDeny ? "deny" : "allow",
          permissionDecisionReason: reason,
        },
      };
      process.stdout.write(JSON.stringify(output) + "\n");
      break;
    }
  }
}
