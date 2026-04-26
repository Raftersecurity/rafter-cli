import { Command } from "commander";
import { CommandInterceptor, CommandEvaluation } from "../../core/command-interceptor.js";
import { RegexScanner } from "../../scanners/regex-scanner.js";
import { AuditLogger } from "../../core/audit-logger.js";
import { execSync } from "child_process";

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

  if (tool_name === "Bash") {
    return evaluateBash(tool_input?.command || "");
  }

  if (tool_name === "Write" || tool_name === "Edit") {
    return evaluateWrite(tool_input || {});
  }

  return { decision: "allow" };
}

function evaluateBash(command: string): HookDecision {
  const interceptor = new CommandInterceptor();
  const audit = new AuditLogger();
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

  // Git commit/push — scan staged files for secrets
  const trimmed = command.trim();
  if (trimmed.startsWith("git commit") || trimmed.startsWith("git push")) {
    const scanResult = scanStagedFiles();
    if (scanResult.secretsFound) {
      audit.logSecretDetected("staged files", `${scanResult.count} secret(s)`, "blocked");
      return {
        decision: "deny",
        reason: `${scanResult.count} secret(s) detected in ${scanResult.files} staged file(s). Run 'rafter secrets --staged' for details.`,
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

  const scanner = new RegexScanner();
  if (scanner.hasSecrets(content)) {
    const matches = scanner.scanText(content);
    const names = [...new Set(matches.map(m => m.pattern.name))];
    const audit = new AuditLogger();
    audit.logSecretDetected(
      toolInput.file_path || "file content",
      names.join(", "),
      "blocked",
    );
    return {
      decision: "deny",
      reason: `Secret detected in file content: ${names.join(", ")}`,
    };
  }

  return { decision: "allow" };
}

function scanStagedFiles(): { secretsFound: boolean; count: number; files: number } {
  try {
    const stagedOutput = execSync("git diff --cached --name-only --diff-filter=ACM", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();

    if (!stagedOutput) {
      return { secretsFound: false, count: 0, files: 0 };
    }

    const stagedFiles = stagedOutput.split("\n").filter(f => f.trim());
    const scanner = new RegexScanner();
    const results = scanner.scanFiles(stagedFiles);
    const totalMatches = results.reduce((sum, r) => sum + r.matches.length, 0);

    return {
      secretsFound: results.length > 0,
      count: totalMatches,
      files: results.length,
    };
  } catch {
    return { secretsFound: false, count: 0, files: 0 };
  }
}

const STDIN_TIMEOUT_MS = 5000;

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    const timeout = setTimeout(() => { resolve(data); }, STDIN_TIMEOUT_MS);
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk) => { data += chunk; });
    process.stdin.on("end", () => { clearTimeout(timeout); resolve(data); });
    process.stdin.on("error", () => { clearTimeout(timeout); resolve(data); });
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
