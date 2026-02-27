import { Command } from "commander";
import { CommandInterceptor, CommandEvaluation } from "../../core/command-interceptor.js";
import { RegexScanner } from "../../scanners/regex-scanner.js";
import { AuditLogger } from "../../core/audit-logger.js";
import { execSync } from "child_process";

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
    .action(async () => {
      const input = await readStdin();
      let payload: HookInput;

      try {
        payload = JSON.parse(input);
      } catch {
        // Can't parse → fail open
        writeDecision({ decision: "allow" });
        return;
      }

      const decision = evaluateToolCall(payload);
      writeDecision(decision);
    });
}

function evaluateToolCall(payload: HookInput): HookDecision {
  const { tool_name, tool_input } = payload;

  if (tool_name === "Bash") {
    return evaluateBash(tool_input.command || "");
  }

  if (tool_name === "Write" || tool_name === "Edit") {
    return evaluateWrite(tool_input);
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
        reason: `${scanResult.count} secret(s) detected in ${scanResult.files} staged file(s). Run 'rafter scan local --staged' for details.`,
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

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk) => { data += chunk; });
    process.stdin.on("end", () => { resolve(data); });
    process.stdin.resume();
  });
}

function writeDecision(decision: HookDecision): void {
  process.stdout.write(JSON.stringify(decision) + "\n");
}
