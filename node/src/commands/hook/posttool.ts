import { Command } from "commander";
import { RegexScanner } from "../../scanners/regex-scanner.js";
import { AuditLogger } from "../../core/audit-logger.js";

type HookFormat = "claude" | "cursor" | "gemini" | "windsurf";

interface PostToolInput {
  session_id?: string;
  tool_name: string;
  tool_input: Record<string, any>;
  tool_response?: {
    output?: string;
    content?: string;
    error?: string;
  };
}

interface PostToolOutput {
  action: "continue" | "modify";
  tool_response?: Record<string, any>;
}

export function createHookPosttoolCommand(): Command {
  return new Command("posttool")
    .description("PostToolUse hook handler (reads stdin, redacts secrets in output, writes JSON to stdout)")
    .option("--format <format>", "Output format: claude (default, also Codex/Continue), cursor, gemini, windsurf", "claude")
    .action(async (opts) => {
      const format = (opts.format || "claude") as HookFormat;
      try {
        const input = await readStdin();
        let raw: Record<string, any>;

        try {
          raw = JSON.parse(input);
        } catch {
          writeOutput({ action: "continue" }, format);
          return;
        }

        // Validate payload is an object with expected shape
        if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
          writeOutput({ action: "continue" }, format);
          return;
        }

        const payload = normalizePostInput(raw, format);
        const output = evaluateToolResponse(payload);
        writeOutput(output, format);
      } catch {
        // Any unexpected error → fail open
        writeOutput({ action: "continue" }, format);
      }
    });
}

/**
 * Normalize platform-specific PostToolUse stdin into common shape.
 * Windsurf sends { tool_info: { stdout, stderr } }, Cursor sends { output, ... }.
 */
function normalizePostInput(raw: Record<string, any>, format: HookFormat): PostToolInput {
  if (format === "windsurf") {
    const toolInfo = raw.tool_info || {};
    return {
      session_id: raw.trajectory_id,
      tool_name: raw.agent_action_name?.includes("run_command") ? "Bash" : (toolInfo.mcp_tool_name || "unknown"),
      tool_input: {},
      tool_response: {
        output: toolInfo.stdout || toolInfo.output || "",
        error: toolInfo.stderr || "",
      },
    };
  }

  if (format === "cursor") {
    return {
      session_id: raw.conversation_id,
      tool_name: raw.hook_event_name === "afterShellExecution" ? "Bash" : (raw.tool_name || "unknown"),
      tool_input: raw.tool_input || {},
      tool_response: {
        output: raw.output || raw.tool_response?.output || "",
        content: raw.content || raw.tool_response?.content || "",
        error: raw.error || raw.tool_response?.error || "",
      },
    };
  }

  // Claude, Codex, Continue, Gemini — same shape
  return {
    session_id: raw.session_id,
    tool_name: raw.tool_name || "",
    tool_input: raw.tool_input || {},
    tool_response: raw.tool_response,
  };
}

function evaluateToolResponse(payload: PostToolInput): PostToolOutput {
  const { tool_response } = payload;

  // No response body — pass through
  if (!tool_response) {
    return { action: "continue" };
  }

  const scanner = new RegexScanner();
  let modified = false;
  const redacted: Record<string, any> = { ...tool_response };

  // Scan and redact output
  if (typeof tool_response.output === "string" && tool_response.output) {
    if (scanner.hasSecrets(tool_response.output)) {
      redacted.output = scanner.redact(tool_response.output);
      modified = true;
    }
  }

  // Scan and redact content (used by some tools)
  if (typeof tool_response.content === "string" && tool_response.content) {
    if (scanner.hasSecrets(tool_response.content)) {
      redacted.content = scanner.redact(tool_response.content);
      modified = true;
    }
  }

  if (modified) {
    const audit = new AuditLogger();
    const matchCount = countMatches(scanner, tool_response);
    audit.logContentSanitized(`${payload.tool_name} tool response`, matchCount);
    return { action: "modify", tool_response: redacted };
  }

  return { action: "continue" };
}

function countMatches(scanner: RegexScanner, tool_response: PostToolInput["tool_response"]): number {
  let count = 0;
  if (typeof tool_response?.output === "string" && tool_response.output) {
    count += scanner.scanText(tool_response.output).length;
  }
  if (typeof tool_response?.content === "string" && tool_response.content) {
    count += scanner.scanText(tool_response.content).length;
  }
  return count;
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

function writeOutput(output: PostToolOutput, format: HookFormat): void {
  const isModify = output.action === "modify" && output.tool_response;

  switch (format) {
    case "cursor": {
      // Cursor: { agentMessage?: string } for post-tool notifications
      if (isModify) {
        process.stdout.write(JSON.stringify({
          agentMessage: "Rafter redacted secrets from tool output",
        }) + "\n");
      }
      // No output for continue (noop)
      break;
    }

    case "gemini": {
      // Gemini AfterTool: { systemMessage?: string } or {}
      if (isModify) {
        process.stdout.write(JSON.stringify({
          systemMessage: "Rafter redacted secrets from tool output",
        }) + "\n");
      } else {
        process.stdout.write("{}\n");
      }
      break;
    }

    case "windsurf": {
      // Windsurf: exit 0 for continue, stderr for notification
      if (isModify) {
        process.stderr.write("Rafter: secrets redacted from tool output\n");
      }
      // Always exit 0 for post-tool (never block after execution)
      break;
    }

    default: {
      // Claude Code / Codex / Continue.dev: hookSpecificOutput envelope
      const hookOutput: Record<string, any> = {
        hookSpecificOutput: {
          hookEventName: "PostToolUse",
        },
      };
      if (isModify) {
        hookOutput.hookSpecificOutput.modifiedToolResult = output.tool_response;
      }
      process.stdout.write(JSON.stringify(hookOutput) + "\n");
      break;
    }
  }
}
