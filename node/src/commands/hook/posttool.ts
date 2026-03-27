import { Command } from "commander";
import { RegexScanner } from "../../scanners/regex-scanner.js";
import { AuditLogger } from "../../core/audit-logger.js";

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
    .action(async () => {
      try {
        const input = await readStdin();
        let payload: PostToolInput;

        try {
          payload = JSON.parse(input);
        } catch {
          writeOutput({ action: "continue" });
          return;
        }

        // Validate payload is an object with expected shape
        if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
          writeOutput({ action: "continue" });
          return;
        }

        const output = evaluateToolResponse(payload);
        writeOutput(output);
      } catch {
        // Any unexpected error → fail open
        writeOutput({ action: "continue" });
      }
    });
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

function writeOutput(output: PostToolOutput): void {
  const hookOutput: Record<string, any> = {
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
    },
  };
  if (output.action === "modify" && output.tool_response) {
    hookOutput.hookSpecificOutput.modifiedToolResult = output.tool_response;
  }
  process.stdout.write(JSON.stringify(hookOutput) + "\n");
}
