import { Command } from "commander";

type SessionStartFormat = "claude";

/**
 * Directive injected once per session (SessionStart fires on startup/resume/clear).
 * Goal: get agents to organically invoke the rafter-secure-design / rafter-code-review
 * skills and run `rafter scan local .` before shipping, without relying on a
 * verbose CLAUDE.md block. Keep this short — it lands in the model's context on
 * every session, so every word counts.
 */
export const SESSION_START_DIRECTIVE =
  "Rafter is active in this project. Before `git commit` or signalling a task is done, " +
  "run `rafter scan local .` to catch secrets. When working on auth, payments, credentials, " +
  "file upload, or data deletion, invoke the `rafter-secure-design` skill before writing code.";

export function createHookSessionStartCommand(): Command {
  return new Command("session-start")
    .description("SessionStart hook handler (emits additionalContext to steer agent toward rafter skills)")
    .option("--format <format>", "Output format: claude (default)", "claude")
    .action(async (opts) => {
      const format = (opts.format || "claude") as SessionStartFormat;
      try {
        // Drain stdin without blocking — some agents send a JSON payload we don't need.
        await readStdin();
        writeDirective(format);
      } catch {
        // Any unexpected error → emit nothing so the agent isn't disrupted.
        process.stdout.write("{}\n");
      }
    });
}

function writeDirective(format: SessionStartFormat): void {
  // Claude Code SessionStart contract: { hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: "..." } }
  const output = {
    hookSpecificOutput: {
      hookEventName: "SessionStart",
      additionalContext: SESSION_START_DIRECTIVE,
    },
  };
  process.stdout.write(JSON.stringify(output) + "\n");
}

const STDIN_TIMEOUT_MS = 1000;

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
