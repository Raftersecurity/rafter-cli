import { Command } from "commander";
import { readFileSync, readdirSync, existsSync } from "fs";
import path from "path";

/**
 * Stop hook — fires when the agent tries to end its turn. If the session
 * hasn't touched rafter yet (no `rafter scan local` and no `rafter-*` skill
 * invocation), block once with a short directive. On the second stop attempt
 * (`stop_hook_active: true`), always allow — we never loop the agent.
 *
 * Token cost is zero on the success path (empty object) and ~30 tokens on
 * block. The block fires at most once per session.
 */

export const STOP_DIRECTIVE =
  "Before finishing: run `rafter scan local .` to catch secrets in the work " +
  "you just did. If you touched auth, payments, credentials, file upload, or " +
  "data deletion, also invoke the `rafter-secure-design` skill to review the design.";

interface StopInput {
  transcript_path?: string;
  stop_hook_active?: boolean;
}

export function createHookStopCommand(): Command {
  return new Command("stop")
    .description("Stop hook handler (blocks completion until rafter scan or skill has run)")
    .option("--format <format>", "Output format: claude (default)", "claude")
    .action(async () => {
      try {
        const raw = await readStdin();
        let input: StopInput = {};
        try { input = JSON.parse(raw) || {}; } catch { /* treat as empty */ }

        // If we've already blocked once this session, always allow — prevents loops.
        if (input.stop_hook_active) {
          process.stdout.write("{}\n");
          return;
        }

        const transcript = input.transcript_path;
        if (!transcript || !transcriptTouchedRafter(transcript)) {
          process.stdout.write(JSON.stringify({
            decision: "block",
            reason: STOP_DIRECTIVE,
          }) + "\n");
          return;
        }

        process.stdout.write("{}\n");
      } catch {
        // Fail open — never trap the agent if the hook itself breaks.
        process.stdout.write("{}\n");
      }
    });
}

/**
 * Scan transcript JSONL for evidence of rafter engagement:
 *   - Bash tool_use with command containing `rafter scan` / `rafter mcp` / `rafter skill`
 *   - Skill tool_use targeting a `rafter-*` skill
 *
 * Also scans subagent transcripts (Claude Code writes them under a sibling
 * `<main_transcript_basename>/subagents/*.jsonl` directory) so delegated work
 * counts toward engagement.
 */
export function transcriptTouchedRafter(transcriptPath: string): boolean {
  if (scanSingleTranscript(transcriptPath)) return true;

  // Subagent transcripts live at `<dir>/<mainBasename-without-.jsonl>/subagents/*.jsonl`.
  const dir = path.dirname(transcriptPath);
  const base = path.basename(transcriptPath, ".jsonl");
  const subDir = path.join(dir, base, "subagents");
  if (!existsSync(subDir)) return false;

  let subFiles: string[] = [];
  try { subFiles = readdirSync(subDir).filter((f) => f.endsWith(".jsonl")); } catch { return false; }
  for (const f of subFiles) {
    if (scanSingleTranscript(path.join(subDir, f))) return true;
  }
  return false;
}

function scanSingleTranscript(p: string): boolean {
  let text: string;
  try { text = readFileSync(p, "utf-8"); } catch { return false; }

  for (const line of text.split("\n")) {
    if (!line) continue;
    let entry: any;
    try { entry = JSON.parse(line); } catch { continue; }

    const content = entry?.message?.content;
    if (!Array.isArray(content)) continue;

    for (const block of content) {
      if (!block || block.type !== "tool_use") continue;
      const name = block.name || "";
      const input = block.input || {};

      if (name === "Bash") {
        const cmd = String(input.command || "");
        if (/\brafter\s+(scan|mcp|skill|agent\s+scan|agent\s+audit)\b/.test(cmd)) {
          return true;
        }
      }

      if (name === "Skill") {
        const skill = String(input.skill || input.name || "");
        if (skill.startsWith("rafter-") || skill.startsWith("rafter:")) {
          return true;
        }
      }
    }
  }
  return false;
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
