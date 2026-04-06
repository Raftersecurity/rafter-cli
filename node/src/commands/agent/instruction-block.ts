import fs from "fs";
import path from "path";

export const RAFTER_MARKER_START = "<!-- rafter:start -->";
export const RAFTER_MARKER_END = "<!-- rafter:end -->";

/** Rafter security context block for agent instruction files (CLAUDE.md, AGENTS.md, etc.) */
export const RAFTER_INSTRUCTION_BLOCK = `${RAFTER_MARKER_START}
## Security: Rafter

This environment has Rafter available — the security toolkit built for AI workflows.

**Secure coding rules for this project:**
- Never hardcode API keys, tokens, passwords, or credentials. Use environment variables or secret managers.
- Scan your changes before committing: \`rafter scan local --staged\`
- If Rafter's pre-commit hook blocks a commit, do not bypass with \`--no-verify\` — fix the finding first.
- When generating example configs or test data, use obviously fake values (e.g., \`sk-test-XXXX\`, \`AKIAIOSFODNN7EXAMPLE\`).
- Do not log sensitive values. Rafter's audit log records event metadata only, never raw secrets.

**Local scanning** (always available, no API key needed):
- \`rafter scan local .\` — scan directory for leaked credentials
- \`rafter scan local --staged\` — scan staged changes before committing
- \`rafter scan local --diff HEAD~1\` — scan changes since last commit

**Reading scan output:**
Exit codes: \`0\` = clean, \`1\` = secrets found, \`2\` = runtime error. Use \`--json\` for structured output.
If findings are false positives, add \`exclude_paths\` to \`.rafter.yml\` rather than bypassing the scan.

**Remote analysis** (requires RAFTER_API_KEY):
- \`rafter run\` — SAST, secret detection, dependency checks on the remote repo
- \`rafter run --mode plus\` — agentic deep-dive with additional analysis passes

**Project integration:**
- \`rafter agent install-hook\` — pre-commit secret scanning (blocks commits with secrets)
- \`rafter ci init\` — add scanning to CI/CD pipeline
- \`.rafter.yml\` — project-specific policy (custom patterns, blocked commands, risk level)

**Hooks (if installed via \`rafter agent init --with-claude-code\`):**
PreToolUse hooks intercept Bash commands automatically — dangerous commands are blocked or require
approval without manual intervention. PostToolUse hooks scan file writes for accidentally leaked secrets.
If a command is blocked, check \`rafter agent audit --last 5\` to see why.

**More:**
- \`rafter agent audit-skill <path>\` — audit a skill/extension before installing
- \`rafter agent audit --last 5\` — recent security events
- \`rafter brief commands\` — full CLI reference
- \`rafter brief security\` — full local security toolkit guide
${RAFTER_MARKER_END}`;

/**
 * Write a Rafter instruction block into an instruction file.
 * Uses marker comments for idempotent updates — existing rafter blocks are replaced,
 * non-rafter content is preserved.
 */
export function injectInstructionFile(filePath: string): boolean {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const block = RAFTER_INSTRUCTION_BLOCK;
  const startMarker = RAFTER_MARKER_START;
  const endMarker = RAFTER_MARKER_END;

  let content = "";
  if (fs.existsSync(filePath)) {
    content = fs.readFileSync(filePath, "utf-8");
  }

  // Replace existing block or append
  const startIdx = content.indexOf(startMarker);
  const endIdx = content.indexOf(endMarker);
  if (startIdx !== -1 && endIdx !== -1) {
    content = content.slice(0, startIdx) + block + content.slice(endIdx + endMarker.length);
  } else {
    if (content.length > 0 && !content.endsWith("\n\n")) {
      content += content.endsWith("\n") ? "\n" : "\n\n";
    }
    content += block + "\n";
  }

  fs.writeFileSync(filePath, content, "utf-8");
  return true;
}
