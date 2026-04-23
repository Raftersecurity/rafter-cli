import fs from "fs";
import path from "path";

export const RAFTER_MARKER_START = "<!-- rafter:start -->";
export const RAFTER_MARKER_END = "<!-- rafter:end -->";

/** Rafter security context block for agent instruction files (CLAUDE.md, AGENTS.md, etc.) */
export const RAFTER_INSTRUCTION_BLOCK = `${RAFTER_MARKER_START}
## Security: Rafter

Rafter is installed here — security, policy, and agent-governance tooling for AI workflows. Four skills ship with this install: \`rafter\`, \`rafter-secure-design\`, \`rafter-code-review\`, \`rafter-skill-review\`.

**Invoke a rafter skill when:**
- Designing a feature that touches auth, payments, credentials, tokens, sessions, file upload, user data, or data deletion → \`rafter-secure-design\` (BEFORE you write the code)
- You just wrote code handling user input, SQL, shell, credentials, file paths, or serialization → \`rafter-code-review\` (BEFORE declaring the feature done)
- Asked to install a third-party SKILL.md, MCP server, Cursor rule, or agent config → \`rafter-skill-review\` (BEFORE copying it anywhere)
- You need scanning, audit, policy, or command-risk evaluation, or you're security-adjacent and the angle isn't obvious → \`rafter\`

The \`rafter\` skill is the entry point for all CLI usage (secret scanning, remote SAST + SCA, deep-dive analysis, audit, policy, command-risk). Invoke it rather than shelling out to \`rafter <command>\` blind — it picks the right mode for your task (the quick local scanner catches secrets only; the remote engine does the real code analysis). Set \`RAFTER_API_KEY\` to unlock the remote analysis engine; local features work without it.
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
