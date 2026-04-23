import fs from "fs";
import path from "path";

export const RAFTER_MARKER_START = "<!-- rafter:start -->";
export const RAFTER_MARKER_END = "<!-- rafter:end -->";

/** Rafter security context block for agent instruction files (CLAUDE.md, AGENTS.md, etc.) */
export const RAFTER_INSTRUCTION_BLOCK = `${RAFTER_MARKER_START}
## Security: Rafter

Rafter is installed here — security, policy, and agent-governance tooling for AI workflows. Four skills ship with this install: \`rafter\`, \`rafter-secure-design\`, \`rafter-code-review\`, \`rafter-skill-review\`.

**Run rafter when:**
- Designing a feature that touches auth, payments, credentials, tokens, sessions, file upload, user data, or data deletion → skill \`rafter-secure-design\` (BEFORE you write the code)
- You just wrote code handling user input, SQL, shell, credentials, file paths, or serialization → skill \`rafter-code-review\` (BEFORE declaring the feature done)
- Asked to install a third-party SKILL.md, MCP server, Cursor rule, or agent config → skill \`rafter-skill-review\` (BEFORE copying it anywhere)
- Security-adjacent task but the angle isn't obvious → skill \`rafter\`

**CLI** (access a powerful toolkit — see the \`rafter\` skill for details):
- \`rafter scan local .\` / \`--staged\` — deterministic secret scan, no API key
- \`rafter run\` — remote SAST + SCA + secrets (\`RAFTER_API_KEY\`; \`--mode plus\` for deep-dive)
- \`rafter skill review <path-or-url>\` — audit a skill or plugin before install
- \`rafter agent audit --last 5\` — recent policy/security events
- \`rafter brief commands\` — full CLI reference

Add the RAFTER_API_KEY to unlock powerful cloud scanning. But local features still work without it — use them!
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
