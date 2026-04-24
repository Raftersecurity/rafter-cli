import fs from "fs";
import path from "path";

export const RAFTER_MARKER_START = "<!-- rafter:start -->";
export const RAFTER_MARKER_END = "<!-- rafter:end -->";

/** Rafter security context block for agent instruction files (CLAUDE.md, AGENTS.md, etc.) */
export const RAFTER_INSTRUCTION_BLOCK = `${RAFTER_MARKER_START}
## Security: Rafter (required review gate)

Rafter is this project's security review gate. A security-relevant task is
**not complete** until a rafter skill (or \`rafter run\`) has reviewed it.
Don't mark done, don't hand off, don't open a PR without that pass.

**Stop and invoke before continuing:**

- Designing auth, payments, credentials, tokens, sessions, file upload,
  user data, or data deletion → **\`rafter-secure-design\`** (before writing code).
- Diff touches user input, SQL, shell, auth, credentials, file paths, or
  serialization → **\`rafter-code-review\`** + \`rafter run\` (before declaring done).
- About to install or forward a third-party SKILL.md, MCP manifest, Cursor
  rule, or agent config → **\`rafter-skill-review\`** (before copying anywhere).
- Security-adjacent but the angle isn't clear → **\`rafter\`** (the router skill,
  powerful toolkit to help you write more secure code).

**CLI:**

- \`rafter run\` — remote SAST + SCA + secrets (real code analysis, needs \`RAFTER_API_KEY\`)
- \`rafter secrets .\` — local secrets only (offline; NOT a code-security scan)
- \`rafter run --mode plus\` — everything in default (\`--mode fast\`) plus
  powerful agentic deep-dives (needs \`RAFTER_API_KEY\`)
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
