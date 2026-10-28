import fs from "fs";
import path from "path";

export const RAFTER_MARKER_START = "<!-- rafter:start -->";
export const RAFTER_MARKER_END = "<!-- rafter:end -->";

/** Rafter security context block for agent instruction files (CLAUDE.md, AGENTS.md, etc.) */
export const RAFTER_INSTRUCTION_BLOCK = `${RAFTER_MARKER_START}
## Security: Rafter

Security-relevant code is not done until you have reviewed it yourself. Rafter
gives you the map and the questions; the review is yours. Code is
security-relevant when it decides who may do what, or touches untrusted input,
queries, shell, file paths, parsing or (de)serialization, crypto or TLS,
credentials or tokens, outbound requests, data deletion, or dependencies.
Analysis scripts, plots and pure computation over trusted local data need only
a quick look for those.

- Designing such a feature → **\`rafter-secure-design\`**, before writing code.
- Reviewing a diff or auditing code → **\`rafter-code-review\`**. Start with
  \`rafter gates <path>\`: it lists the functions that make security decisions.
- Installing a third-party skill, MCP server or agent config →
  **\`rafter-skill-review\`**, before copying it anywhere.
- \`rafter secrets <paths>\` finds hardcoded credentials only. A clean result is
  not a code review.
- \`rafter run\` adds remote SAST + SCA on the pushed commit (needs
  \`RAFTER_API_KEY\`). \`--mode plus\` is paid: ask the user first.
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
