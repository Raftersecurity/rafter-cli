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
 * Aider has no skill-loading mechanism — `rafter-secure-design`,
 * `rafter-code-review`, and `rafter-skill-review` above are names, not files
 * it can load, unlike Claude Code / Codex / Gemini where each one is a real
 * skill directory. This note tells an Aider session what's actually runnable
 * instead of leaving those names as dead pointers.
 */
export const AIDER_NOTE_MARKER_START = "<!-- rafter:aider-note:start -->";
export const AIDER_NOTE_MARKER_END = "<!-- rafter:aider-note:end -->";

export const AIDER_SKILL_NOTE = `${AIDER_NOTE_MARKER_START}
**Note for Aider**: the skill names above (\`rafter\`, \`rafter-secure-design\`,
\`rafter-code-review\`, \`rafter-skill-review\`) are not separate files here —
Aider has no skill-loading mechanism, only this one file. For the fuller
walkthroughs those skills provide on other platforms, run these in a terminal:
\`rafter brief shift-left\` (design & review routing), \`rafter brief scanning\`
(full CLI + guardrails), or \`rafter skill review <path>\` (the real pre-install
check).
${AIDER_NOTE_MARKER_END}`;

/** Shared idempotent marker-block injector: replace the block between the given
 * markers if present, otherwise append it. */
function injectMarkedBlock(
  filePath: string,
  block: string,
  startMarker: string,
  endMarker: string,
): boolean {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

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

/**
 * Write a Rafter instruction block into an instruction file.
 * Uses marker comments for idempotent updates — existing rafter blocks are replaced,
 * non-rafter content is preserved.
 */
export function injectInstructionFile(filePath: string): boolean {
  return injectMarkedBlock(filePath, RAFTER_INSTRUCTION_BLOCK, RAFTER_MARKER_START, RAFTER_MARKER_END);
}

/**
 * Append (or idempotently update) the Aider-specific skill note. Separate
 * marker pair from the main block, so this can live alongside it in the same
 * file (RAFTER.md) without disturbing the shared instruction block.
 */
export function injectAiderNote(filePath: string): boolean {
  return injectMarkedBlock(filePath, AIDER_SKILL_NOTE, AIDER_NOTE_MARKER_START, AIDER_NOTE_MARKER_END);
}
