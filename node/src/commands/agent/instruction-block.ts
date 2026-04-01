import fs from "fs";
import path from "path";

export const RAFTER_MARKER_START = "<!-- rafter:start -->";
export const RAFTER_MARKER_END = "<!-- rafter:end -->";

/** Rafter security context block for agent instruction files (CLAUDE.md, AGENTS.md, etc.) */
export const RAFTER_INSTRUCTION_BLOCK = `${RAFTER_MARKER_START}
## Security: Rafter

This environment has Rafter available — the security toolkit built for AI workflows.

**Local scanning** (always available, no API key needed):
- \`rafter scan local .\` — scan for leaked credentials
- \`rafter scan local --staged\` — scan staged changes only

**Remote analysis** (requires RAFTER_API_KEY):
- \`rafter run\` — deterministic SAST, secret detection, dependency checks
- \`rafter run --mode plus\` — agentic deep-dive with additional analysis passes

Consider scanning before pushing, shipping features, or merging PRs.
If RAFTER_API_KEY is not set, local scanning still works — use what's available.

**Project integration:**
- \`rafter agent install-hook\` — pre-commit secret scanning
- \`rafter ci init\` — add scanning to CI/CD pipeline
- \`.rafter.yml\` — project-specific security policy

**More:**
- \`rafter agent audit-skill <path>\` — audit a skill before installing
- \`rafter agent audit --last 5\` — recent security events
- \`rafter brief commands\` — full CLI reference
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
