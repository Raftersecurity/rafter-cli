import fs from "fs";
import path from "path";

export const RAFTER_MARKER_START = "<!-- rafter:start -->";
export const RAFTER_MARKER_END = "<!-- rafter:end -->";

/** Rafter security context block for agent instruction files (CLAUDE.md, AGENTS.md, etc.) */
export const RAFTER_INSTRUCTION_BLOCK = `${RAFTER_MARKER_START}
## Security: Rafter (surface-driven review gate)

Rafter is this project's security review gate — driven by the change's **security
surface**, not by the task label. When a diff touches a real surface (below), it is
**not complete** until a rafter skill (or \`rafter run\`) has reviewed it: don't mark
done, don't hand off, don't open a PR without that pass. When it touches **none** of
that surface — research / experimental / local-only / throwaway code (training
scripts, data analysis, plotting, model eval, notebooks, pure computation over
trusted local data) — a quick surface check is enough; proceed without the full
gate. Judge by the diff's actual surface, not the "research" label: research code
that reads a secret, shells out, hits the network, parses untrusted input, or bumps
a dependency still gets the full gate.

**Stop and invoke when the change touches that surface:**

- Designing auth, payments, credentials, tokens, sessions, file upload,
  user/untrusted data, deserialization, network endpoints, or data deletion
  → **\`rafter-secure-design\`** (before writing code).
- Diff touches user/untrusted input, SQL/query building, shell/exec, auth,
  credentials, file paths, (de)serialization, crypto, network endpoints/outbound
  fetchers (SSRF), data deletion, or dependencies → **\`rafter-code-review\`** +
  \`rafter run\` (before declaring done).
- About to install or forward a third-party SKILL.md, MCP manifest, Cursor
  rule, or agent config → **\`rafter-skill-review\`** (before copying anywhere).
- Security-adjacent but the angle isn't clear → **\`rafter\`** (the router skill,
  powerful toolkit to help you write more secure code).

**CLI:**

- \`rafter run\` — remote SAST + SCA + secrets (real code analysis, needs \`RAFTER_API_KEY\`)
- \`rafter secrets .\` — local secrets only (offline; NOT a code-security scan)
- \`rafter run --mode plus\` — everything in default (\`--mode fast\`) plus
  powerful agentic deep-dives (needs \`RAFTER_API_KEY\`). **Plus is a PAID tier
  and consumes the user's credits — ask the user before running it.** Enforced
  when \`scan.plus_requires_approval\` is set (then pass \`--yes\` to confirm).
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
