import { Command } from "commander";
import { RegexScanner } from "../../scanners/regex-scanner.js";
import { AuditLogger } from "../../core/audit-logger.js";
import { persistSecrets, EnvWriteResult, SecretToPersist } from "../../core/env-writer.js";
import {
  PROMPT_SHIELD_PATTERNS,
  PromptShieldPattern,
  DEFAULT_PATTERN_ENV_NAMES,
  CREDENTIAL_KEYWORD_RE,
} from "../../scanners/prompt-shield-patterns.js";

type Mode = "warn" | "block";

interface PromptHookInput {
  session_id?: string;
  prompt?: string;
  cwd?: string;
}

interface DetectedSecret {
  /** Pattern name for audit / display. */
  patternName: string;
  /** Suggested env var basename. */
  envBaseName: string;
  /** The actual secret value to persist. */
  value: string;
}

const STDIN_TIMEOUT_MS = 5000;

export function createHookUserPromptSubmitCommand(): Command {
  return new Command("user-prompt-submit")
    .description(
      "UserPromptSubmit hook handler — detects secrets in the user's prompt, " +
      "persists them to .env, ensures .gitignore covers .env, and warns the model."
    )
    .option(
      "--mode <mode>",
      "warn (default): pass prompt through with warning context; block: stop the prompt and require re-submit",
      process.env.RAFTER_PROMPT_SHIELD_MODE || "warn"
    )
    .action(async (opts) => {
      // Hard kill switch — RAFTER_PROMPT_SHIELD=0 disables entirely.
      if (process.env.RAFTER_PROMPT_SHIELD === "0") {
        emitNoop();
        return;
      }

      try {
        const raw = await readStdin();
        let payload: PromptHookInput;
        try {
          payload = JSON.parse(raw);
        } catch {
          emitNoop();
          return;
        }

        if (!payload || typeof payload !== "object" || typeof payload.prompt !== "string" || !payload.prompt) {
          emitNoop();
          return;
        }

        const detected = detectSecrets(payload.prompt);
        if (detected.length === 0) {
          emitNoop();
          return;
        }

        const root = typeof payload.cwd === "string" && payload.cwd ? payload.cwd : process.cwd();
        const toPersist: SecretToPersist[] = detected.map((d) => ({
          baseName: d.envBaseName,
          value: d.value,
        }));

        let result: EnvWriteResult;
        try {
          result = persistSecrets(toPersist, root);
        } catch {
          // .env write failed (permission, disk, etc.) — degrade to a warn-only
          // notice so we don't break the user's flow.
          emitWarn(
            buildContextNote(detected, null, []),
            opts.mode as Mode
          );
          return;
        }

        // Audit-log a single content_sanitized entry per prompt.
        try {
          const audit = new AuditLogger();
          audit.logContentSanitized("user prompt", detected.length);
        } catch {
          // Never let audit errors break the hook.
        }

        const note = buildContextNote(detected, result, result.written);
        const mode: Mode = opts.mode === "block" ? "block" : "warn";
        if (mode === "block") {
          emitBlock(note);
        } else {
          emitWarn(note, mode);
        }
      } catch {
        emitNoop();
      }
    });
}

/**
 * Run all prompt-shield + default-secret patterns against `text`, returning
 * one DetectedSecret per match. Deduplicates on (patternName, value) so we
 * don't double-count a value matched by two overlapping patterns.
 */
function detectSecrets(text: string): DetectedSecret[] {
  const seen = new Set<string>();
  const out: DetectedSecret[] = [];

  // 1. Prompt-shield patterns (capture-group aware)
  for (const p of PROMPT_SHIELD_PATTERNS) {
    const re = freshRegex(p.regex);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const value = m[p.valueGroup];
      if (!value || isLikelyPlaceholder(value)) continue;
      // For the assignment pattern, gate on the LHS identifier containing a
      // credential keyword — we matched a broad identifier shape, so skip
      // assignments like "size=200" or "user=alice".
      if (p.name === "Inline credential assignment") {
        const lhs = m[1] || "";
        if (!CREDENTIAL_KEYWORD_RE.test(lhs)) continue;
      }
      const key = `${p.name}\x00${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        patternName: p.name,
        envBaseName: deriveEnvName(p, m),
        value,
      });
      if (re.lastIndex === m.index) re.lastIndex++; // guard against zero-width
    }
  }

  // 2. Default secret patterns (full match = value)
  const scanner = new RegexScanner();
  const matches = scanner.scanText(text);
  for (const match of matches) {
    const value = match.match;
    if (!value || isLikelyPlaceholder(value)) continue;
    const baseName = DEFAULT_PATTERN_ENV_NAMES[match.pattern.name] || "RAFTER_SECRET";
    const key = `${match.pattern.name}\x00${value}`;
    if (seen.has(key)) continue;
    // Also dedupe across pattern types: if this value was already captured by a
    // prompt-shield pattern, skip — the more-specific provider name wins.
    let dupValue = false;
    for (const prior of out) {
      if (prior.value === value) { dupValue = true; break; }
    }
    if (dupValue) continue;
    seen.add(key);
    out.push({
      patternName: match.pattern.name,
      envBaseName: baseName,
      value,
    });
  }

  return out;
}

/**
 * Pick a meaningful env basename from a prompt-shield match. For assignment-
 * style patterns the keyword group (e.g. "DB_PASSWORD" in "DB_PASSWORD=foo")
 * is a much better name than the generic envBaseName fallback.
 */
function deriveEnvName(p: PromptShieldPattern, m: RegExpExecArray): string {
  // For assignment-style matches, the captured LHS identifier (e.g. DB_PASSWORD)
  // is a much better env var name than the generic fallback.
  if (p.name === "Inline credential assignment" && m[1]) return m[1];
  return p.envBaseName;
}

/**
 * Reject obvious documentation placeholders so we don't write
 * "RAFTER_SECRET=your-api-key-here" to .env.
 */
function isLikelyPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  if (lower.includes("xxx") && lower.length < 16) return true;
  if (lower === "your-secret" || lower === "your_secret") return true;
  if (lower === "changeme" || lower === "change-me") return true;
  if (/^<.+>$/.test(value)) return true;        // <your-key>
  if (/^\$\{?[A-Z_][A-Z0-9_]*\}?$/.test(value)) return true; // already a $VAR
  if (/^example/.test(lower)) return true;
  return false;
}

function buildContextNote(
  detected: DetectedSecret[],
  result: EnvWriteResult | null,
  written: { name: string; value: string; alreadyPresent: boolean }[]
): string {
  const lines: string[] = [];
  lines.push("🔐 Rafter prompt-shield: detected " +
    detected.length + (detected.length === 1 ? " secret" : " secrets") +
    " in the user's prompt.");

  if (result) {
    const newlyWritten = written.filter((w) => !w.alreadyPresent);
    const reused = written.filter((w) => w.alreadyPresent);

    if (newlyWritten.length > 0) {
      lines.push(`Written to ${result.envFilePath}:`);
      for (const w of newlyWritten) lines.push(`  - $${w.name}`);
    }
    if (reused.length > 0) {
      lines.push(`Already in ${result.envFilePath} (reusing existing entries):`);
      for (const w of reused) lines.push(`  - $${w.name}`);
    }

    const envStateBits: string[] = [];
    if (result.envFileCreated) envStateBits.push(".env was created");
    if (result.gitignoreCreated) envStateBits.push(".gitignore was created with .env");
    else if (result.gitignoreUpdated) envStateBits.push(".env was added to .gitignore");
    if (envStateBits.length > 0) lines.push("(" + envStateBits.join("; ") + ")");
  } else {
    lines.push("Could not write to .env in the project directory.");
    for (const d of detected) lines.push(`  - ${d.patternName}`);
  }

  lines.push("");
  lines.push("⚠️ Treat these literal values as sensitive:");
  lines.push("  - Do NOT echo them back in your reply.");
  lines.push("  - Do NOT write them into source files.");
  lines.push("  - Reference them via the env var names above (e.g., process.env.DB_PASSWORD, os.environ['DB_PASSWORD']).");

  return lines.join("\n");
}

/* ---------------- I/O ---------------- */

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    const timeout = setTimeout(() => resolve(data), STDIN_TIMEOUT_MS);
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk) => { data += chunk; });
    process.stdin.on("end", () => { clearTimeout(timeout); resolve(data); });
    process.stdin.on("error", () => { clearTimeout(timeout); resolve(data); });
    process.stdin.resume();
  });
}

function emitNoop(): void {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: { hookEventName: "UserPromptSubmit" },
    }) + "\n"
  );
}

function emitWarn(note: string, _mode: Mode): void {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "UserPromptSubmit",
        additionalContext: note,
      },
    }) + "\n"
  );
}

function emitBlock(note: string): void {
  process.stdout.write(
    JSON.stringify({
      decision: "block",
      reason: note + "\n\nRe-submit your prompt referencing the env var names above instead of the literal values.",
    }) + "\n"
  );
}

/**
 * Construct a fresh RegExp with the same source/flags, so each call starts
 * with lastIndex=0 (the source PROMPT_SHIELD_PATTERNS hold global regexes
 * which would otherwise carry state between calls).
 */
function freshRegex(re: RegExp): RegExp {
  return new RegExp(re.source, re.flags);
}
