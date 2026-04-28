import { Command } from "commander";
import { AuditLogger } from "../../core/audit-logger.js";
import { persistSecrets, SecretToPersist, EnvWriteResult } from "../../core/env-writer.js";
import { detectSecrets, replaceSecretsWithRefs, DetectedSecret } from "../../core/prompt-shield.js";

/**
 * Gemini CLI `BeforeModel` hook handler.
 *
 * Unlike Claude Code's UserPromptSubmit (additionalContext-only), Gemini's
 * BeforeModel hook can REWRITE the outgoing request. We use that to remove
 * literal secrets from user-role messages and substitute $VAR references —
 * the model never sees the literal values.
 *
 * Verified contract (gemini-cli main, packages/core/src/hooks/types.ts:674,
 * packages/core/src/core/geminiChat.ts:628):
 *
 *   stdin: {
 *     llm_request: {
 *       model: string;
 *       messages: Array<{
 *         role: 'user' | 'model' | 'system';
 *         content: string | Array<{ type: string; text?: string; ... }>;
 *       }>;
 *       config?: { ... };
 *     };
 *     ... (session_id, cwd, hook_event_name)
 *   }
 *
 *   stdout: {
 *     hookSpecificOutput?: {
 *       hookEventName: "BeforeModel";
 *       llm_request?: Partial<LLMRequest>;   // overrides outgoing request
 *       llm_response?: ...;                  // synthetic response (unused)
 *     };
 *   }
 */

const STDIN_TIMEOUT_MS = 5000;

interface BeforeModelInput {
  session_id?: string;
  cwd?: string;
  llm_request?: {
    model?: string;
    messages?: any[];
    config?: any;
  };
}

export function createHookBeforeModelCommand(): Command {
  return new Command("before-model")
    .description(
      "Gemini BeforeModel hook handler — scans user messages for secrets, " +
      "rewrites the outgoing request to substitute $VAR references for literals, " +
      "and persists detected values to .env."
    )
    .action(async () => {
      // Hard kill switch
      if (process.env.RAFTER_PROMPT_SHIELD === "0") {
        emitNoop();
        return;
      }

      try {
        const raw = await readStdin();
        let payload: BeforeModelInput;
        try {
          payload = JSON.parse(raw);
        } catch {
          emitNoop();
          return;
        }

        if (!payload || typeof payload !== "object" || !payload.llm_request ||
            !Array.isArray(payload.llm_request.messages)) {
          emitNoop();
          return;
        }

        const messages = payload.llm_request.messages;
        // Aggregate detection across all user messages so we share .env writes
        // and value→name mapping for substitution.
        const allDetected: DetectedSecret[] = [];
        const userMsgIndices: number[] = [];
        const userMsgTexts: string[] = [];

        for (let i = 0; i < messages.length; i++) {
          const msg = messages[i];
          if (!msg || msg.role !== "user") continue;
          const text = extractText(msg.content);
          if (!text) continue;
          userMsgIndices.push(i);
          userMsgTexts.push(text);
          for (const d of detectSecrets(text)) {
            // Dedupe by value across all user messages.
            if (!allDetected.some((existing) => existing.value === d.value)) {
              allDetected.push(d);
            }
          }
        }

        if (allDetected.length === 0) {
          emitNoop();
          return;
        }

        const root = typeof payload.cwd === "string" && payload.cwd ? payload.cwd : process.cwd();
        const toPersist: SecretToPersist[] = allDetected.map((d) => ({
          baseName: d.envBaseName,
          value: d.value,
        }));

        let result: EnvWriteResult;
        try {
          result = persistSecrets(toPersist, root);
        } catch {
          // .env write failed — degrade to no-op rather than send the secret
          // through unmodified. Better to fail-closed here than leak.
          emitNoop();
          return;
        }

        // Build value → final-name map from the persistence result.
        const valueToName = new Map<string, string>();
        for (const w of result.written) valueToName.set(w.value, w.name);

        // Rewrite each user message in-place.
        const newMessages = messages.map((msg, i) => {
          if (!userMsgIndices.includes(i)) return msg;
          return rewriteUserMessage(msg, allDetected, valueToName);
        });

        try {
          const audit = new AuditLogger();
          audit.logContentSanitized("Gemini llm_request user messages", allDetected.length);
        } catch { /* never break hook */ }

        emitOverride(newMessages);
      } catch {
        emitNoop();
      }
    });
}

/* ---------------- message helpers ---------------- */

/**
 * Extract concatenated text from a Gemini message content. Handles both the
 * stable hook shape (string OR Array<{type,...}>) and the SDK-native
 * Array<{text}> shape that may slip through.
 */
function extractText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === "string") return part;
        if (part && typeof part === "object" && typeof (part as any).text === "string") {
          return (part as any).text;
        }
        return "";
      })
      .join("");
  }
  return "";
}

function rewriteUserMessage(
  msg: any,
  detected: DetectedSecret[],
  valueToName: Map<string, string>
): any {
  if (!msg || typeof msg !== "object") return msg;
  const content = msg.content;

  if (typeof content === "string") {
    return { ...msg, content: replaceSecretsWithRefs(content, detected, valueToName) };
  }

  if (Array.isArray(content)) {
    const newParts = content.map((part) => {
      if (part && typeof part === "object" && typeof (part as any).text === "string") {
        return { ...part, text: replaceSecretsWithRefs((part as any).text, detected, valueToName) };
      }
      return part;
    });
    return { ...msg, content: newParts };
  }

  return msg;
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
      hookSpecificOutput: { hookEventName: "BeforeModel" },
    }) + "\n"
  );
}

function emitOverride(messages: any[]): void {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "BeforeModel",
        llm_request: { messages },
      },
    }) + "\n"
  );
}
