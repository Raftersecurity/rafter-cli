import { Command } from "commander";
import { AuditLogger } from "../../core/audit-logger.js";
import { persistSecrets, SecretToPersist, EnvWriteResult } from "../../core/env-writer.js";
import { detectSecrets, replaceSecretsWithRefs } from "../../core/prompt-shield.js";

/**
 * Hermes `pre_gateway_dispatch` hook handler (stdio adapter).
 *
 * Hermes hooks are normally in-process Python plugins, NOT stdio shell hooks.
 * To bridge that, we ship a Python plugin shim (`hermes_rafter_plugin.py`)
 * that registers a `pre_gateway_dispatch` callback and shells out to this
 * command. This file owns the security logic; the shim owns the Hermes API
 * adaptation.
 *
 * Verified contract (NousResearch/hermes-agent gateway/run.py:3402-3441):
 *   stdin: { event: { text: string, channel?: string, sender_id?: string, ... }, cwd?: string }
 *   stdout: one of:
 *     {"action": "allow"}                     — pass through
 *     {"action": "rewrite", "text": "..."}    — replace event.text
 *     {"action": "skip", "reason": "..."}     — drop the message
 *
 * Default behavior: warn-via-rewrite (substitute $VAR refs for any detected
 * secrets so the message reaches the agent without literal credentials).
 * Fail-open as "allow" on any error to avoid breaking gateway message flow.
 */

const STDIN_TIMEOUT_MS = 5000;

interface GatewayInput {
  cwd?: string;
  event?: {
    text?: any;
    channel?: string;
    sender_id?: string;
    [k: string]: any;
  };
}

export function createHookGatewayDispatchCommand(): Command {
  return new Command("gateway-dispatch")
    .description(
      "Hermes pre_gateway_dispatch handler — scans inbound chat-platform messages " +
      "for secrets, rewrites with $VAR refs, persists to .env. Stdio adapter for the " +
      "in-process Python plugin shim."
    )
    .action(async () => {
      if (process.env.RAFTER_PROMPT_SHIELD === "0") {
        emitAllow();
        return;
      }

      try {
        const raw = await readStdin();
        let payload: GatewayInput;
        try {
          payload = JSON.parse(raw);
        } catch {
          emitAllow();
          return;
        }

        const text = payload?.event?.text;
        if (typeof text !== "string" || !text) {
          emitAllow();
          return;
        }

        const detected = detectSecrets(text);
        if (detected.length === 0) {
          emitAllow();
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
          // .env write failed — fail closed to "skip" rather than leak text downstream.
          emitSkip("Rafter detected a secret but could not write .env; dropping message rather than leaking.");
          return;
        }

        const valueToName = new Map<string, string>();
        for (const w of result.written) valueToName.set(w.value, w.name);
        const rewritten = replaceSecretsWithRefs(text, detected, valueToName);

        try {
          const audit = new AuditLogger();
          audit.logContentSanitized(`Hermes gateway message (${payload.event?.channel || "unknown"})`, detected.length);
        } catch { /* never break hook */ }

        emitRewrite(rewritten);
      } catch {
        emitAllow();
      }
    });
}

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

function emitAllow(): void {
  process.stdout.write(JSON.stringify({ action: "allow" }) + "\n");
}

function emitRewrite(text: string): void {
  process.stdout.write(JSON.stringify({ action: "rewrite", text }) + "\n");
}

function emitSkip(reason: string): void {
  process.stdout.write(JSON.stringify({ action: "skip", reason }) + "\n");
}
