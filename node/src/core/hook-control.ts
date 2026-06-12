import { ConfigManager } from "./config-manager.js";
import { RafterConfig } from "./config-schema.js";

/**
 * Where the effective hook setting came from — surfaced by `rafter agent status`
 * so "why didn't the hook fire?" is always answerable (secure-design D4).
 */
export type HookControlSource = "default" | "global-config" | "env";

export interface HookControl {
  /** Master: when false the hook allows everything (no scan, no command policy). */
  hookEnabled: boolean;
  /** Whether the Write/Edit/staged secret scan runs. */
  secretScanEnabled: boolean;
  /** Whether Bash command-risk interception runs. */
  commandPolicyEnabled: boolean;
  /** Attribution for each decision, for status/audit. */
  source: {
    hook: HookControlSource;
    secretScan: HookControlSource;
    commandPolicy: HookControlSource;
  };
}

/**
 * Parse a tri-state from an env var. Returns true (disable), false (force-enable),
 * or undefined (unset / unrecognized → defer to config). Deliberately strict:
 * only explicit, well-known tokens count, so a stray value fails safe to "defer"
 * rather than silently disabling a security control (secure-design D2).
 */
function envTriState(raw: string | undefined): boolean | undefined {
  if (raw == null) return undefined;
  const v = raw.trim().toLowerCase();
  if (v === "1" || v === "true" || v === "yes" || v === "on") return true; // disable
  if (v === "0" || v === "false" || v === "no" || v === "off") return false; // force-enable
  return undefined;
}

/**
 * Resolve whether the hook (and its sub-parts) should act.
 *
 * SECURITY (secure-design D1): the disable signal is honored ONLY from trusted,
 * machine-owner-owned sources — the global `~/.rafter/config.json` and the
 * `RAFTER_DISABLE_*` env vars. It is NEVER read from project-local `.rafter.yml`,
 * so cloning a hostile repo cannot silently disable a victim's secret scanning or
 * command interception. That is enforced structurally: this function calls
 * `ConfigManager.load()` (global config only), NOT `loadWithPolicy()` (which
 * merges `.rafter.yml`), and `hooks` is absent from the PolicyFile schema.
 *
 * Precedence (D5): env var overrides global config. Default (D2): enabled; an
 * unreadable config or unrecognized value fails safe to enabled.
 */
export function resolveHookControl(opts?: {
  config?: RafterConfig;
  env?: NodeJS.ProcessEnv;
}): HookControl {
  const env = opts?.env ?? process.env;

  let cfg: RafterConfig | undefined = opts?.config;
  if (!cfg) {
    try {
      cfg = new ConfigManager().load();
    } catch {
      // Unreadable/corrupt global config must not disable the hook — fail safe.
      cfg = undefined;
    }
  }
  const h = cfg?.agent?.hooks;

  // Resolve one axis: env wins over global; absent → default `true` (enabled).
  // `globalDisabled` is the config saying `<key>: false` (disabled) or
  // `hooks.<sub>: true` meaning "disable this sub-part".
  const resolve = (
    envVal: boolean | undefined,
    globalDisabled: boolean | undefined,
  ): { enabled: boolean; source: HookControlSource } => {
    if (envVal !== undefined) return { enabled: !envVal, source: "env" };
    if (globalDisabled === true) return { enabled: false, source: "global-config" };
    return { enabled: true, source: "default" };
  };

  // Master switch. Global form: `agent.hooks.enabled === false` disables.
  const hook = resolve(
    envTriState(env.RAFTER_DISABLE_HOOKS),
    h?.enabled === false ? true : undefined,
  );

  // Sub-parts. Global form: `agent.hooks.secretScan === false` disables that part.
  // A disabled master switch forces every sub-part off regardless of its own setting.
  const secretScan = hook.enabled
    ? resolve(envTriState(env.RAFTER_DISABLE_SECRET_SCAN), h?.secretScan === false ? true : undefined)
    : { enabled: false, source: hook.source };
  const commandPolicy = hook.enabled
    ? resolve(envTriState(env.RAFTER_DISABLE_COMMAND_POLICY), h?.commandPolicy === false ? true : undefined)
    : { enabled: false, source: hook.source };

  return {
    hookEnabled: hook.enabled,
    secretScanEnabled: secretScan.enabled,
    commandPolicyEnabled: commandPolicy.enabled,
    source: {
      hook: hook.source,
      secretScan: secretScan.source,
      commandPolicy: commandPolicy.source,
    },
  };
}
