export type RiskLevel = 'minimal' | 'moderate' | 'aggressive';
export type CommandPolicyMode = 'allow-all' | 'approve-dangerous' | 'deny-list';
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface ScanCustomPattern {
  name: string;
  regex: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface ScanIgnoreRule {
  paths: string[];
  rules?: string[];
  reason?: string;
}

export interface RafterConfig {
  version: string;
  initialized: string;

  // Backend config (existing)
  backend?: {
    apiKey?: string;
    endpoint?: string;
  };

  // Agent config (new)
  agent?: {
    riskLevel: RiskLevel;
    environments: {
      openclaw?: {
        enabled: boolean;
        skillPath: string;
      };
      claudeCode?: {
        enabled: boolean;
        mcpPath: string;
      };
      codex?: {
        enabled: boolean;
        skillsDir: string;
      };
      gemini?: {
        enabled: boolean;
        configPath: string;
      };
      aider?: {
        enabled: boolean;
        configPath: string;
      };
      cursor?: {
        enabled: boolean;
        mcpPath: string;
      };
      windsurf?: {
        enabled: boolean;
        mcpPath: string;
      };
      continueDev?: {
        enabled: boolean;
        configPath: string;
      };
    };
    skills: {
      autoUpdate: boolean;
      installOnInit: boolean;
      backupBeforeUpdate: boolean;
      installedVersion?: string;
      lastChecked?: string;
    };
    commandPolicy: {
      mode: CommandPolicyMode;
      blockedPatterns: string[];
      requireApproval: string[];
      /**
       * Opt out of the project-policy floor (sable-nz4y).
       *
       * Read ONLY from the machine owner's global config — never from a
       * project `.rafter.yml`, or a repo could grant itself the permission and
       * the floor would be no floor at all. Default (absent/false) keeps the
       * floor: a project policy may tighten command policy, never loosen it.
       */
      allowProjectOverride?: boolean;

      /**
       * Positive allowlist: unanchored regexes that force a command to `low`
       * and skip the approval prompt. For the known-safe command that would
       * otherwise trip a broad risk tier -- the motivating case being
       * `git push --force-with-lease` to a feature branch on a repo whose
       * main is protected server-side.
       *
       * Three properties make this safe to put on a guard rail, and all three
       * are enforced in CommandInterceptor, not here:
       *   1. blockedPatterns always wins. An allowlist never re-opens what a
       *      deny rule closed.
       *   2. A `critical` command is never allowlistable.
       *   3. A match does not apply when the command contains a chain
       *      operator, so "^git push" cannot wave through
       *      `rm -rf / && git push`.
       */
      allowedPatterns?: string[];
    };
    outputFiltering: {
      redactSecrets: boolean;
      blockPatterns: boolean;
    };
    audit: {
      logAllActions: boolean;
      retentionDays: number;
      logLevel: LogLevel;
      logPath?: string;
    };
    notifications?: {
      webhook?: string;
      minRiskLevel?: 'high' | 'critical';
    };
    /**
     * Runtime enable/disable for the PreToolUse / pre-commit hook. Distinct from
     * `components["<platform>.hooks"]` (which tracks whether a hook is *installed*
     * in a platform's settings) — this gates whether an installed hook actually
     * acts. Default (undefined) = enabled.
     *
     * SECURITY: by design this is honored ONLY from the global
     * `~/.rafter/config.json` (machine-owner-owned) and the `RAFTER_DISABLE_*`
     * env vars — NEVER from project-local `.rafter.yml`, so a hostile repo can't
     * ship a config that silently disables a victim's hook (see hook-control.ts).
     * That is why this field lives on RafterConfig but NOT on PolicyFile.
     */
    hooks?: {
      /** Master switch. false = the hook allows everything (no scan, no command policy). */
      enabled?: boolean;
      /** Disable only the secret scan on Write/Edit/staged content; keep command policy. */
      secretScan?: boolean;
      /** Disable only command-risk interception on Bash; keep secret scanning. */
      commandPolicy?: boolean;
    };
    scan?: {
      excludePaths?: string[];
      customPatterns?: ScanCustomPattern[];
      ignore?: ScanIgnoreRule[];
      /**
       * sable-o4k — auto-update a stale rafter-managed betterleaks binary at
       * scan time. Default true. Set false (YAML: `scan.auto_update_betterleaks`)
       * to opt out, e.g. in CI that provisions its own binary.
       */
      autoUpdateBetterleaks?: boolean;
      /**
       * sable-9ddf — require explicit confirmation before a paid Plus scan
       * (`rafter run --mode plus`). Default false (undefined) — existing
       * behavior is unchanged unless opted in. When true, a Plus scan refuses
       * in a non-interactive/agent context unless `--yes` or `RAFTER_CONFIRM=1`
       * is present, and prompts when a TTY is attached.
       *
       * SECURITY: honored additively (OR) across global config and project
       * `.rafter.yml` — a project policy can turn this ON but can NEVER turn OFF
       * a gate the machine owner enabled globally. See runRemoteScan.
       * YAML key: `scan.plus_requires_approval`.
       */
      plusRequiresApproval?: boolean;
    };
    /**
     * Fine-grained per-component install state. Keys are component IDs like
     * "claude-code.hooks" or "cursor.mcp". Set by `rafter agent enable/disable`
     * and used by `rafter agent list` to distinguish explicitly-disabled
     * components from ones that were never installed.
     */
    components?: Record<string, {
      enabled: boolean;
      updatedAt?: string;
    }>;
  };
}
