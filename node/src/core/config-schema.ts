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
