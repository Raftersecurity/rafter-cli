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
       * When 'approve-dangerous' mode is active, also gate on the built-in
       * HIGH_PATTERNS regex catalog (rm -rf <anything>, sudo rm, curl|sh,
       * git push --force, etc.) in addition to the user's requireApproval.
       *
       * Default true preserves the historically-safer behavior. Set to false
       * when your blockedPatterns already covers the catastrophic cases
       * precisely and you don't want routine `rm -rf node_modules` to gate.
       *
       * The CRITICAL_PATTERNS catalog (fork bomb, mkfs, dd of=/dev/sd, etc.)
       * still always gates — this opt-out does NOT disable the catastrophic
       * tier.
       */
      useBuiltinRiskPatterns?: boolean;
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
    scan?: {
      excludePaths?: string[];
      customPatterns?: ScanCustomPattern[];
      ignore?: ScanIgnoreRule[];
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
