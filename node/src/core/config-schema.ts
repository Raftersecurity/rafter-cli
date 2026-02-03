export type RiskLevel = 'minimal' | 'moderate' | 'aggressive';
export type CommandPolicyMode = 'allow-all' | 'approve-dangerous' | 'deny-list';
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

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
    };
  };
}
