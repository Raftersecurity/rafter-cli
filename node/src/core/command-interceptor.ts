import { ConfigManager } from "./config-manager.js";
import { AuditLogger } from "./audit-logger.js";

export type CommandRiskLevel = "low" | "medium" | "high" | "critical";

export interface CommandEvaluation {
  command: string;
  riskLevel: CommandRiskLevel;
  allowed: boolean;
  requiresApproval: boolean;
  reason?: string;
  matchedPattern?: string;
}

export class CommandInterceptor {
  private config: ConfigManager;
  private audit: AuditLogger;

  constructor() {
    this.config = new ConfigManager();
    this.audit = new AuditLogger();
  }

  /**
   * Evaluate if a command should be allowed
   */
  evaluate(command: string): CommandEvaluation {
    const cfg = this.config.loadWithPolicy();
    const policy = cfg.agent?.commandPolicy;

    if (!policy) {
      // No policy configured, allow by default
      return {
        command,
        riskLevel: "low",
        allowed: true,
        requiresApproval: false
      };
    }

    // Check blocked patterns (always block)
    for (const pattern of policy.blockedPatterns) {
      if (this.matchesPattern(command, pattern)) {
        return {
          command,
          riskLevel: "critical",
          allowed: false,
          requiresApproval: false,
          reason: `Matches blocked pattern: ${pattern}`,
          matchedPattern: pattern
        };
      }
    }

    // Check approval patterns
    for (const pattern of policy.requireApproval) {
      if (this.matchesPattern(command, pattern)) {
        const riskLevel = this.assessRisk(command);
        return {
          command,
          riskLevel,
          allowed: false,
          requiresApproval: true,
          reason: `Matches approval pattern: ${pattern}`,
          matchedPattern: pattern
        };
      }
    }

    // Check policy mode
    if (policy.mode === "deny-list") {
      // If not in blocked or approval lists, allow
      return {
        command,
        riskLevel: this.assessRisk(command),
        allowed: true,
        requiresApproval: false
      };
    } else if (policy.mode === "approve-dangerous") {
      // Assess risk and require approval for high/critical
      const riskLevel = this.assessRisk(command);
      if (riskLevel === "high" || riskLevel === "critical") {
        return {
          command,
          riskLevel,
          allowed: false,
          requiresApproval: true,
          reason: `High risk command requires approval`
        };
      }
      return {
        command,
        riskLevel,
        allowed: true,
        requiresApproval: false
      };
    } else if (policy.mode === "allow-all") {
      return {
        command,
        riskLevel: this.assessRisk(command),
        allowed: true,
        requiresApproval: false
      };
    }

    // Default: allow
    return {
      command,
      riskLevel: this.assessRisk(command),
      allowed: true,
      requiresApproval: false
    };
  }

  /**
   * Log command evaluation result
   */
  logEvaluation(evaluation: CommandEvaluation, actionTaken: "blocked" | "allowed" | "overridden"): void {
    this.audit.logCommandIntercepted(
      evaluation.command,
      evaluation.allowed,
      actionTaken,
      evaluation.reason
    );
  }

  /**
   * Match command against pattern
   */
  private matchesPattern(command: string, pattern: string): boolean {
    try {
      const regex = new RegExp(pattern, "i");
      return regex.test(command);
    } catch {
      // If pattern is not valid regex, try case-insensitive substring match
      return command.toLowerCase().includes(pattern.toLowerCase());
    }
  }

  /**
   * Assess risk level of command
   */
  private assessRisk(command: string): CommandRiskLevel {
    const cmd = command.toLowerCase();

    // Critical patterns
    const critical = [
      /rm\s+-rf\s+\//,
      /:\(\)\{\s*:\|:&\s*\};:/,  // fork bomb
      /dd\s+if=.*of=\/dev\/sd/,
      />\s*\/dev\/sd/,
      /mkfs/,
      /fdisk/,
      /parted/
    ];

    // High risk patterns
    const high = [
      /rm\s+-rf/,
      /sudo\s+rm/,
      /chmod\s+777/,
      /curl.*\|.*sh/,
      /wget.*\|.*sh/,
      /git\s+push\s+--force/,
      /docker\s+system\s+prune/,
      /npm\s+publish/,
      /pypi.*upload/
    ];

    // Medium risk patterns
    const medium = [
      /sudo/,
      /chmod/,
      /chown/,
      /systemctl/,
      /service/,
      /kill\s+-9/,
      /pkill/,
      /killall/
    ];

    for (const pattern of critical) {
      if (pattern.test(cmd)) return "critical";
    }

    for (const pattern of high) {
      if (pattern.test(cmd)) return "high";
    }

    for (const pattern of medium) {
      if (pattern.test(cmd)) return "medium";
    }

    return "low";
  }
}
