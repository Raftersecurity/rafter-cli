import { ConfigManager } from "./config-manager.js";
import { AuditLogger } from "./audit-logger.js";
import {
  assessCommandRisk,
  matchedCriticalPattern,
  sanitizeCommandForMatching,
  CommandRiskLevel,
} from "./risk-rules.js";

export type { CommandRiskLevel } from "./risk-rules.js";

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
    const riskLevel = this.assessRisk(command);

    // Unconditional hard-block: catastrophic destructive commands (rm -rf /,
    // fork bombs, disk wipes, mkfs, …) are NEVER allowed, regardless of the
    // configured policy — or its absence. Security must not depend on a policy
    // being present (the default config may be missing one) or on the chosen
    // mode (even allow-all / a custom deny-list cannot opt out of these).
    if (riskLevel === "critical") {
      return {
        command,
        riskLevel,
        allowed: false,
        requiresApproval: false,
        reason: "Matches built-in blocked pattern (critical destructive command)",
        matchedPattern: matchedCriticalPattern(command) ?? "builtin:critical-destructive"
      };
    }

    const cfg = this.config.loadWithPolicy();
    const policy = cfg.agent?.commandPolicy;

    if (!policy) {
      // No policy configured — fall back to safe built-in defaults rather than
      // allow-all: high-risk commands still require approval.
      if (riskLevel === "high") {
        return {
          command,
          riskLevel,
          allowed: false,
          requiresApproval: true,
          reason: "High risk command requires approval"
        };
      }
      return {
        command,
        riskLevel,
        allowed: true,
        requiresApproval: false
      };
    }

    // Check blocked patterns (always block).
    //
    // A deny-list match denies — that is what a deny-list is for — but it must
    // NOT rewrite the command's risk. Reporting every deny-list hit as
    // "critical" made the hook tell users a `gh pr create` was an irreversible
    // system-damage command. The assessed risk is reported as assessed; the
    // genuinely unconditional hard-blocks are the CRITICAL_PATTERNS handled
    // above, and the default deny-list is exactly that set.
    for (const pattern of policy.blockedPatterns) {
      if (this.matchesPattern(command, pattern)) {
        return {
          command,
          riskLevel,
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

    // Check policy mode. `riskLevel` is the assessment made at the top of
    // evaluate() — critical already returned, so it is high/medium/low here.
    if (policy.mode === "approve-dangerous" && riskLevel === "high") {
      return {
        command,
        riskLevel,
        allowed: false,
        requiresApproval: true,
        reason: `High risk command requires approval`
      };
    }

    // deny-list / allow-all / unknown mode: not blocked, not approval-gated.
    return {
      command,
      riskLevel,
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
   * Match a command against a policy pattern.
   *
   * Matching runs against the SANITIZED command line, not the raw string: the
   * policy patterns describe commands, so quoted text a command merely consumes
   * as data (a commit message, a PR body) must not match them, while text a
   * shell or eval wrapper executes (`bash -c "…"`) must. See
   * `sanitizeCommandForMatching`.
   */
  private matchesPattern(command: string, pattern: string): boolean {
    const target = sanitizeCommandForMatching(command);
    try {
      const regex = new RegExp(pattern, "i");
      return regex.test(target);
    } catch {
      // If pattern is not valid regex, try case-insensitive substring match
      return target.toLowerCase().includes(pattern.toLowerCase());
    }
  }

  /**
   * Assess risk level of command
   */
  private assessRisk(command: string): CommandRiskLevel {
    return assessCommandRisk(command);
  }
}
