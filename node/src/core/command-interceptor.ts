import { ConfigManager } from "./config-manager.js";
import { AuditLogger } from "./audit-logger.js";
import {
  assessCommandRisk,
  matchedCriticalPattern,
  sanitizeCommandForMatching,
  CommandRiskLevel,
  CHAIN_OPERATORS,
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

    // Check the positive allowlist. Deliberately AFTER blockedPatterns and
    // BEFORE requireApproval: a deny rule always wins, and an allow rule's
    // whole job is to suppress the approval prompt for a known-safe command.
    //
    // Two guards keep an allowlist from becoming a hole in the guard rail:
    //
    //   - A `critical` command is never allowlistable. `rm -rf /`, a DB drop
    //     and wiping .git stay blocked whatever the config says.
    //   - A match does not apply when the command contains a chain operator.
    //     Patterns are unanchored by request, so without this "^git push"
    //     would wave through `rm -rf / && git push`. This mirrors the same
    //     disqualification SAFE_PREFIX already carries in risk-rules.ts.
    for (const pattern of policy.allowedPatterns ?? []) {
      if (!this.matchesPattern(command, pattern)) continue;

      if (CHAIN_OPERATORS.test(command)) {
        // Fall through to normal classification rather than allowing.
        break;
      }
      if (this.assessRisk(command) === "critical") {
        break;
      }
      return {
        command,
        riskLevel: "low",
        allowed: true,
        requiresApproval: false,
        reason: `Matches allowed pattern: ${pattern}`,
        matchedPattern: pattern
      };
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
