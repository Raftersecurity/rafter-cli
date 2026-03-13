import { randomBytes } from "crypto";
import dns from "dns/promises";
import fs from "fs";
import net from "net";
import path from "path";
import { getAuditLogPath } from "./config-defaults.js";
import { ConfigManager } from "./config-manager.js";
import { assessCommandRisk } from "./risk-rules.js";

/**
 * Validate a webhook URL to prevent SSRF attacks.
 * Rejects non-HTTP(S) schemes and URLs that resolve to private/internal IPs.
 */
export async function validateWebhookUrl(rawUrl: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid webhook URL: ${rawUrl}`);
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(`Webhook URL must use http or https, got ${parsed.protocol}`);
  }

  // URL.hostname keeps brackets for IPv6 (e.g. "[::1]") — strip them
  let hostname = parsed.hostname;
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    hostname = hostname.slice(1, -1);
  }

  // If the hostname is already an IP, check it directly
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new Error(`Webhook URL must not point to a private/internal address: ${hostname}`);
    }
    return;
  }

  // Resolve hostname and check all resulting IPs
  let addresses: string[];
  try {
    const results = await dns.resolve(hostname);
    addresses = results;
  } catch {
    throw new Error(`Could not resolve webhook hostname: ${hostname}`);
  }

  for (const addr of addresses) {
    if (isPrivateIp(addr)) {
      throw new Error(`Webhook URL must not point to a private/internal address: ${hostname} resolved to ${addr}`);
    }
  }
}

/**
 * Check if an IP address belongs to a private, loopback, link-local, or
 * cloud-metadata range.
 */
function isPrivateIp(ip: string): boolean {
  // IPv4 checks
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    const [a, b] = parts;

    // 127.0.0.0/8 — loopback
    if (a === 127) return true;
    // 10.0.0.0/8 — private
    if (a === 10) return true;
    // 172.16.0.0/12 — private
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16 — private
    if (a === 192 && b === 168) return true;
    // 169.254.0.0/16 — link-local / cloud metadata
    if (a === 169 && b === 254) return true;
    // 0.0.0.0
    if (a === 0) return true;

    return false;
  }

  // IPv6 checks
  const lower = ip.toLowerCase();
  // ::1 — loopback
  if (lower === "::1") return true;
  // :: — unspecified
  if (lower === "::") return true;
  // fe80::/10 — link-local
  if (lower.startsWith("fe80:")) return true;
  // fc00::/7 — unique local (ULA)
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
  // ::ffff:127.0.0.1 etc — IPv4-mapped IPv6
  if (lower.startsWith("::ffff:")) {
    const mapped = lower.slice(7);
    if (net.isIPv4(mapped)) return isPrivateIp(mapped);
  }

  return false;
}

export type EventType =
  | "command_intercepted"
  | "secret_detected"
  | "content_sanitized"
  | "policy_override"
  | "scan_executed"
  | "config_changed";

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type ActionTaken = "blocked" | "allowed" | "overridden" | "redacted";
export type AgentType = "openclaw" | "claude-code";

export interface AuditLogEntry {
  timestamp: string;
  sessionId: string;
  eventType: EventType;
  agentType?: AgentType;
  action?: {
    command?: string;
    tool?: string;
    riskLevel?: RiskLevel;
  };
  securityCheck?: {
    passed: boolean;
    reason?: string;
    details?: any;
  };
  resolution?: {
    actionTaken: ActionTaken;
    overrideReason?: string;
  };
}

export const RISK_SEVERITY: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

export class AuditLogger {
  private logPath: string;
  private sessionId: string;
  private configManager: ConfigManager;

  constructor(logPath?: string) {
    this.logPath = logPath || getAuditLogPath();
    this.sessionId = this.generateSessionId();
    this.configManager = new ConfigManager();

    // Ensure log directory exists
    const dir = path.dirname(this.logPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Log an audit event
   */
  log(entry: Omit<AuditLogEntry, "timestamp" | "sessionId">): void {
    const config = this.configManager.load();

    // Check if logging is enabled
    if (!config.agent?.audit.logAllActions) {
      return;
    }

    const fullEntry: AuditLogEntry = {
      ...entry,
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId
    };

    // Append to log file
    const line = JSON.stringify(fullEntry) + "\n";
    fs.appendFileSync(this.logPath, line, { encoding: "utf-8", mode: 0o600 });

    // Send webhook notification if configured and risk meets threshold
    this.sendNotification(fullEntry, config);
  }

  /**
   * Send webhook notification for high-risk events
   */
  private sendNotification(entry: AuditLogEntry, config: any): void {
    const webhookUrl = config.agent?.notifications?.webhook;
    if (!webhookUrl) return;

    const eventRisk = entry.action?.riskLevel || "low";
    const minRisk = config.agent?.notifications?.minRiskLevel || "high";

    if ((RISK_SEVERITY[eventRisk] ?? 0) < (RISK_SEVERITY[minRisk] ?? 2)) {
      return;
    }

    const payload = {
      event: entry.eventType,
      risk: eventRisk,
      command: entry.action?.command || null,
      timestamp: entry.timestamp,
      agent: entry.agentType || null,
      // Slack-compatible text field
      text: `[rafter] ${eventRisk}-risk event: ${entry.eventType}${entry.action?.command ? ` — ${entry.action.command}` : ""}`,
      // Discord-compatible content field
      content: `[rafter] ${eventRisk}-risk event: ${entry.eventType}${entry.action?.command ? ` — ${entry.action.command}` : ""}`,
    };

    // Fire-and-forget POST — never block audit logging
    // Validate URL to prevent SSRF before making the request
    validateWebhookUrl(webhookUrl)
      .then(() =>
        fetch(webhookUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(5000),
        })
      )
      .catch(() => {
        // Silently ignore webhook failures (including validation rejections)
      });
  }

  /**
   * Log a command interception
   */
  logCommandIntercepted(
    command: string,
    passed: boolean,
    actionTaken: ActionTaken,
    reason?: string,
    agentType?: AgentType
  ): void {
    this.log({
      eventType: "command_intercepted",
      agentType,
      action: {
        command,
        riskLevel: this.assessCommandRisk(command)
      },
      securityCheck: {
        passed,
        reason
      },
      resolution: {
        actionTaken
      }
    });
  }

  /**
   * Log a secret detection
   */
  logSecretDetected(
    location: string,
    secretType: string,
    actionTaken: ActionTaken,
    agentType?: AgentType
  ): void {
    this.log({
      eventType: "secret_detected",
      agentType,
      action: {
        riskLevel: "critical"
      },
      securityCheck: {
        passed: false,
        reason: `${secretType} detected in ${location}`
      },
      resolution: {
        actionTaken
      }
    });
  }

  /**
   * Log content sanitization
   */
  logContentSanitized(
    contentType: string,
    patternsMatched: number,
    agentType?: AgentType
  ): void {
    this.log({
      eventType: "content_sanitized",
      agentType,
      securityCheck: {
        passed: false,
        reason: `${patternsMatched} sensitive patterns detected`,
        details: { contentType, patternsMatched }
      },
      resolution: {
        actionTaken: "redacted"
      }
    });
  }

  /**
   * Log a policy override
   */
  logPolicyOverride(
    reason: string,
    command?: string,
    agentType?: AgentType
  ): void {
    this.log({
      eventType: "policy_override",
      agentType,
      action: {
        command,
        riskLevel: "high"
      },
      securityCheck: {
        passed: false,
        reason: "Security policy overridden by user"
      },
      resolution: {
        actionTaken: "overridden",
        overrideReason: reason
      }
    });
  }

  /**
   * Read audit log entries
   */
  read(filter?: {
    eventType?: EventType;
    agentType?: AgentType;
    since?: Date;
    limit?: number;
  }): AuditLogEntry[] {
    if (!fs.existsSync(this.logPath)) {
      return [];
    }

    const content = fs.readFileSync(this.logPath, "utf-8");
    const lines = content.split("\n").filter(line => line.trim());

    let entries = lines.map(line => {
      try {
        const parsed = JSON.parse(line);
        // Skip malformed entries missing required fields
        if (!parsed || typeof parsed !== "object" || !parsed.timestamp) return null;
        return parsed as AuditLogEntry;
      } catch {
        return null;
      }
    }).filter(entry => entry !== null) as AuditLogEntry[];

    // Apply filters
    if (filter) {
      if (filter.eventType) {
        entries = entries.filter(e => e.eventType === filter.eventType);
      }
      if (filter.agentType) {
        entries = entries.filter(e => e.agentType === filter.agentType);
      }
      if (filter.since) {
        entries = entries.filter(e => new Date(e.timestamp) >= filter.since!);
      }
      if (filter.limit) {
        entries = entries.slice(-filter.limit);
      }
    }

    return entries;
  }

  /**
   * Clean up old log entries based on retention policy
   */
  cleanup(): void {
    const config = this.configManager.load();
    const retentionDays = config.agent?.audit.retentionDays || 30;
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    const entries = this.read();
    const filtered = entries.filter(e => new Date(e.timestamp) >= cutoffDate);

    // Rewrite log file with only retained entries
    const content = filtered.map(e => JSON.stringify(e)).join("\n") + "\n";
    fs.writeFileSync(this.logPath, content, { encoding: "utf-8", mode: 0o600 });
  }

  /**
   * Generate a unique session ID
   */
  private generateSessionId(): string {
    return `${Date.now()}-${randomBytes(8).toString("hex")}`;
  }

  /**
   * Assess risk level of a command
   */
  private assessCommandRisk(command: string): RiskLevel {
    return assessCommandRisk(command) as RiskLevel;
  }
}
