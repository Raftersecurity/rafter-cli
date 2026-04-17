import { createHash, randomBytes } from "crypto";
import dns from "dns/promises";
import fs from "fs";
import net from "net";
import path from "path";
import { getAuditLogPath } from "./config-defaults.js";
import { ConfigManager } from "./config-manager.js";
import { assessCommandRisk } from "./risk-rules.js";
import { RegexScanner } from "../scanners/regex-scanner.js";

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
  cwd?: string;
  gitRepo?: string;
  /** sha256 of the previous raw line (including trailing newline). null for the first entry. */
  prevHash?: string | null;
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

/**
 * Return sha256 hex of the last non-empty line of the file (including its
 * trailing newline), or null if the file is empty / does not exist.
 * Reads only the tail of the file so this is cheap even for large logs.
 */
export function readLastLineHash(filePath: string): string | null {
  if (!fs.existsSync(filePath)) return null;
  const stat = fs.statSync(filePath);
  if (stat.size === 0) return null;
  // Read the last 64KB — an audit line tops out well under this.
  const readBytes = Math.min(stat.size, 65536);
  const fd = fs.openSync(filePath, "r");
  try {
    const buf = Buffer.alloc(readBytes);
    fs.readSync(fd, buf, 0, readBytes, stat.size - readBytes);
    const text = buf.toString("utf-8");
    // Find last non-empty line
    const lines = text.split("\n");
    for (let i = lines.length - 1; i >= 0; i--) {
      if (lines[i].trim()) {
        return createHash("sha256").update(lines[i] + "\n").digest("hex");
      }
    }
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Best-effort exclusive file lock via O_EXCL sibling lock file. Retries briefly
 * then gives up (better to log without chain integrity than to drop the event).
 */
export function acquireLock(targetPath: string, maxAttempts: number = 20, delayMs: number = 25): () => void {
  const lockPath = targetPath + ".lock";
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const fd = fs.openSync(lockPath, "wx", 0o600);
      fs.writeSync(fd, String(process.pid));
      fs.closeSync(fd);
      return () => {
        try { fs.unlinkSync(lockPath); } catch { /* already gone */ }
      };
    } catch (e: any) {
      if (e.code !== "EEXIST") throw e;
      // Stale lock detection: if older than 5s, steal it
      try {
        const st = fs.statSync(lockPath);
        if (Date.now() - st.mtimeMs > 5000) {
          fs.unlinkSync(lockPath);
          continue;
        }
      } catch { /* race with another releaser — retry */ }
      const until = Date.now() + delayMs;
      while (Date.now() < until) { /* busy wait */ }
    }
  }
  // Degrade gracefully: caller proceeds without the lock.
  return () => {};
}

/**
 * Walk up from startDir looking for a .git directory. Returns the repo root
 * (the directory containing .git), or undefined if none found within maxDepth.
 * Single-filesystem-hop lookup — no subprocess, no git binary required.
 */
export function findGitRepoRoot(startDir: string, maxDepth: number = 20): string | undefined {
  let dir = startDir;
  for (let i = 0; i < maxDepth; i++) {
    try {
      if (fs.existsSync(path.join(dir, ".git"))) {
        return dir;
      }
    } catch {
      return undefined;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
  return undefined;
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
  private scanner: RegexScanner;

  constructor(logPath?: string) {
    this.configManager = new ConfigManager();
    this.scanner = new RegexScanner();
    this.sessionId = this.generateSessionId();

    if (logPath) {
      this.logPath = logPath;
    } else {
      // Project-local override from .rafter.yml (via loadWithPolicy) beats global
      let policyPath: string | undefined;
      try {
        policyPath = this.configManager.loadWithPolicy()?.agent?.audit?.logPath;
      } catch {
        // fall through to global
      }
      this.logPath = policyPath
        ? path.resolve(policyPath)
        : getAuditLogPath();
    }

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

    const cwd = entry.cwd ?? process.cwd();
    const gitRepo = entry.gitRepo ?? findGitRepoRoot(cwd);

    // Atomic read-last-line + append under a file lock so concurrent writers
    // don't race and produce entries with duplicate prevHash values.
    const release = acquireLock(this.logPath);
    try {
      const prevHash = readLastLineHash(this.logPath);
      const fullEntry: AuditLogEntry = {
        ...entry,
        cwd,
        gitRepo,
        prevHash,
        timestamp: new Date().toISOString(),
        sessionId: this.sessionId
      };

      const line = JSON.stringify(fullEntry) + "\n";
      fs.appendFileSync(this.logPath, line, { encoding: "utf-8", mode: 0o600 });

      // Send webhook notification if configured and risk meets threshold
      this.sendNotification(fullEntry, config);
    } finally {
      release();
    }
  }

  /**
   * Verify the hash chain integrity of the audit log.
   * Returns break locations (1-indexed line numbers where prevHash didn't
   * match the sha256 of the actual prior line). Empty array means the chain
   * is intact. A non-empty result means the log has been tampered with,
   * truncated, or rewritten (including by the legacy cleanup() path).
   */
  verify(): Array<{ line: number; reason: string }> {
    if (!fs.existsSync(this.logPath)) {
      return [];
    }
    const content = fs.readFileSync(this.logPath, "utf-8");
    const rawLines = content.split("\n");
    const breaks: Array<{ line: number; reason: string }> = [];
    let lastRawLine: string | null = null;

    for (let i = 0; i < rawLines.length; i++) {
      const raw = rawLines[i];
      if (!raw.trim()) continue;
      let entry: AuditLogEntry;
      try {
        entry = JSON.parse(raw);
      } catch {
        breaks.push({ line: i + 1, reason: "malformed JSON" });
        lastRawLine = raw;
        continue;
      }
      const expected = lastRawLine === null
        ? null
        : createHash("sha256").update(lastRawLine + "\n").digest("hex");
      const actual = entry.prevHash ?? null;
      if (actual !== expected) {
        breaks.push({
          line: i + 1,
          reason: expected === null
            ? `first entry has prevHash ${actual} but expected null`
            : `prevHash ${actual ?? "null"} does not match expected ${expected}`,
        });
      }
      lastRawLine = raw;
    }

    return breaks;
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
        command: this.scanner.redact(command),
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
        command: command ? this.scanner.redact(command) : command,
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
    cwd?: string;
    gitRepo?: string;
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
      if (filter.cwd) {
        const needle = filter.cwd;
        entries = entries.filter(e => (e.cwd ?? "").includes(needle));
      }
      if (filter.gitRepo) {
        const needle = filter.gitRepo;
        entries = entries.filter(e => (e.gitRepo ?? "").includes(needle));
      }
      if (filter.limit) {
        entries = entries.slice(-filter.limit);
      }
    }

    return entries;
  }

  /**
   * Clean up old log entries based on retention policy.
   *
   * Retention rewrites break the on-disk hash chain by design (some entries
   * disappear). To keep verify() meaningful post-cleanup we re-seal the
   * chain across surviving entries and record a sidecar `audit.retention.log`
   * line capturing the pre-cleanup tip hash and pruned count, so a verifier
   * can cross-check that retention — not tampering — is what broke the
   * old chain.
   */
  cleanup(): void {
    const config = this.configManager.load();
    const retentionDays = config.agent?.audit.retentionDays || 30;
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    const release = acquireLock(this.logPath);
    try {
      if (!fs.existsSync(this.logPath)) return;
      const preTipHash = readLastLineHash(this.logPath);
      const raw = fs.readFileSync(this.logPath, "utf-8");
      const rawLines = raw.split("\n").filter(l => l.trim());

      const kept: AuditLogEntry[] = [];
      let prunedCount = 0;
      for (const line of rawLines) {
        try {
          const entry = JSON.parse(line) as AuditLogEntry;
          if (!entry.timestamp) { prunedCount++; continue; }
          if (new Date(entry.timestamp) >= cutoffDate) {
            kept.push(entry);
          } else {
            prunedCount++;
          }
        } catch {
          prunedCount++;
        }
      }

      // Re-seal the chain across surviving entries.
      const output: string[] = [];
      let prevLine: string | null = null;
      for (const entry of kept) {
        const resealed: AuditLogEntry = {
          ...entry,
          prevHash: prevLine === null
            ? null
            : createHash("sha256").update(prevLine + "\n").digest("hex"),
        };
        const serialized = JSON.stringify(resealed);
        output.push(serialized);
        prevLine = serialized;
      }

      const content = output.length > 0 ? output.join("\n") + "\n" : "";
      // Atomic replace so readers never see a truncated file.
      const tmpPath = this.logPath + ".tmp-" + randomBytes(4).toString("hex");
      fs.writeFileSync(tmpPath, content, { encoding: "utf-8", mode: 0o600 });
      fs.renameSync(tmpPath, this.logPath);

      if (prunedCount > 0) {
        const sidecar = this.logPath + ".retention.log";
        const note = {
          timestamp: new Date().toISOString(),
          prunedCount,
          retainedCount: kept.length,
          retentionDays,
          preCleanupTipHash: preTipHash,
        };
        try {
          fs.appendFileSync(sidecar, JSON.stringify(note) + "\n", { encoding: "utf-8", mode: 0o600 });
        } catch {
          // sidecar is best-effort — don't fail cleanup if we can't write it
        }
      }
    } finally {
      release();
    }
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
