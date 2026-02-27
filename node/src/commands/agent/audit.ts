import { createHash } from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Command } from "commander";
import { AuditLogger, AuditLogEntry, EventType, AgentType } from "../../core/audit-logger.js";
import { ConfigManager } from "../../core/config-manager.js";
import { fmt } from "../../utils/formatter.js";
import { isAgentMode } from "../../utils/formatter.js";

export function createAuditCommand(): Command {
  return new Command("audit")
    .description("View audit log entries")
    .option("--last <n>", "Show last N entries", "10")
    .option("--event <type>", "Filter by event type")
    .option("--agent <type>", "Filter by agent type (openclaw, claude-code)")
    .option("--since <date>", "Show entries since date (YYYY-MM-DD)")
    .option("--share", "Generate a redacted excerpt for issue reports")
    .action((opts) => {
      if (opts.share) {
        generateShareExcerpt();
        return;
      }

      const logger = new AuditLogger();

      const filter: any = {
        limit: parseInt(opts.last, 10)
      };

      if (opts.event) {
        filter.eventType = opts.event as EventType;
      }

      if (opts.agent) {
        filter.agentType = opts.agent as AgentType;
      }

      if (opts.since) {
        filter.since = new Date(opts.since);
      }

      const entries = logger.read(filter);

      if (entries.length === 0) {
        console.log("No audit log entries found");
        return;
      }

      console.log(`\nShowing ${entries.length} audit log entries:\n`);

      for (const entry of entries) {
        const timestamp = new Date(entry.timestamp).toLocaleString();
        const indicator = getEventIndicator(entry.eventType);
        console.log(`${indicator} [${timestamp}] ${entry.eventType}`);

        if (entry.agentType) {
          console.log(`   Agent: ${entry.agentType}`);
        }

        if (entry.action?.command) {
          console.log(`   Command: ${entry.action.command}`);
        }

        if (entry.action?.riskLevel) {
          console.log(`   Risk: ${entry.action.riskLevel}`);
        }

        console.log(`   Check: ${entry.securityCheck.passed ? "PASSED" : "FAILED"}`);

        if (entry.securityCheck.reason) {
          console.log(`   Reason: ${entry.securityCheck.reason}`);
        }

        console.log(`   Action: ${entry.resolution.actionTaken}`);

        if (entry.resolution.overrideReason) {
          console.log(`   Override: ${entry.resolution.overrideReason}`);
        }

        console.log("");
      }
    });
}

export function generateShareExcerpt(): void {
  const version = getPkgVersion();
  const os = `${process.platform}/${process.arch}`;
  const timestamp = new Date().toISOString();

  const config = new ConfigManager().loadWithPolicy();
  const policyHash = computePolicyHash(config);
  const riskLevel = getRiskLevel(config);

  const logger = new AuditLogger();
  const entries = logger.read({ limit: 5 });

  const lines: string[] = [
    "Rafter Audit Excerpt",
    `Generated: ${timestamp}`,
    "",
    "Environment:",
    `  CLI:    ${version}`,
    `  OS:     ${os}`,
    `  Policy: sha256:${policyHash} (${riskLevel})`,
    "",
    "Recent events (last 5):",
  ];

  if (entries.length === 0) {
    lines.push("  (no entries)");
  } else {
    for (const entry of entries) {
      const ts = entry.timestamp.replace("T", " ").replace(/\.\d+Z$/, "Z");
      const eventPad = entry.eventType.padEnd(20);
      const riskRaw = entry.action?.riskLevel ?? "low";
      const riskPad = riskRaw.toUpperCase().padEnd(8);
      const detail = formatShareDetail(entry);
      lines.push(`  ${ts}  ${eventPad}  ${riskPad} ${detail}`);
    }
  }

  lines.push("");
  lines.push("Share this excerpt when reporting issues at https://github.com/Raftersecurity/rafter-cli/issues");

  console.log(lines.join("\n"));
}

export function getPkgVersion(): string {
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    // Walk up from dist/commands/agent/ to find package.json
    let dir = __dirname;
    for (let i = 0; i < 6; i++) {
      const candidate = path.join(dir, "package.json");
      if (fs.existsSync(candidate)) {
        const pkg = JSON.parse(fs.readFileSync(candidate, "utf-8"));
        if (pkg.version) return pkg.version;
      }
      dir = path.dirname(dir);
    }
  } catch {
    // fall through
  }
  return "unknown";
}

export function computePolicyHash(config: any): string {
  const patterns: string[] = config?.agent?.commandPolicy?.requireApproval ?? [];
  const payload = JSON.stringify(patterns.slice().sort());
  return createHash("sha256").update(payload).digest("hex").slice(0, 16);
}

export function getRiskLevel(config: any): string {
  return config?.agent?.riskLevel ?? "moderate";
}

export function formatShareDetail(entry: AuditLogEntry): string {
  const action = entry.resolution.actionTaken;
  const suffix = `[${action}]`;

  if (entry.eventType === "secret_detected") {
    const reason = entry.securityCheck.reason ?? "";
    return `${reason} ${suffix}`;
  }

  if (entry.action?.command) {
    return `${truncateCommand(entry.action.command, 60)} ${suffix}`;
  }

  if (entry.securityCheck.reason) {
    return `${entry.securityCheck.reason} ${suffix}`;
  }

  return suffix;
}

export function truncateCommand(cmd: string, maxLen: number = 60): string {
  if (cmd.length <= maxLen) return cmd;
  return cmd.slice(0, maxLen) + "...";
}

function getEventIndicator(eventType: EventType): string {
  if (isAgentMode()) {
    const tagMap: Record<EventType, string> = {
      command_intercepted: "[INTERCEPT]",
      secret_detected: "[SECRET]",
      content_sanitized: "[SANITIZE]",
      policy_override: "[OVERRIDE]",
      scan_executed: "[SCAN]",
      config_changed: "[CONFIG]",
    };
    return tagMap[eventType] || "[EVENT]";
  }

  const emojiMap: Record<EventType, string> = {
    command_intercepted: "🛡️",
    secret_detected: "🔑",
    content_sanitized: "🧹",
    policy_override: "⚠️",
    scan_executed: "🔍",
    config_changed: "⚙️"
  };
  return emojiMap[eventType] || "📝";
}
