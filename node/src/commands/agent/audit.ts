import { Command } from "commander";
import { AuditLogger, EventType, AgentType } from "../../core/audit-logger.js";

export function createAuditCommand(): Command {
  return new Command("audit")
    .description("View audit log entries")
    .option("--last <n>", "Show last N entries", "10")
    .option("--event <type>", "Filter by event type")
    .option("--agent <type>", "Filter by agent type (openclaw, claude-code)")
    .option("--since <date>", "Show entries since date (YYYY-MM-DD)")
    .action((opts) => {
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
        const emoji = getEventEmoji(entry.eventType);
        console.log(`${emoji} [${timestamp}] ${entry.eventType}`);

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

function getEventEmoji(eventType: EventType): string {
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
