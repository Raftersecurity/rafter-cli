/**
 * Audit log panel — TreeView provider that reads rafter audit log entries.
 */
import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export type EventType =
  | "command_intercepted"
  | "secret_detected"
  | "content_sanitized"
  | "policy_override"
  | "scan_executed"
  | "config_changed";

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type ActionTaken = "blocked" | "allowed" | "overridden" | "redacted";

export interface AuditLogEntry {
  timestamp: string;
  sessionId: string;
  eventType: EventType;
  agentType?: string;
  action?: {
    command?: string;
    tool?: string;
    riskLevel?: RiskLevel;
  };
  securityCheck?: {
    passed: boolean;
    reason?: string;
  };
  resolution?: {
    actionTaken: ActionTaken;
    overrideReason?: string;
  };
}

function getAuditLogPath(): string {
  const config = vscode.workspace.getConfiguration("rafter");
  const custom = config.get<string>("auditLogPath");
  if (custom) return custom;
  return path.join(os.homedir(), ".rafter", "audit.jsonl");
}

function readAuditLog(limit: number = 100): AuditLogEntry[] {
  const logPath = getAuditLogPath();
  if (!fs.existsSync(logPath)) return [];

  try {
    const content = fs.readFileSync(logPath, "utf-8");
    const lines = content.split("\n").filter((l) => l.trim());
    const entries: AuditLogEntry[] = [];

    for (const line of lines) {
      try {
        const parsed = JSON.parse(line);
        if (parsed && typeof parsed === "object" && parsed.timestamp) {
          entries.push(parsed);
        }
      } catch {
        // Skip malformed lines
      }
    }

    // Return most recent entries first
    return entries.reverse().slice(0, limit);
  } catch {
    return [];
  }
}

const EVENT_ICONS: Record<string, string> = {
  command_intercepted: "$(terminal)",
  secret_detected: "$(key)",
  content_sanitized: "$(eye-closed)",
  policy_override: "$(warning)",
  scan_executed: "$(search)",
  config_changed: "$(gear)",
};

const RISK_ICONS: Record<string, string> = {
  critical: "$(error)",
  high: "$(warning)",
  medium: "$(info)",
  low: "$(pass)",
};

class AuditLogItem extends vscode.TreeItem {
  constructor(
    public readonly entry: AuditLogEntry,
  ) {
    const icon = EVENT_ICONS[entry.eventType] || "$(circle)";
    const time = new Date(entry.timestamp).toLocaleTimeString();
    const label = `${icon} ${entry.eventType.replace(/_/g, " ")}`;

    super(label, vscode.TreeItemCollapsibleState.None);

    this.description = `${time}`;

    const riskLevel = entry.action?.riskLevel;
    const command = entry.action?.command;
    const actionTaken = entry.resolution?.actionTaken;
    const reason = entry.securityCheck?.reason;

    const details: string[] = [];
    if (riskLevel) details.push(`Risk: **${riskLevel.toUpperCase()}**`);
    if (command) details.push(`Command: \`${command}\``);
    if (actionTaken) details.push(`Action: ${actionTaken}`);
    if (reason) details.push(`Reason: ${reason}`);
    if (entry.agentType) details.push(`Agent: ${entry.agentType}`);

    this.tooltip = new vscode.MarkdownString(
      `**${entry.eventType.replace(/_/g, " ")}**\n\n` +
      `Time: ${entry.timestamp}\n\n` +
      details.join("\n\n")
    );

    if (riskLevel === "critical" || riskLevel === "high") {
      this.iconPath = new vscode.ThemeIcon("warning", new vscode.ThemeColor("errorForeground"));
    } else if (riskLevel === "medium") {
      this.iconPath = new vscode.ThemeIcon("info", new vscode.ThemeColor("editorWarning.foreground"));
    } else {
      this.iconPath = new vscode.ThemeIcon("circle-outline");
    }
  }
}

export class AuditLogProvider implements vscode.TreeDataProvider<AuditLogItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<AuditLogItem | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private watcher: fs.FSWatcher | undefined;

  constructor() {
    this.watchLogFile();
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: AuditLogItem): vscode.TreeItem {
    return element;
  }

  getChildren(): AuditLogItem[] {
    const entries = readAuditLog(200);
    if (entries.length === 0) {
      return [];
    }
    return entries.map((entry) => new AuditLogItem(entry));
  }

  private watchLogFile(): void {
    const logPath = getAuditLogPath();
    const dir = path.dirname(logPath);

    if (!fs.existsSync(dir)) return;

    try {
      this.watcher = fs.watch(dir, (eventType, filename) => {
        if (filename === path.basename(logPath)) {
          this.refresh();
        }
      });
    } catch {
      // Watching may fail on some platforms — that's fine, user can refresh manually
    }
  }

  dispose(): void {
    this.watcher?.close();
    this._onDidChangeTreeData.dispose();
  }
}

/**
 * Risk overview — summarizes current risk posture
 */
class RiskOverviewItem extends vscode.TreeItem {
  constructor(label: string, description: string, icon: vscode.ThemeIcon) {
    super(label, vscode.TreeItemCollapsibleState.None);
    this.description = description;
    this.iconPath = icon;
  }
}

export class RiskOverviewProvider implements vscode.TreeDataProvider<RiskOverviewItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<RiskOverviewItem | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: RiskOverviewItem): vscode.TreeItem {
    return element;
  }

  getChildren(): RiskOverviewItem[] {
    const entries = readAuditLog(1000);
    const items: RiskOverviewItem[] = [];

    // Count by event type
    const eventCounts: Record<string, number> = {};
    const riskCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };

    for (const entry of entries) {
      eventCounts[entry.eventType] = (eventCounts[entry.eventType] || 0) + 1;
      const risk = entry.action?.riskLevel;
      if (risk && risk in riskCounts) {
        riskCounts[risk]++;
      }
    }

    items.push(new RiskOverviewItem(
      "Total Events",
      `${entries.length}`,
      new vscode.ThemeIcon("pulse"),
    ));

    if (riskCounts.critical > 0) {
      items.push(new RiskOverviewItem(
        "Critical",
        `${riskCounts.critical}`,
        new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground")),
      ));
    }
    if (riskCounts.high > 0) {
      items.push(new RiskOverviewItem(
        "High",
        `${riskCounts.high}`,
        new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground")),
      ));
    }
    if (riskCounts.medium > 0) {
      items.push(new RiskOverviewItem(
        "Medium",
        `${riskCounts.medium}`,
        new vscode.ThemeIcon("info"),
      ));
    }

    // Event type breakdown
    for (const [eventType, count] of Object.entries(eventCounts)) {
      const icon = eventType === "secret_detected"
        ? new vscode.ThemeIcon("key")
        : eventType === "command_intercepted"
        ? new vscode.ThemeIcon("terminal")
        : new vscode.ThemeIcon("circle-outline");

      items.push(new RiskOverviewItem(
        eventType.replace(/_/g, " "),
        `${count}`,
        icon,
      ));
    }

    if (items.length === 1 && entries.length === 0) {
      return [new RiskOverviewItem(
        "No audit events",
        "Run rafter to generate audit data",
        new vscode.ThemeIcon("info"),
      )];
    }

    return items;
  }

  dispose(): void {
    this._onDidChangeTreeData.dispose();
  }
}
