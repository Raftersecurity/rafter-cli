import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// Mock vscode module before importing audit-panel
vi.mock("vscode", () => {
  class MockTreeItem {
    label: string;
    description?: string;
    tooltip?: unknown;
    iconPath?: unknown;
    collapsibleState: number;
    constructor(label: string, collapsibleState: number) {
      this.label = label;
      this.collapsibleState = collapsibleState;
    }
  }

  class MockEventEmitter {
    private listeners: Array<(...args: unknown[]) => void> = [];
    event = (listener: (...args: unknown[]) => void) => {
      this.listeners.push(listener);
      return { dispose: () => {} };
    };
    fire(data?: unknown) {
      for (const l of this.listeners) l(data);
    }
    dispose() {
      this.listeners = [];
    }
  }

  class MockThemeIcon {
    id: string;
    color?: unknown;
    constructor(id: string, color?: unknown) {
      this.id = id;
      this.color = color;
    }
  }

  class MockThemeColor {
    id: string;
    constructor(id: string) {
      this.id = id;
    }
  }

  class MockMarkdownString {
    value: string;
    constructor(value: string) {
      this.value = value;
    }
  }

  const configValues: Record<string, unknown> = {};

  return {
    TreeItem: MockTreeItem,
    TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
    EventEmitter: MockEventEmitter,
    ThemeIcon: MockThemeIcon,
    ThemeColor: MockThemeColor,
    MarkdownString: MockMarkdownString,
    workspace: {
      getConfiguration: (_section: string) => ({
        get: <T>(key: string, defaultValue?: T): T =>
          (configValues[key] as T) ?? (defaultValue as T),
      }),
    },
    window: {
      registerTreeDataProvider: vi.fn(),
    },
    // Expose for tests to set config values
    __configValues: configValues,
  };
});

import {
  AuditLogProvider,
  RiskOverviewProvider,
  type AuditLogEntry,
} from "../src/audit-panel";

describe("AuditLogProvider", () => {
  let tmpDir: string;
  let logPath: string;
  let vscodeModule: { __configValues: Record<string, unknown> };

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-audit-test-"));
    logPath = path.join(tmpDir, "audit.jsonl");
    vscodeModule = await import("vscode") as unknown as typeof vscodeModule;
    vscodeModule.__configValues["auditLogPath"] = logPath;
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vscodeModule.__configValues["auditLogPath"] = undefined;
  });

  function writeEntries(entries: AuditLogEntry[]): void {
    const lines = entries.map((e) => JSON.stringify(e)).join("\n");
    fs.writeFileSync(logPath, lines + "\n");
  }

  it("returns empty array when log file does not exist", () => {
    vscodeModule.__configValues["auditLogPath"] = path.join(tmpDir, "nonexistent.jsonl");
    const provider = new AuditLogProvider();
    expect(provider.getChildren()).toEqual([]);
    provider.dispose();
  });

  it("returns empty array for empty log file", () => {
    fs.writeFileSync(logPath, "");
    const provider = new AuditLogProvider();
    expect(provider.getChildren()).toEqual([]);
    provider.dispose();
  });

  it("parses valid JSONL entries", () => {
    writeEntries([
      {
        timestamp: "2026-01-15T10:00:00Z",
        sessionId: "sess-1",
        eventType: "command_intercepted",
        action: { command: "rm -rf /", riskLevel: "critical" },
        resolution: { actionTaken: "blocked" },
      },
      {
        timestamp: "2026-01-15T10:01:00Z",
        sessionId: "sess-1",
        eventType: "secret_detected",
        securityCheck: { passed: false, reason: "AWS key found" },
      },
    ]);

    const provider = new AuditLogProvider();
    const children = provider.getChildren();
    // Returns most recent first
    expect(children.length).toBe(2);
    expect(children[0].entry.eventType).toBe("secret_detected");
    expect(children[1].entry.eventType).toBe("command_intercepted");
    provider.dispose();
  });

  it("skips malformed JSON lines gracefully", () => {
    fs.writeFileSync(
      logPath,
      `{"timestamp":"2026-01-15T10:00:00Z","sessionId":"s1","eventType":"scan_executed"}\nnot valid json\n{"timestamp":"2026-01-15T10:02:00Z","sessionId":"s2","eventType":"config_changed"}\n`
    );

    const provider = new AuditLogProvider();
    const children = provider.getChildren();
    expect(children.length).toBe(2);
    provider.dispose();
  });

  it("skips JSON objects without timestamp field", () => {
    fs.writeFileSync(
      logPath,
      `{"sessionId":"s1","eventType":"scan_executed"}\n{"timestamp":"2026-01-15T10:00:00Z","sessionId":"s2","eventType":"scan_executed"}\n`
    );

    const provider = new AuditLogProvider();
    const children = provider.getChildren();
    expect(children.length).toBe(1);
    provider.dispose();
  });

  it("limits output to specified number of entries (default 200)", () => {
    const entries: AuditLogEntry[] = [];
    for (let i = 0; i < 250; i++) {
      entries.push({
        timestamp: `2026-01-15T10:${String(i).padStart(2, "0")}:00Z`,
        sessionId: `sess-${i}`,
        eventType: "scan_executed",
      });
    }
    writeEntries(entries);

    const provider = new AuditLogProvider();
    const children = provider.getChildren();
    expect(children.length).toBe(200);
    provider.dispose();
  });

  it("fires onDidChangeTreeData on refresh", () => {
    const provider = new AuditLogProvider();
    let fired = false;
    provider.onDidChangeTreeData(() => {
      fired = true;
    });
    provider.refresh();
    expect(fired).toBe(true);
    provider.dispose();
  });

  it("getTreeItem returns the item itself", () => {
    writeEntries([
      {
        timestamp: "2026-01-15T10:00:00Z",
        sessionId: "s1",
        eventType: "scan_executed",
      },
    ]);

    const provider = new AuditLogProvider();
    const children = provider.getChildren();
    const item = provider.getTreeItem(children[0]);
    expect(item).toBe(children[0]);
    provider.dispose();
  });
});

describe("AuditLogItem", () => {
  let tmpDir: string;
  let logPath: string;
  let vscodeModule: { __configValues: Record<string, unknown> };

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-audit-item-"));
    logPath = path.join(tmpDir, "audit.jsonl");
    vscodeModule = await import("vscode") as unknown as typeof vscodeModule;
    vscodeModule.__configValues["auditLogPath"] = logPath;
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vscodeModule.__configValues["auditLogPath"] = undefined;
  });

  function writeAndGetItem(entry: AuditLogEntry) {
    fs.writeFileSync(logPath, JSON.stringify(entry) + "\n");
    const provider = new AuditLogProvider();
    const children = provider.getChildren();
    provider.dispose();
    return children[0];
  }

  it("sets label with event type (spaces instead of underscores)", () => {
    const item = writeAndGetItem({
      timestamp: "2026-01-15T10:00:00Z",
      sessionId: "s1",
      eventType: "command_intercepted",
    });
    expect(item.label).toContain("command intercepted");
  });

  it("uses warning icon for critical risk", () => {
    const item = writeAndGetItem({
      timestamp: "2026-01-15T10:00:00Z",
      sessionId: "s1",
      eventType: "command_intercepted",
      action: { riskLevel: "critical" },
    });
    expect((item.iconPath as { id: string }).id).toBe("warning");
  });

  it("uses warning icon for high risk", () => {
    const item = writeAndGetItem({
      timestamp: "2026-01-15T10:00:00Z",
      sessionId: "s1",
      eventType: "command_intercepted",
      action: { riskLevel: "high" },
    });
    expect((item.iconPath as { id: string }).id).toBe("warning");
  });

  it("uses info icon for medium risk", () => {
    const item = writeAndGetItem({
      timestamp: "2026-01-15T10:00:00Z",
      sessionId: "s1",
      eventType: "command_intercepted",
      action: { riskLevel: "medium" },
    });
    expect((item.iconPath as { id: string }).id).toBe("info");
  });

  it("uses circle-outline icon for low/no risk", () => {
    const item = writeAndGetItem({
      timestamp: "2026-01-15T10:00:00Z",
      sessionId: "s1",
      eventType: "scan_executed",
    });
    expect((item.iconPath as { id: string }).id).toBe("circle-outline");
  });

  it("includes command in tooltip when present", () => {
    const item = writeAndGetItem({
      timestamp: "2026-01-15T10:00:00Z",
      sessionId: "s1",
      eventType: "command_intercepted",
      action: { command: "rm -rf /" },
    });
    expect((item.tooltip as { value: string }).value).toContain("rm -rf /");
  });

  it("includes agent type in tooltip when present", () => {
    const item = writeAndGetItem({
      timestamp: "2026-01-15T10:00:00Z",
      sessionId: "s1",
      eventType: "scan_executed",
      agentType: "claude",
    });
    expect((item.tooltip as { value: string }).value).toContain("claude");
  });

  it("includes action taken in tooltip when present", () => {
    const item = writeAndGetItem({
      timestamp: "2026-01-15T10:00:00Z",
      sessionId: "s1",
      eventType: "command_intercepted",
      resolution: { actionTaken: "blocked" },
    });
    expect((item.tooltip as { value: string }).value).toContain("blocked");
  });

  it("includes security check reason in tooltip", () => {
    const item = writeAndGetItem({
      timestamp: "2026-01-15T10:00:00Z",
      sessionId: "s1",
      eventType: "secret_detected",
      securityCheck: { passed: false, reason: "API key exposed" },
    });
    expect((item.tooltip as { value: string }).value).toContain("API key exposed");
  });
});

describe("RiskOverviewProvider", () => {
  let tmpDir: string;
  let logPath: string;
  let vscodeModule: { __configValues: Record<string, unknown> };

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-risk-overview-"));
    logPath = path.join(tmpDir, "audit.jsonl");
    vscodeModule = await import("vscode") as unknown as typeof vscodeModule;
    vscodeModule.__configValues["auditLogPath"] = logPath;
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vscodeModule.__configValues["auditLogPath"] = undefined;
  });

  function writeEntries(entries: AuditLogEntry[]): void {
    const lines = entries.map((e) => JSON.stringify(e)).join("\n");
    fs.writeFileSync(logPath, lines + "\n");
  }

  it("shows 'No audit events' when log is empty", () => {
    fs.writeFileSync(logPath, "");
    const provider = new RiskOverviewProvider();
    const children = provider.getChildren();
    expect(children.length).toBe(1);
    expect(children[0].label).toBe("No audit events");
    provider.dispose();
  });

  it("shows total event count", () => {
    writeEntries([
      { timestamp: "2026-01-15T10:00:00Z", sessionId: "s1", eventType: "scan_executed" },
      { timestamp: "2026-01-15T10:01:00Z", sessionId: "s2", eventType: "scan_executed" },
      { timestamp: "2026-01-15T10:02:00Z", sessionId: "s3", eventType: "config_changed" },
    ]);

    const provider = new RiskOverviewProvider();
    const children = provider.getChildren();
    const totalItem = children.find((c) => c.label === "Total Events");
    expect(totalItem).toBeDefined();
    expect(totalItem!.description).toBe("3");
    provider.dispose();
  });

  it("shows critical risk count when present", () => {
    writeEntries([
      {
        timestamp: "2026-01-15T10:00:00Z",
        sessionId: "s1",
        eventType: "command_intercepted",
        action: { riskLevel: "critical" },
      },
      {
        timestamp: "2026-01-15T10:01:00Z",
        sessionId: "s2",
        eventType: "command_intercepted",
        action: { riskLevel: "critical" },
      },
    ]);

    const provider = new RiskOverviewProvider();
    const children = provider.getChildren();
    const criticalItem = children.find((c) => c.label === "Critical");
    expect(criticalItem).toBeDefined();
    expect(criticalItem!.description).toBe("2");
    provider.dispose();
  });

  it("shows high and medium risk counts", () => {
    writeEntries([
      {
        timestamp: "2026-01-15T10:00:00Z",
        sessionId: "s1",
        eventType: "command_intercepted",
        action: { riskLevel: "high" },
      },
      {
        timestamp: "2026-01-15T10:01:00Z",
        sessionId: "s2",
        eventType: "command_intercepted",
        action: { riskLevel: "medium" },
      },
      {
        timestamp: "2026-01-15T10:02:00Z",
        sessionId: "s3",
        eventType: "command_intercepted",
        action: { riskLevel: "medium" },
      },
    ]);

    const provider = new RiskOverviewProvider();
    const children = provider.getChildren();
    const highItem = children.find((c) => c.label === "High");
    expect(highItem).toBeDefined();
    expect(highItem!.description).toBe("1");
    const medItem = children.find((c) => c.label === "Medium");
    expect(medItem).toBeDefined();
    expect(medItem!.description).toBe("2");
    provider.dispose();
  });

  it("omits risk levels with zero count", () => {
    writeEntries([
      {
        timestamp: "2026-01-15T10:00:00Z",
        sessionId: "s1",
        eventType: "scan_executed",
        action: { riskLevel: "low" },
      },
    ]);

    const provider = new RiskOverviewProvider();
    const children = provider.getChildren();
    expect(children.find((c) => c.label === "Critical")).toBeUndefined();
    expect(children.find((c) => c.label === "High")).toBeUndefined();
    expect(children.find((c) => c.label === "Medium")).toBeUndefined();
    provider.dispose();
  });

  it("shows event type breakdown", () => {
    writeEntries([
      { timestamp: "2026-01-15T10:00:00Z", sessionId: "s1", eventType: "secret_detected" },
      { timestamp: "2026-01-15T10:01:00Z", sessionId: "s2", eventType: "secret_detected" },
      { timestamp: "2026-01-15T10:02:00Z", sessionId: "s3", eventType: "command_intercepted" },
    ]);

    const provider = new RiskOverviewProvider();
    const children = provider.getChildren();
    const secretItem = children.find((c) => c.label === "secret detected");
    expect(secretItem).toBeDefined();
    expect(secretItem!.description).toBe("2");
    const cmdItem = children.find((c) => c.label === "command intercepted");
    expect(cmdItem).toBeDefined();
    expect(cmdItem!.description).toBe("1");
    provider.dispose();
  });

  it("uses key icon for secret_detected events", () => {
    writeEntries([
      { timestamp: "2026-01-15T10:00:00Z", sessionId: "s1", eventType: "secret_detected" },
    ]);

    const provider = new RiskOverviewProvider();
    const children = provider.getChildren();
    const secretItem = children.find((c) => c.label === "secret detected");
    expect((secretItem!.iconPath as { id: string }).id).toBe("key");
    provider.dispose();
  });

  it("uses terminal icon for command_intercepted events", () => {
    writeEntries([
      { timestamp: "2026-01-15T10:00:00Z", sessionId: "s1", eventType: "command_intercepted" },
    ]);

    const provider = new RiskOverviewProvider();
    const children = provider.getChildren();
    const cmdItem = children.find((c) => c.label === "command intercepted");
    expect((cmdItem!.iconPath as { id: string }).id).toBe("terminal");
    provider.dispose();
  });

  it("fires onDidChangeTreeData on refresh", () => {
    const provider = new RiskOverviewProvider();
    let fired = false;
    provider.onDidChangeTreeData(() => {
      fired = true;
    });
    provider.refresh();
    expect(fired).toBe(true);
    provider.dispose();
  });
});
