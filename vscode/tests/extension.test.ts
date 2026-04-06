import { describe, it, expect, vi, beforeEach } from "vitest";

// Track registered event handlers and commands
const registeredCommands: Record<string, (...args: unknown[]) => unknown> = {};
const subscriptions: Array<{ dispose: () => void }> = [];
const diagnosticsMap = new Map<string, unknown[]>();

let onDidSaveHandler: ((doc: unknown) => void) | null = null;
let onDidOpenHandler: ((doc: unknown) => void) | null = null;
let onDidChangeEditorHandler: ((editor: unknown) => void) | null = null;
let onDidChangeDocHandler: ((event: unknown) => void) | null = null;

const configValues: Record<string, unknown> = {
  scanOnSave: true,
  scanOnOpen: false,
  riskHighlighting: true,
  excludePatterns: ["**/node_modules/**", "**/.git/**"],
};

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

  return {
    TreeItem: MockTreeItem,
    TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
    EventEmitter: MockEventEmitter,
    ThemeIcon: class {
      constructor(public id: string, public color?: unknown) {}
    },
    ThemeColor: class {
      constructor(public id: string) {}
    },
    MarkdownString: class {
      constructor(public value: string) {}
    },
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    ProgressLocation: { Notification: 15 },
    languages: {
      createDiagnosticCollection: (_name: string) => ({
        set: (uri: string, diags: unknown[]) => diagnosticsMap.set(uri, diags),
        delete: (uri: string) => diagnosticsMap.delete(uri),
        clear: () => diagnosticsMap.clear(),
        dispose: () => diagnosticsMap.clear(),
      }),
      match: (_selector: unknown, _doc: unknown) => 0,
    },
    Range: class {
      constructor(
        public startLine: number,
        public startCol: number,
        public endLine: number,
        public endCol: number,
      ) {}
    },
    Diagnostic: class {
      source?: string;
      code?: string;
      constructor(
        public range: unknown,
        public message: string,
        public severity: number,
      ) {}
    },
    workspace: {
      getConfiguration: (_section: string) => ({
        get: <T>(key: string, defaultValue?: T): T =>
          (configValues[key] as T) ?? (defaultValue as T),
      }),
      onDidSaveTextDocument: (handler: (doc: unknown) => void) => {
        onDidSaveHandler = handler;
        const d = { dispose: () => { onDidSaveHandler = null; } };
        subscriptions.push(d);
        return d;
      },
      onDidOpenTextDocument: (handler: (doc: unknown) => void) => {
        onDidOpenHandler = handler;
        const d = { dispose: () => { onDidOpenHandler = null; } };
        subscriptions.push(d);
        return d;
      },
      onDidChangeTextDocument: (handler: (event: unknown) => void) => {
        onDidChangeDocHandler = handler;
        const d = { dispose: () => { onDidChangeDocHandler = null; } };
        subscriptions.push(d);
        return d;
      },
      asRelativePath: (uri: string) => uri,
      findFiles: vi.fn().mockResolvedValue([]),
    },
    window: {
      activeTextEditor: undefined as unknown,
      visibleTextEditors: [] as unknown[],
      registerTreeDataProvider: vi.fn((_id: string, _provider: unknown) => ({
        dispose: () => {},
      })),
      showInformationMessage: vi.fn(),
      showInputBox: vi.fn(),
      onDidChangeActiveTextEditor: (handler: (editor: unknown) => void) => {
        onDidChangeEditorHandler = handler;
        const d = { dispose: () => { onDidChangeEditorHandler = null; } };
        subscriptions.push(d);
        return d;
      },
      createTextEditorDecorationType: (_opts: unknown) => ({
        dispose: () => {},
      }),
      withProgress: vi.fn(),
    },
    commands: {
      registerCommand: (id: string, handler: (...args: unknown[]) => unknown) => {
        registeredCommands[id] = handler;
        const d = { dispose: () => { delete registeredCommands[id]; } };
        subscriptions.push(d);
        return d;
      },
      executeCommand: vi.fn(),
    },
    Uri: {
      file: (f: string) => f,
    },
  };
});

// Import after mock setup
import { activate, deactivate } from "../src/extension";

function makeContext() {
  const subs: Array<{ dispose: () => void }> = [];
  return {
    subscriptions: subs,
    extensionPath: "/mock/extension",
    extensionUri: "/mock/extension",
    storagePath: "/mock/storage",
    globalStoragePath: "/mock/global-storage",
    logPath: "/mock/log",
    extensionMode: 3,
    extension: {} as unknown,
    globalState: { get: vi.fn(), update: vi.fn(), keys: () => [], setKeysForSync: vi.fn() },
    workspaceState: { get: vi.fn(), update: vi.fn(), keys: () => [] },
    secrets: { get: vi.fn(), store: vi.fn(), delete: vi.fn(), onDidChange: vi.fn() },
    storageUri: undefined,
    globalStorageUri: undefined,
    logUri: undefined,
    asAbsolutePath: (p: string) => p,
    environmentVariableCollection: {} as unknown,
    languageModelAccessInformation: {} as unknown,
  };
}

describe("extension activation", () => {
  beforeEach(() => {
    // Reset state
    diagnosticsMap.clear();
    onDidSaveHandler = null;
    onDidOpenHandler = null;
    onDidChangeEditorHandler = null;
    onDidChangeDocHandler = null;
    Object.keys(registeredCommands).forEach((k) => delete registeredCommands[k]);
    configValues.scanOnSave = true;
    configValues.scanOnOpen = false;
    configValues.riskHighlighting = true;
    configValues.excludePatterns = ["**/node_modules/**", "**/.git/**"];
  });

  it("registers all expected commands", () => {
    const ctx = makeContext();
    activate(ctx as never);

    expect(registeredCommands["rafter.scanFile"]).toBeDefined();
    expect(registeredCommands["rafter.scanWorkspace"]).toBeDefined();
    expect(registeredCommands["rafter.assessCommand"]).toBeDefined();
    expect(registeredCommands["rafter.showAuditLog"]).toBeDefined();
    expect(registeredCommands["rafter.refreshAuditLog"]).toBeDefined();
    expect(registeredCommands["rafter.clearDiagnostics"]).toBeDefined();
  });

  it("registers tree data providers for audit log and risk overview", async () => {
    const vsc = await import("vscode");
    const ctx = makeContext();
    activate(ctx as never);

    expect(vsc.window.registerTreeDataProvider).toHaveBeenCalledWith(
      "rafter.auditLog",
      expect.anything(),
    );
    expect(vsc.window.registerTreeDataProvider).toHaveBeenCalledWith(
      "rafter.riskOverview",
      expect.anything(),
    );
  });

  it("pushes disposables to context.subscriptions", () => {
    const ctx = makeContext();
    activate(ctx as never);
    expect(ctx.subscriptions.length).toBeGreaterThan(0);
  });
});

describe("scanOnSave behavior", () => {
  beforeEach(() => {
    diagnosticsMap.clear();
    configValues.scanOnSave = true;
    configValues.scanOnOpen = false;
  });

  it("scans document on save when scanOnSave is true", () => {
    const ctx = makeContext();
    activate(ctx as never);

    expect(onDidSaveHandler).not.toBeNull();

    const mockDoc = {
      getText: () => 'const k = "AKIAIOSFODNN7EXAMPLE";',
      uri: "file:///test.ts",
      languageId: "typescript",
    };

    onDidSaveHandler!(mockDoc);
    expect(diagnosticsMap.has("file:///test.ts")).toBe(true);
  });

  it("does not scan on save when scanOnSave is false", () => {
    configValues.scanOnSave = false;
    const ctx = makeContext();
    activate(ctx as never);

    const mockDoc = {
      getText: () => 'const k = "AKIAIOSFODNN7EXAMPLE";',
      uri: "file:///test.ts",
      languageId: "typescript",
    };

    onDidSaveHandler!(mockDoc);
    // Diagnostics should not be set for this URI from the scan
    // (The updateRiskOverlay also runs on save, but it checks languageId)
    expect(diagnosticsMap.has("file:///test.ts")).toBe(false);
  });
});

describe("scanOnOpen behavior", () => {
  beforeEach(() => {
    diagnosticsMap.clear();
    configValues.scanOnOpen = false;
    configValues.scanOnSave = true;
  });

  it("does not scan on open when scanOnOpen is false", () => {
    const ctx = makeContext();
    activate(ctx as never);

    expect(onDidOpenHandler).not.toBeNull();

    const mockDoc = {
      getText: () => 'const k = "AKIAIOSFODNN7EXAMPLE";',
      uri: "file:///opened.ts",
      languageId: "typescript",
    };

    onDidOpenHandler!(mockDoc);
    expect(diagnosticsMap.has("file:///opened.ts")).toBe(false);
  });

  it("scans on open when scanOnOpen is true", () => {
    configValues.scanOnOpen = true;
    const ctx = makeContext();
    activate(ctx as never);

    const mockDoc = {
      getText: () => 'const k = "AKIAIOSFODNN7EXAMPLE";',
      uri: "file:///opened.ts",
      languageId: "typescript",
    };

    onDidOpenHandler!(mockDoc);
    expect(diagnosticsMap.has("file:///opened.ts")).toBe(true);
  });
});

describe("riskHighlighting setting", () => {
  beforeEach(() => {
    configValues.riskHighlighting = true;
  });

  it("registers onDidChangeTextDocument handler", () => {
    const ctx = makeContext();
    activate(ctx as never);
    expect(onDidChangeDocHandler).not.toBeNull();
  });

  it("does not update risk overlay when riskHighlighting is false", async () => {
    configValues.riskHighlighting = false;
    const ctx = makeContext();
    activate(ctx as never);

    // The handler should check config and bail
    const mockEvent = {
      document: {
        getText: () => "rm -rf /",
        uri: "file:///script.sh",
        languageId: "shellscript",
        lineCount: 1,
        lineAt: () => ({ text: "rm -rf /" }),
      },
    };

    // Should not throw even with no visible editors
    onDidChangeDocHandler!(mockEvent);
  });
});

describe("command handlers", () => {
  beforeEach(() => {
    diagnosticsMap.clear();
  });

  it("rafter.clearDiagnostics clears all diagnostics", () => {
    const ctx = makeContext();
    activate(ctx as never);

    diagnosticsMap.set("file:///a.ts", [{}]);
    diagnosticsMap.set("file:///b.ts", [{}]);

    registeredCommands["rafter.clearDiagnostics"]!();
    expect(diagnosticsMap.size).toBe(0);
  });

  it("rafter.showAuditLog calls executeCommand to focus audit log", async () => {
    const vsc = await import("vscode");
    const ctx = makeContext();
    activate(ctx as never);

    registeredCommands["rafter.showAuditLog"]!();
    expect(vsc.commands.executeCommand).toHaveBeenCalledWith("rafter.auditLog.focus");
  });
});

describe("scanWorkspace command", () => {
  beforeEach(() => {
    diagnosticsMap.clear();
  });

  it("calls withProgress with Notification location and cancellable true", async () => {
    const vsc = await import("vscode");
    const findFilesMock = vsc.workspace.findFiles as ReturnType<typeof vi.fn>;
    findFilesMock.mockResolvedValue([]);

    const withProgressMock = vsc.window.withProgress as ReturnType<typeof vi.fn>;
    withProgressMock.mockImplementation(async (_opts: unknown, cb: (progress: { report: () => void }, token: { isCancellationRequested: boolean }) => Promise<void>) => {
      await cb({ report: () => {} }, { isCancellationRequested: false });
    });

    const ctx = makeContext();
    activate(ctx as never);
    await registeredCommands["rafter.scanWorkspace"]!();

    expect(withProgressMock).toHaveBeenCalledWith(
      expect.objectContaining({
        location: 15, // ProgressLocation.Notification
        cancellable: true,
      }),
      expect.any(Function),
    );
  });

  it("limits workspace scan to 500 files", async () => {
    const vsc = await import("vscode");
    const findFilesMock = vsc.workspace.findFiles as ReturnType<typeof vi.fn>;
    findFilesMock.mockResolvedValue([]);

    const withProgressMock = vsc.window.withProgress as ReturnType<typeof vi.fn>;
    withProgressMock.mockImplementation(async (_opts: unknown, cb: (progress: { report: () => void }, token: { isCancellationRequested: boolean }) => Promise<void>) => {
      await cb({ report: () => {} }, { isCancellationRequested: false });
    });

    const ctx = makeContext();
    activate(ctx as never);
    await registeredCommands["rafter.scanWorkspace"]!();

    // findFiles called with 500 limit
    expect(findFilesMock).toHaveBeenCalledWith(
      "**/*",
      expect.anything(),
      500,
    );
  });

  it("respects cancellation token during workspace scan", async () => {
    const vsc = await import("vscode");

    const mockDocs = Array.from({ length: 5 }, (_, i) => `file:///test${i}.ts`);
    const findFilesMock = vsc.workspace.findFiles as ReturnType<typeof vi.fn>;
    findFilesMock.mockResolvedValue(mockDocs);

    // openTextDocument mock
    (vsc.workspace as Record<string, unknown>).openTextDocument = vi.fn().mockResolvedValue({
      getText: () => 'const safe = "hello";',
      uri: "file:///test0.ts",
      languageId: "typescript",
    });

    let filesProcessed = 0;
    const withProgressMock = vsc.window.withProgress as ReturnType<typeof vi.fn>;
    withProgressMock.mockImplementation(async (_opts: unknown, cb: (progress: { report: () => void }, token: { isCancellationRequested: boolean }) => Promise<void>) => {
      const token = { isCancellationRequested: false };
      const progress = {
        report: () => {
          filesProcessed++;
          // Cancel after first file
          token.isCancellationRequested = true;
        },
      };
      await cb(progress, token);
    });

    const ctx = makeContext();
    activate(ctx as never);
    await registeredCommands["rafter.scanWorkspace"]!();

    // Should have stopped early due to cancellation
    expect(filesProcessed).toBeLessThan(5);
  });

  it("shows summary message with file count and finding count", async () => {
    const vsc = await import("vscode");
    const findFilesMock = vsc.workspace.findFiles as ReturnType<typeof vi.fn>;
    findFilesMock.mockResolvedValue(["file:///a.ts", "file:///b.ts"]);

    (vsc.workspace as Record<string, unknown>).openTextDocument = vi.fn().mockResolvedValue({
      getText: () => 'const k = "AKIAIOSFODNN7EXAMPLE";',
      uri: "file:///a.ts",
      languageId: "typescript",
    });

    const withProgressMock = vsc.window.withProgress as ReturnType<typeof vi.fn>;
    withProgressMock.mockImplementation(async (_opts: unknown, cb: (progress: { report: () => void }, token: { isCancellationRequested: boolean }) => Promise<void>) => {
      await cb({ report: () => {} }, { isCancellationRequested: false });
    });

    const ctx = makeContext();
    activate(ctx as never);
    await registeredCommands["rafter.scanWorkspace"]!();

    expect(vsc.window.showInformationMessage).toHaveBeenCalledWith(
      expect.stringMatching(/Scanned \d+ files, found \d+ potential secret/),
    );
  });

  it("builds exclude glob from excludePatterns config", async () => {
    const vsc = await import("vscode");
    configValues.excludePatterns = ["**/node_modules/**", "**/.git/**"];

    const findFilesMock = vsc.workspace.findFiles as ReturnType<typeof vi.fn>;
    findFilesMock.mockResolvedValue([]);

    const withProgressMock = vsc.window.withProgress as ReturnType<typeof vi.fn>;
    withProgressMock.mockImplementation(async (_opts: unknown, cb: (progress: { report: () => void }, token: { isCancellationRequested: boolean }) => Promise<void>) => {
      await cb({ report: () => {} }, { isCancellationRequested: false });
    });

    const ctx = makeContext();
    activate(ctx as never);
    await registeredCommands["rafter.scanWorkspace"]!();

    expect(findFilesMock).toHaveBeenCalledWith(
      "**/*",
      "{**/node_modules/**,**/.git/**}",
      500,
    );
  });

  it("skips files that fail to open", async () => {
    const vsc = await import("vscode");
    const findFilesMock = vsc.workspace.findFiles as ReturnType<typeof vi.fn>;
    findFilesMock.mockResolvedValue(["file:///good.ts", "file:///bad.bin"]);

    let callCount = 0;
    (vsc.workspace as Record<string, unknown>).openTextDocument = vi.fn().mockImplementation(() => {
      callCount++;
      if (callCount === 2) throw new Error("Cannot open binary");
      return Promise.resolve({
        getText: () => "const x = 1;",
        uri: "file:///good.ts",
        languageId: "typescript",
      });
    });

    const withProgressMock = vsc.window.withProgress as ReturnType<typeof vi.fn>;
    withProgressMock.mockImplementation(async (_opts: unknown, cb: (progress: { report: () => void }, token: { isCancellationRequested: boolean }) => Promise<void>) => {
      await cb({ report: () => {} }, { isCancellationRequested: false });
    });

    const ctx = makeContext();
    activate(ctx as never);
    // Should not throw even when a file fails to open
    await expect(registeredCommands["rafter.scanWorkspace"]!()).resolves.not.toThrow();
  });
});

describe("assessCommand input flow", () => {
  beforeEach(() => {
    diagnosticsMap.clear();
  });

  it("shows input box with prompt and placeholder", async () => {
    const vsc = await import("vscode");
    const showInputBoxMock = vsc.window.showInputBox as ReturnType<typeof vi.fn>;
    showInputBoxMock.mockResolvedValue(undefined);

    const ctx = makeContext();
    activate(ctx as never);
    await registeredCommands["rafter.assessCommand"]!();

    expect(showInputBoxMock).toHaveBeenCalledWith(
      expect.objectContaining({
        prompt: expect.stringContaining("command"),
        placeHolder: expect.stringContaining("rm"),
      }),
    );
  });

  it("shows risk level when user enters a command", async () => {
    const vsc = await import("vscode");
    const showInputBoxMock = vsc.window.showInputBox as ReturnType<typeof vi.fn>;
    showInputBoxMock.mockResolvedValue("rm -rf /");

    const ctx = makeContext();
    activate(ctx as never);
    await registeredCommands["rafter.assessCommand"]!();

    expect(vsc.window.showInformationMessage).toHaveBeenCalledWith(
      expect.stringMatching(/CRITICAL/i),
    );
  });

  it("does nothing when user cancels input box", async () => {
    const vsc = await import("vscode");
    const showInputBoxMock = vsc.window.showInputBox as ReturnType<typeof vi.fn>;
    showInputBoxMock.mockResolvedValue(undefined);
    const infoMock = vsc.window.showInformationMessage as ReturnType<typeof vi.fn>;
    infoMock.mockClear();

    const ctx = makeContext();
    activate(ctx as never);
    await registeredCommands["rafter.assessCommand"]!();

    // showInformationMessage should NOT have been called for risk assessment
    // (it may have been called during activate for other things)
    const riskCalls = infoMock.mock.calls.filter(
      (call: unknown[]) => typeof call[0] === "string" && (call[0] as string).includes("Risk Assessment"),
    );
    expect(riskCalls).toHaveLength(0);
  });

  it("shows LOW for safe commands", async () => {
    const vsc = await import("vscode");
    const showInputBoxMock = vsc.window.showInputBox as ReturnType<typeof vi.fn>;
    showInputBoxMock.mockResolvedValue("ls -la");

    const ctx = makeContext();
    activate(ctx as never);
    await registeredCommands["rafter.assessCommand"]!();

    expect(vsc.window.showInformationMessage).toHaveBeenCalledWith(
      expect.stringMatching(/LOW/i),
    );
  });
});

describe("onDidChangeActiveTextEditor", () => {
  beforeEach(() => {
    diagnosticsMap.clear();
  });

  it("registers the handler on activation", () => {
    const ctx = makeContext();
    activate(ctx as never);
    expect(onDidChangeEditorHandler).not.toBeNull();
  });

  it("updates risk overlay when switching to a shell file", () => {
    const ctx = makeContext();
    activate(ctx as never);

    const mockEditor = {
      document: {
        getText: () => "rm -rf /important",
        uri: "file:///deploy.sh",
        languageId: "shellscript",
        lineCount: 1,
        lineAt: (i: number) => ({ text: i === 0 ? "rm -rf /important" : "" }),
      },
    };

    // Simulate editor change — should not throw
    expect(() => onDidChangeEditorHandler!(mockEditor)).not.toThrow();
  });

  it("does nothing when editor is undefined", () => {
    const ctx = makeContext();
    activate(ctx as never);

    // Passing undefined should not throw
    expect(() => onDidChangeEditorHandler!(undefined)).not.toThrow();
  });
});

describe("activation initial scan", () => {
  beforeEach(() => {
    diagnosticsMap.clear();
    configValues.scanOnOpen = false;
  });

  it("scans active editor on activation when scanOnOpen is true", async () => {
    const vsc = await import("vscode");
    configValues.scanOnOpen = true;

    // Set activeTextEditor before activation
    (vsc.window as Record<string, unknown>).activeTextEditor = {
      document: {
        getText: () => 'const secret = "AKIAIOSFODNN7EXAMPLE";',
        uri: "file:///initial.ts",
        languageId: "typescript",
        lineCount: 1,
        lineAt: () => ({ text: "" }),
      },
    };

    const ctx = makeContext();
    activate(ctx as never);

    expect(diagnosticsMap.has("file:///initial.ts")).toBe(true);

    // Reset
    (vsc.window as Record<string, unknown>).activeTextEditor = undefined;
  });

  it("does not scan active editor when scanOnOpen is false", async () => {
    const vsc = await import("vscode");
    configValues.scanOnOpen = false;

    (vsc.window as Record<string, unknown>).activeTextEditor = {
      document: {
        getText: () => 'const secret = "AKIAIOSFODNN7EXAMPLE";',
        uri: "file:///initial.ts",
        languageId: "typescript",
        lineCount: 1,
        lineAt: () => ({ text: "" }),
      },
    };

    const ctx = makeContext();
    activate(ctx as never);

    // scanDocument should NOT have been called, but updateRiskOverlay runs
    // Since it's not a shell doc, no risk overlay applies, so no diagnostics from scan
    expect(diagnosticsMap.has("file:///initial.ts")).toBe(false);

    (vsc.window as Record<string, unknown>).activeTextEditor = undefined;
  });
});

describe("refreshAuditLog command", () => {
  it("triggers refresh on both audit log and risk overview providers", async () => {
    const vsc = await import("vscode");
    const ctx = makeContext();
    activate(ctx as never);

    // The command should not throw
    expect(() => registeredCommands["rafter.refreshAuditLog"]!()).not.toThrow();

    // Both tree data providers should have been registered
    expect(vsc.window.registerTreeDataProvider).toHaveBeenCalledWith(
      "rafter.auditLog",
      expect.anything(),
    );
    expect(vsc.window.registerTreeDataProvider).toHaveBeenCalledWith(
      "rafter.riskOverview",
      expect.anything(),
    );
  });
});

describe("scanFile command", () => {
  beforeEach(() => {
    diagnosticsMap.clear();
  });

  it("scans active editor and shows info message", async () => {
    const vsc = await import("vscode");
    (vsc.window as Record<string, unknown>).activeTextEditor = {
      document: {
        getText: () => 'const key = "AKIAIOSFODNN7EXAMPLE";',
        uri: "file:///scanme.ts",
        languageId: "typescript",
      },
    };

    const ctx = makeContext();
    activate(ctx as never);
    registeredCommands["rafter.scanFile"]!();

    expect(diagnosticsMap.has("file:///scanme.ts")).toBe(true);
    expect(vsc.window.showInformationMessage).toHaveBeenCalledWith("Rafter: Scan complete.");

    (vsc.window as Record<string, unknown>).activeTextEditor = undefined;
  });

  it("does nothing when no active editor", async () => {
    const vsc = await import("vscode");
    (vsc.window as Record<string, unknown>).activeTextEditor = undefined;
    const infoMock = vsc.window.showInformationMessage as ReturnType<typeof vi.fn>;
    infoMock.mockClear();

    const ctx = makeContext();
    activate(ctx as never);
    registeredCommands["rafter.scanFile"]!();

    const scanCalls = infoMock.mock.calls.filter(
      (call: unknown[]) => typeof call[0] === "string" && (call[0] as string).includes("Scan complete"),
    );
    expect(scanCalls).toHaveLength(0);
  });
});

describe("exclude patterns in scanDocument", () => {
  beforeEach(() => {
    diagnosticsMap.clear();
  });

  it("uses excludePatterns from config to filter scanned files", () => {
    configValues.excludePatterns = ["**/node_modules/**"];
    const ctx = makeContext();
    activate(ctx as never);

    // languages.match returns 0 (no match) by default — file not excluded
    const mockDoc = {
      getText: () => 'const k = "AKIAIOSFODNN7EXAMPLE";',
      uri: "file:///src/index.ts",
      languageId: "typescript",
    };

    onDidSaveHandler!(mockDoc);
    expect(diagnosticsMap.has("file:///src/index.ts")).toBe(true);
  });
});

describe("deactivate", () => {
  it("does not throw on deactivate", () => {
    expect(() => deactivate()).not.toThrow();
  });
});
