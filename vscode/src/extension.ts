/**
 * Rafter Security — VS Code extension entry point.
 *
 * Features:
 * 1. Secret scanning with editor diagnostics (on save / on demand)
 * 2. Command risk overlay for shell scripts
 * 3. Audit log panel with live-refresh
 */
import * as vscode from "vscode";
import { scanText } from "./secret-scanner";
import {
  isShellDocument,
  findRiskyCommands,
  applyRiskDecorations,
  clearRiskDecorations,
  getDecorationTypes,
  assessCommandRisk,
} from "./risk-overlay";
import { AuditLogProvider, RiskOverviewProvider } from "./audit-panel";

const DIAGNOSTIC_SOURCE = "rafter";

let diagnosticCollection: vscode.DiagnosticCollection;
let auditLogProvider: AuditLogProvider;
let riskOverviewProvider: RiskOverviewProvider;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);
  context.subscriptions.push(diagnosticCollection);

  // --- Audit log panel ---
  auditLogProvider = new AuditLogProvider();
  riskOverviewProvider = new RiskOverviewProvider();

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("rafter.auditLog", auditLogProvider),
    vscode.window.registerTreeDataProvider("rafter.riskOverview", riskOverviewProvider),
  );

  // --- Commands ---
  context.subscriptions.push(
    vscode.commands.registerCommand("rafter.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scanDocument(editor.document);
        vscode.window.showInformationMessage("Rafter: Scan complete.");
      }
    }),

    vscode.commands.registerCommand("rafter.scanWorkspace", async () => {
      await scanWorkspace();
    }),

    vscode.commands.registerCommand("rafter.assessCommand", async () => {
      const input = await vscode.window.showInputBox({
        prompt: "Enter a command to assess its risk level",
        placeHolder: "e.g., rm -rf /tmp/build",
      });
      if (input) {
        const risk = assessCommandRisk(input);
        const emoji = risk === "critical" ? "!!" : risk === "high" ? "!" : "";
        vscode.window.showInformationMessage(
          `Rafter Risk Assessment: ${risk.toUpperCase()} ${emoji} — ${input}`
        );
      }
    }),

    vscode.commands.registerCommand("rafter.showAuditLog", () => {
      vscode.commands.executeCommand("rafter.auditLog.focus");
    }),

    vscode.commands.registerCommand("rafter.refreshAuditLog", () => {
      auditLogProvider.refresh();
      riskOverviewProvider.refresh();
    }),

    vscode.commands.registerCommand("rafter.clearDiagnostics", () => {
      diagnosticCollection.clear();
    }),
  );

  // --- Event listeners ---
  const config = vscode.workspace.getConfiguration("rafter");

  // Scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (config.get<boolean>("scanOnSave", true)) {
        scanDocument(doc);
      }
      updateRiskOverlay(doc);
    }),
  );

  // Scan on open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (config.get<boolean>("scanOnOpen", false)) {
        scanDocument(doc);
      }
    }),
  );

  // Update risk overlay when active editor changes
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) {
        updateRiskOverlay(editor.document);
      }
    }),
  );

  // Update risk overlay on document change
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (config.get<boolean>("riskHighlighting", true)) {
        updateRiskOverlay(event.document);
      }
    }),
  );

  // Scan currently open editor on activation
  if (vscode.window.activeTextEditor) {
    const doc = vscode.window.activeTextEditor.document;
    if (config.get<boolean>("scanOnOpen", false)) {
      scanDocument(doc);
    }
    updateRiskOverlay(doc);
  }

  // Clean up decoration types on deactivate
  context.subscriptions.push({
    dispose: () => {
      for (const dt of Object.values(getDecorationTypes())) {
        dt.dispose();
      }
      auditLogProvider.dispose();
      riskOverviewProvider.dispose();
    },
  });
}

function scanDocument(doc: vscode.TextDocument): void {
  const config = vscode.workspace.getConfiguration("rafter");
  const excludePatterns = config.get<string[]>("excludePatterns", []);

  // Check if file matches any exclude pattern
  const relativePath = vscode.workspace.asRelativePath(doc.uri);
  for (const pattern of excludePatterns) {
    if (vscode.languages.match({ pattern }, doc)) {
      diagnosticCollection.delete(doc.uri);
      return;
    }
  }

  const matches = scanText(doc.getText());
  const diagnostics: vscode.Diagnostic[] = [];

  for (const m of matches) {
    const range = new vscode.Range(m.line, m.column, m.line, m.column + m.match.length);
    const severity = m.pattern.severity === "critical" || m.pattern.severity === "high"
      ? vscode.DiagnosticSeverity.Error
      : m.pattern.severity === "medium"
      ? vscode.DiagnosticSeverity.Warning
      : vscode.DiagnosticSeverity.Information;
    const diagnostic = new vscode.Diagnostic(
      range,
      `${m.pattern.name} detected (${m.pattern.severity})`,
      severity,
    );
    diagnostic.source = DIAGNOSTIC_SOURCE;
    diagnostic.code = m.pattern.name;
    diagnostics.push(diagnostic);
  }

  diagnosticCollection.set(doc.uri, diagnostics);
}

function updateRiskOverlay(doc: vscode.TextDocument): void {
  const config = vscode.workspace.getConfiguration("rafter");
  if (!config.get<boolean>("riskHighlighting", true)) return;

  const editor = vscode.window.visibleTextEditors.find((e) => e.document === doc);
  if (!editor) return;

  if (!isShellDocument(doc)) {
    clearRiskDecorations(editor);
    return;
  }

  const matches = findRiskyCommands(doc);
  applyRiskDecorations(editor, matches);
}

async function scanWorkspace(): Promise<void> {
  const config = vscode.workspace.getConfiguration("rafter");
  const excludePatterns = config.get<string[]>("excludePatterns", []);
  const excludeGlob = excludePatterns.length > 0
    ? `{${excludePatterns.join(",")}}`
    : undefined;

  const files = await vscode.workspace.findFiles("**/*", excludeGlob, 500);

  let totalFindings = 0;
  let filesScanned = 0;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Rafter: Scanning workspace for secrets...",
      cancellable: true,
    },
    async (progress, token) => {
      for (const file of files) {
        if (token.isCancellationRequested) break;

        try {
          const doc = await vscode.workspace.openTextDocument(file);
          // Skip binary-looking files
          if (doc.languageId === "binary") continue;

          scanDocument(doc);
          filesScanned++;
          const matches = scanText(doc.getText());
          totalFindings += matches.length;

          progress.report({
            increment: (1 / files.length) * 100,
            message: `${filesScanned}/${files.length} files`,
          });
        } catch {
          // Skip files that can't be opened
        }
      }
    },
  );

  vscode.window.showInformationMessage(
    `Rafter: Scanned ${filesScanned} files, found ${totalFindings} potential secret(s).`
  );
}

export function deactivate(): void {
  // Cleanup handled by disposables
}
