/**
 * Command risk overlay — highlights risky commands in shell scripts.
 *
 * VS Code decoration layer on top of risk-rules.ts.
 */
import * as vscode from "vscode";
import {
  type CommandRiskLevel,
  CRITICAL_PATTERNS,
  HIGH_PATTERNS,
  MEDIUM_PATTERNS,
  assessCommandRisk,
} from "./risk-rules";

export { assessCommandRisk };
export type { CommandRiskLevel };

export interface RiskMatch {
  level: CommandRiskLevel;
  line: number;
  startCol: number;
  endCol: number;
  text: string;
}

const SHELL_LANGUAGES = new Set([
  "shellscript", "bash", "sh", "zsh", "fish",
  "dockerfile", "makefile",
]);

export function isShellDocument(doc: vscode.TextDocument): boolean {
  return SHELL_LANGUAGES.has(doc.languageId);
}

export function findRiskyCommands(doc: vscode.TextDocument): RiskMatch[] {
  const matches: RiskMatch[] = [];
  const allPatterns: Array<{ patterns: RegExp[]; level: CommandRiskLevel }> = [
    { patterns: CRITICAL_PATTERNS, level: "critical" },
    { patterns: HIGH_PATTERNS, level: "high" },
    { patterns: MEDIUM_PATTERNS, level: "medium" },
  ];

  for (let i = 0; i < doc.lineCount; i++) {
    const line = doc.lineAt(i);
    const text = line.text;

    // Skip comments
    if (/^\s*#/.test(text)) continue;

    for (const { patterns, level } of allPatterns) {
      for (const pattern of patterns) {
        const match = pattern.exec(text);
        if (match) {
          matches.push({
            level,
            line: i,
            startCol: match.index,
            endCol: match.index + match[0].length,
            text: match[0],
          });
          break; // One match per pattern group per line
        }
      }
    }
  }

  return matches;
}

const DECORATION_TYPES: Record<Exclude<CommandRiskLevel, "low">, vscode.TextEditorDecorationType> = {
  critical: vscode.window.createTextEditorDecorationType({
    backgroundColor: "rgba(255, 0, 0, 0.15)",
    border: "1px solid rgba(255, 0, 0, 0.4)",
    borderRadius: "2px",
    after: {
      contentText: " CRITICAL RISK",
      color: "rgba(255, 80, 80, 0.8)",
      fontWeight: "bold",
      margin: "0 0 0 1em",
    },
  }),
  high: vscode.window.createTextEditorDecorationType({
    backgroundColor: "rgba(255, 140, 0, 0.12)",
    border: "1px solid rgba(255, 140, 0, 0.35)",
    borderRadius: "2px",
    after: {
      contentText: " HIGH RISK",
      color: "rgba(255, 165, 0, 0.8)",
      fontWeight: "bold",
      margin: "0 0 0 1em",
    },
  }),
  medium: vscode.window.createTextEditorDecorationType({
    backgroundColor: "rgba(255, 255, 0, 0.08)",
    border: "1px solid rgba(255, 255, 0, 0.25)",
    borderRadius: "2px",
    after: {
      contentText: " MEDIUM RISK",
      color: "rgba(200, 200, 0, 0.7)",
      margin: "0 0 0 1em",
    },
  }),
};

export function getDecorationTypes(): Record<string, vscode.TextEditorDecorationType> {
  return DECORATION_TYPES;
}

export function applyRiskDecorations(editor: vscode.TextEditor, matches: RiskMatch[]): void {
  const groups: Record<string, vscode.DecorationOptions[]> = {
    critical: [],
    high: [],
    medium: [],
  };

  for (const m of matches) {
    const range = new vscode.Range(m.line, m.startCol, m.line, m.endCol);
    const hoverMessage = new vscode.MarkdownString(
      `**Rafter Risk: ${m.level.toUpperCase()}**\n\n` +
      `Command: \`${m.text}\`\n\n` +
      `This command has been classified as ${m.level}-risk by rafter's security engine.`
    );
    groups[m.level]?.push({ range, hoverMessage });
  }

  for (const [level, decorations] of Object.entries(groups)) {
    const decorationType = DECORATION_TYPES[level as keyof typeof DECORATION_TYPES];
    if (decorationType) {
      editor.setDecorations(decorationType, decorations);
    }
  }
}

export function clearRiskDecorations(editor: vscode.TextEditor): void {
  for (const decorationType of Object.values(DECORATION_TYPES)) {
    editor.setDecorations(decorationType, []);
  }
}
