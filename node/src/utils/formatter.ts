import chalk from "chalk";

let agentMode = false;

export function setAgentMode(enabled: boolean): void {
  agentMode = enabled;
}

export function isAgentMode(): boolean {
  return agentMode;
}

export const fmt = {
  header(text: string): string {
    if (agentMode) return `=== ${text} ===`;
    return chalk.bold(`\n${chalk.cyan("┌─")} ${text} ${chalk.cyan("─┐")}\n`);
  },

  success(text: string): string {
    if (agentMode) return `[OK] ${text}`;
    return chalk.green(`✓ ${text}`);
  },

  warning(text: string): string {
    if (agentMode) return `[WARN] ${text}`;
    return chalk.yellow(`⚠️  ${text}`);
  },

  error(text: string): string {
    if (agentMode) return `[ERROR] ${text}`;
    return chalk.red(`✗ ${text}`);
  },

  severity(level: string): string {
    const upper = level.toUpperCase();
    if (agentMode) return `[${upper}]`;
    switch (level) {
      case "critical": return chalk.bgRed.white.bold(` ${upper} `);
      case "high": return chalk.bgYellow.black.bold(` ${upper} `);
      case "medium": return chalk.bgBlue.white(` ${upper} `);
      case "low": return chalk.bgGreen.white(` ${upper} `);
      default: return `[${upper}]`;
    }
  },

  divider(): string {
    if (agentMode) return "---";
    return chalk.gray("═".repeat(50));
  },

  info(text: string): string {
    if (agentMode) return text;
    return chalk.cyan(text);
  },
};
