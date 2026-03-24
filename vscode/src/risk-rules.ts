/**
 * Command risk classification — pure logic, no VS Code dependency.
 *
 * Mirrors node/src/core/risk-rules.ts patterns.
 */

export type CommandRiskLevel = "low" | "medium" | "high" | "critical";

export const CRITICAL_PATTERNS: RegExp[] = [
  /rm\s+-rf\s+\//,
  /:\(\)\{\s*:\|:&\s*\};:/,
  /dd\s+if=.*of=\/dev\/sd/,
  />\s*\/dev\/sd/,
  /mkfs/,
  /fdisk/,
  /parted/,
];

export const HIGH_PATTERNS: RegExp[] = [
  /rm\s+-rf/,
  /sudo\s+rm/,
  /chmod\s+777/,
  /curl.*\|\s*(bash|sh|zsh|dash)\b/,
  /wget.*\|\s*(bash|sh|zsh|dash)\b/,
  /git\s+push\b.*\s--force\b/,
  /git\s+push\b.*\s-[a-zA-Z]*f\b/,
  /git\s+push\b.*\s--force-(with-lease|if-includes)\b/,
  /git\s+push\s+\S*\s+\+/,
  /docker\s+system\s+prune/,
  /npm\s+publish/,
  /pypi.*upload/,
];

export const MEDIUM_PATTERNS: RegExp[] = [
  /sudo/,
  /chmod/,
  /chown/,
  /systemctl/,
  /service/,
  /kill\s+-9/,
  /pkill/,
  /killall/,
];

export function assessCommandRisk(command: string): CommandRiskLevel {
  const cmd = command.toLowerCase();
  for (const pattern of CRITICAL_PATTERNS) {
    if (pattern.test(cmd)) return "critical";
  }
  for (const pattern of HIGH_PATTERNS) {
    if (pattern.test(cmd)) return "high";
  }
  for (const pattern of MEDIUM_PATTERNS) {
    if (pattern.test(cmd)) return "medium";
  }
  return "low";
}
