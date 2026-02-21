/**
 * Centralized risk assessment rules.
 * Single source of truth — imported by command-interceptor, audit-logger, and config-defaults.
 */

export type CommandRiskLevel = "low" | "medium" | "high" | "critical";

export const CRITICAL_PATTERNS: RegExp[] = [
  /rm\s+-rf\s+\//,
  /:\(\)\{\s*:\|:&\s*\};:/,  // fork bomb
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
  /git\s+push\s+(--force|-f)\b/,
  /git\s+push\s+--force-(with-lease|if-includes)\b/,
  /git\s+push\s+\S*\s+\+\S+/,  // refspec force: git push origin +main
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

export const DEFAULT_BLOCKED_PATTERNS: string[] = [
  "rm -rf /",
  ":(){ :|:& };:",
  "dd if=/dev/zero of=/dev/sda",
  "> /dev/sda",
];

export const DEFAULT_REQUIRE_APPROVAL: string[] = [
  "rm -rf",
  "sudo rm",
  "curl.*\\|\\s*(bash|sh|zsh|dash)\\b",
  "wget.*\\|\\s*(bash|sh|zsh|dash)\\b",
  "chmod 777",
  "git push --force",
  "git push -f",
  "git push --force-with-lease",
  "git push --force-if-includes",
];

/**
 * Assess risk level of a command string.
 */
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
