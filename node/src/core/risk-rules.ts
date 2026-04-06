/**
 * Centralized risk assessment rules.
 * Single source of truth — imported by command-interceptor, audit-logger, and config-defaults.
 */

export type CommandRiskLevel = "low" | "medium" | "high" | "critical";

/** Directories where `rm -rf /<dir>` is catastrophic (data loss / unbootable). */
const CRITICAL_DIRS = "home|etc|usr|boot|root|sys|proc|lib|lib64|bin|sbin|opt";

export const CRITICAL_PATTERNS: RegExp[] = [
  // rm -rf / (root only, any flag order)
  new RegExp(`rm\\s+(-[a-z]*r[a-z]*\\s+)*-[a-z]*f[a-z]*\\s+/(\\s|$)`),
  new RegExp(`rm\\s+(-[a-z]*f[a-z]*\\s+)*-[a-z]*r[a-z]*\\s+/(\\s|$)`),
  // rm -rf on critical top-level directories
  new RegExp(`rm\\s+(-[a-z]*r[a-z]*\\s+)*-[a-z]*f[a-z]*\\s+/(${CRITICAL_DIRS})(/|\\s|$)`),
  new RegExp(`rm\\s+(-[a-z]*f[a-z]*\\s+)*-[a-z]*r[a-z]*\\s+/(${CRITICAL_DIRS})(/|\\s|$)`),
  /:\(\)\{\s*:\|:&\s*\};:/,  // fork bomb
  /dd\s+if=.*of=\/dev\/sd/,
  />\s*\/dev\/sd/,
  /mkfs/,
  /fdisk/,
  /parted/,
];

export const HIGH_PATTERNS: RegExp[] = [
  /rm\s+(-[a-z]*r[a-z]*\s+)*-[a-z]*f[a-z]*/,  // rm -rf, -fr, -r -f, -f -r (any path)
  /rm\s+(-[a-z]*f[a-z]*\s+)*-[a-z]*r[a-z]*/,  // rm -fr, reversed
  /sudo\s+rm/,
  /chmod\s+777/,
  /curl.*\|\s*(bash|sh|zsh|dash)\b/,
  /wget.*\|\s*(bash|sh|zsh|dash)\b/,
  /git\s+push\b.*\s--force\b/,                           // --force anywhere after push
  /git\s+push\b.*\s-[a-zA-Z]*f\b/,                      // -f or combined flags like -vf
  /git\s+push\b.*\s--force-(with-lease|if-includes)\b/,  // specific force variants
  /git\s+push\s+\S*\s+\+/,                               // refspec force: git push origin +main
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
  "git push .* \\+",
];

/** Read-only commands whose arguments should not trigger risk patterns. */
const SAFE_PREFIX = /^(grep|egrep|fgrep|rg|ag|ack|echo|printf)\s/;

/** Shell operators that chain independent commands. */
const CHAIN_OPERATORS = /[;|&]|&&|\|\|/;

/**
 * Assess risk level of a command string.
 */
export function assessCommandRisk(command: string): CommandRiskLevel {
  const cmd = command.toLowerCase().trim();

  // Safe prefix only applies to simple (non-chained) commands
  if (SAFE_PREFIX.test(cmd) && !CHAIN_OPERATORS.test(cmd)) return "low";

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
