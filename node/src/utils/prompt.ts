import { createInterface } from "readline";

/**
 * Ask a yes/no question on stderr (keeps stdout clean for JSON output) and
 * resolve to a boolean. An empty answer resolves to `defaultYes`.
 *
 * Callers MUST gate this on `process.stdin.isTTY` — with no TTY the readline
 * prompt has no interactive input and would hang waiting for a line.
 */
export async function askYesNo(question: string, defaultYes = true): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const suffix = defaultYes ? "[Y/n]" : "[y/N]";
  return new Promise((resolve) => {
    rl.question(`  ${question} ${suffix} `, (answer) => {
      rl.close();
      const trimmed = answer.trim().toLowerCase();
      if (trimmed === "") resolve(defaultYes);
      else resolve(trimmed === "y" || trimmed === "yes");
    });
  });
}
