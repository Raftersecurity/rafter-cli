import { Command, Option } from "commander";
import { CommandInterceptor } from "../../core/command-interceptor.js";
import { scanAddedDiffLines } from "../../scanners/git-diff-scan.js";
import { parseUnifiedDiffAddedLines } from "../../utils/git-diff.js";
import { execSync } from "child_process";
import readline from "readline";
import { fmt } from "../../utils/formatter.js";

// Approval model (rf-ss67): the only party who can approve a command that the
// policy says needs approval is a person at an interactive terminal. There is
// no flag, env var or stdin trick that stands in for that, because every one
// of those can be produced by the agent whose command is being gated:
//   * `--force` used to skip the prompt. Combined with the PreToolUse hook
//     treating a quoted argument as prose, `rafter agent exec --force "<cmd>"`
//     ran any HIGH-tier command unprompted with the hook blind. The flag is
//     kept only so old invocations parse; it changes nothing.
//   * A piped "yes" is not a person. Approval is offered only when stdin is a
//     TTY; otherwise the command is denied and says why.
// The machine owner widens policy in ~/.rafter/config.json, not per call.

const DRY_RUN_EXIT = { allowed: 0, blocked: 1, approval: 2 } as const;

export function createExecCommand(): Command {
  return new Command("exec")
    .description("Execute command with security validation")
    .argument("<command...>", "Command to execute (quote it, or pass it after --)")
    .option("--skip-scan", "Skip pre-execution file scanning")
    .option(
      "--dry-run",
      "Classify the command and exit without running it (exit 0 allowed, 1 blocked, 2 needs approval)",
    )
    .addOption(
      new Option("--force", "Deprecated: no longer skips approval (rf-ss67)").hideHelp(),
    )
    .action(async (parts: string[], opts) => {
      const command = joinCommandParts(parts);
      const interceptor = new CommandInterceptor();

      // Step 1: Evaluate command
      const evaluation = interceptor.evaluate(command);

      // Step 1b: --dry-run reports the classification and stops. Nothing runs,
      // nothing is scanned, nothing is logged as executed.
      if (opts.dryRun) {
        const blocked = !evaluation.allowed && !evaluation.requiresApproval;
        const verdict = blocked ? "BLOCKED" : evaluation.requiresApproval ? "REQUIRES APPROVAL" : "ALLOWED";
        console.log(`Dry run: ${verdict}`);
        console.log(`Risk Level: ${evaluation.riskLevel.toUpperCase()}`);
        console.log(`Requires approval: ${evaluation.requiresApproval ? "yes" : "no"}`);
        if (evaluation.reason) {
          console.log(`Reason: ${evaluation.reason}`);
        }
        console.log(`Command: ${command}`);
        console.log("Not executed (--dry-run).");
        process.exit(
          blocked ? DRY_RUN_EXIT.blocked : evaluation.requiresApproval ? DRY_RUN_EXIT.approval : DRY_RUN_EXIT.allowed,
        );
      }

      // Step 2: Handle blocked commands
      if (!evaluation.allowed && !evaluation.requiresApproval) {
        console.error(`\n${fmt.error("Command BLOCKED")}\n`);
        console.error(`Risk Level: ${evaluation.riskLevel.toUpperCase()}`);
        console.error(`Reason: ${evaluation.reason}`);
        console.error(`Command: ${command}\n`);

        interceptor.logEvaluation(evaluation, "blocked");
        process.exit(1);
      }

      // Step 3: Pre-execution scanning for git commands
      if (!opts.skipScan && isGitCommand(command)) {
        const scanResult = await scanStagedFiles();
        if (scanResult.secretsFound) {
          console.error(`\n${fmt.warning("Secrets detected in staged files!")}\n`);
          console.error(`Found ${scanResult.count} secret(s) in ${scanResult.files} file(s)`);
          console.error(`\nRun 'rafter secrets' for details.\n`);

          interceptor.logEvaluation(evaluation, "blocked");
          process.exit(1);
        }
      }

      // Step 4: Handle approval required — only a person at a terminal can.
      if (evaluation.requiresApproval) {
        if (opts.force) {
          console.log(
            `\n${fmt.warning("--force no longer skips approval (rf-ss67); approval needs a person at an interactive terminal")}\n`,
          );
        }
        console.log(`\n${fmt.warning("Command requires approval")}\n`);
        console.log(`Risk Level: ${evaluation.riskLevel.toUpperCase()}`);
        console.log(`Command: ${command}`);
        if (evaluation.reason) {
          console.log(`Reason: ${evaluation.reason}`);
        }
        console.log();

        if (!process.stdin.isTTY) {
          console.log(`${fmt.error("Command denied: approval needs an interactive terminal, and stdin is not one")}`);
          console.log(
            "Run the command yourself at a terminal, or have the machine owner adjust " +
              "commandPolicy in ~/.rafter/config.json.\n",
          );
          interceptor.logEvaluation(evaluation, "blocked");
          process.exit(1);
        }

        const approved = await promptApproval();

        if (!approved) {
          console.log(`\n${fmt.error("Command cancelled")}\n`);
          interceptor.logEvaluation(evaluation, "blocked");
          process.exit(1);
        }

        console.log(`\n${fmt.success("Command approved by user")}\n`);
        interceptor.logEvaluation(evaluation, "overridden");
      } else {
        interceptor.logEvaluation(evaluation, "allowed");
      }

      // Step 5: Execute command
      try {
        execSync(command, {
          stdio: "inherit",
          encoding: "utf-8"
        });

        console.log(`\n${fmt.success("Command executed successfully")}\n`);
        process.exit(0);
      } catch (e: any) {
        console.error(`\n${fmt.error(`Command failed with exit code ${e.status}`)}\n`);
        process.exit(e.status || 1);
      }
    });
}

/**
 * One quoted argument is the command verbatim. Several (the `-- rm -rf x` form
 * the docs show) are re-joined with shell quoting, so what the classifier sees
 * is what the shell will run — `-- echo "a b"` becomes `echo 'a b'`, not `echo a b`.
 */
export function joinCommandParts(parts: string[]): string {
  if (parts.length === 1) return parts[0];
  return parts.map(shellQuote).join(" ");
}

function shellQuote(token: string): string {
  if (token === "") return "''";
  if (/^[A-Za-z0-9_\/:=@.,+%-]+$/.test(token)) return token;
  return `'${token.replace(/'/g, `'\\''`)}'`;
}

function isGitCommand(command: string): boolean {
  return command.trim().startsWith("git commit") ||
         command.trim().startsWith("git push");
}

async function scanStagedFiles(): Promise<{ secretsFound: boolean; count: number; files: number }> {
  try {
    const patch = execSync("git diff -U0 --no-color --cached --diff-filter=ACM", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();

    if (!patch) {
      return { secretsFound: false, count: 0, files: 0 };
    }

    const repoRoot = execSync("git rev-parse --show-toplevel", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();

    const addedLines = parseUnifiedDiffAddedLines(patch);
    if (addedLines.length === 0) {
      return { secretsFound: false, count: 0, files: 0 };
    }

    const results = scanAddedDiffLines(addedLines, repoRoot);
    const totalMatches = results.reduce((sum, r) => sum + r.matches.length, 0);

    return {
      secretsFound: results.length > 0,
      count: totalMatches,
      files: results.length,
    };
  } catch {
    // If git command fails (not in repo, etc.), skip scanning
    return { secretsFound: false, count: 0, files: 0 };
  }
}

async function promptApproval(): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    // Handle EOF / non-interactive stdin (e.g. piped or closed stdin)
    rl.on("close", () => resolve(false));
    rl.question("Approve this command? (yes/no): ", (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      resolve(normalized === "yes" || normalized === "y");
    });
  });
}
