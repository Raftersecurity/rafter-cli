import { Command } from "commander";
import { CommandInterceptor } from "../../core/command-interceptor.js";
import { RegexScanner } from "../../scanners/regex-scanner.js";
import { execSync } from "child_process";
import readline from "readline";
import { fmt } from "../../utils/formatter.js";

export function createExecCommand(): Command {
  return new Command("exec")
    .description("Execute command with security validation")
    .argument("<command>", "Command to execute")
    .option("--skip-scan", "Skip pre-execution file scanning")
    .option("--force", "Skip approval prompts (use with caution)")
    .action(async (command, opts) => {
      const interceptor = new CommandInterceptor();

      // Step 1: Evaluate command
      const evaluation = interceptor.evaluate(command);

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
          console.error(`\nRun 'rafter agent scan' for details.\n`);

          interceptor.logEvaluation(evaluation, "blocked");
          process.exit(1);
        }
      }

      // Step 4: Handle approval required
      if (evaluation.requiresApproval && !opts.force) {
        console.log(`\n${fmt.warning("Command requires approval")}\n`);
        console.log(`Risk Level: ${evaluation.riskLevel.toUpperCase()}`);
        console.log(`Command: ${command}`);
        if (evaluation.reason) {
          console.log(`Reason: ${evaluation.reason}`);
        }
        console.log();

        const approved = await promptApproval();

        if (!approved) {
          console.log(`\n${fmt.error("Command cancelled")}\n`);
          interceptor.logEvaluation(evaluation, "blocked");
          process.exit(1);
        }

        console.log(`\n${fmt.success("Command approved by user")}\n`);
        interceptor.logEvaluation(evaluation, "overridden");
      } else if (opts.force && evaluation.requiresApproval) {
        console.log(`\n${fmt.warning("Forcing execution (--force flag)")}\n`);
        interceptor.logEvaluation(evaluation, "overridden");
      } else {
        interceptor.logEvaluation(evaluation, "allowed");
      }

      // Step 5: Execute command
      try {
        const output = execSync(command, {
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

function isGitCommand(command: string): boolean {
  return command.trim().startsWith("git commit") ||
         command.trim().startsWith("git push");
}

async function scanStagedFiles(): Promise<{ secretsFound: boolean; count: number; files: number }> {
  try {
    // Get staged files
    const stagedFiles = execSync("git diff --cached --name-only", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"]
    })
      .trim()
      .split("\n")
      .filter(f => f);

    if (stagedFiles.length === 0) {
      return { secretsFound: false, count: 0, files: 0 };
    }

    // Scan staged files
    const scanner = new RegexScanner();
    const results = scanner.scanFiles(stagedFiles);

    const totalMatches = results.reduce((sum, r) => sum + r.matches.length, 0);

    return {
      secretsFound: results.length > 0,
      count: totalMatches,
      files: results.length
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
    rl.question("Approve this command? (yes/no): ", (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      resolve(normalized === "yes" || normalized === "y");
    });
  });
}
