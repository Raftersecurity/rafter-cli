import { Command } from "commander";
import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createInstallHookCommand(): Command {
  return new Command("install-hook")
    .description("Install pre-commit hook to scan for secrets")
    .option("--global", "Install globally for all repos (via git config)")
    .action(async (opts: { global?: boolean }) => {
      await installHook(opts);
    });
}

async function installHook(opts: { global?: boolean }): Promise<void> {
  if (opts.global) {
    await installGlobalHook();
  } else {
    await installLocalHook();
  }
}

/**
 * Install pre-commit hook for current repository
 */
async function installLocalHook(): Promise<void> {
  // Check if in a git repository
  try {
    execSync("git rev-parse --git-dir", { stdio: "pipe" });
  } catch (e) {
    console.error("❌ Error: Not in a git repository");
    console.error("   Run this command from inside a git repository");
    process.exit(1);
  }

  // Get .git directory
  const gitDir = execSync("git rev-parse --git-dir", { encoding: "utf-8" }).trim();
  const hooksDir = path.resolve(gitDir, "hooks");
  const hookPath = path.join(hooksDir, "pre-commit");

  // Ensure hooks directory exists
  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  // Check if hook already exists
  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, "utf-8");

    // Check if it's already a Rafter hook
    if (existing.includes("Rafter Security Pre-Commit Hook")) {
      console.log("✓ Rafter pre-commit hook already installed");
      return;
    }

    // Backup existing hook
    const backupPath = `${hookPath}.backup-${Date.now()}`;
    fs.copyFileSync(hookPath, backupPath);
    console.log(`📦 Backed up existing hook to: ${path.basename(backupPath)}`);
  }

  // Get hook template path
  const templatePath = path.join(__dirname, "..", "..", "..", "resources", "pre-commit-hook.sh");

  if (!fs.existsSync(templatePath)) {
    console.error("❌ Error: Hook template not found");
    console.error(`   Expected at: ${templatePath}`);
    process.exit(1);
  }

  // Copy hook template
  const hookContent = fs.readFileSync(templatePath, "utf-8");
  fs.writeFileSync(hookPath, hookContent, "utf-8");

  // Make executable
  fs.chmodSync(hookPath, 0o755);

  console.log("✓ Installed Rafter pre-commit hook");
  console.log(`  Location: ${hookPath}`);
  console.log();
  console.log("The hook will:");
  console.log("  • Scan staged files for secrets before each commit");
  console.log("  • Block commits if secrets are detected");
  console.log("  • Can be bypassed with: git commit --no-verify (not recommended)");
  console.log();
}

/**
 * Install pre-commit hook globally for all repositories
 */
async function installGlobalHook(): Promise<void> {
  // Create global hooks directory
  const homeDir = process.env.HOME || process.env.USERPROFILE;
  if (!homeDir) {
    console.error("❌ Error: Could not determine home directory");
    process.exit(1);
  }

  const globalHooksDir = path.join(homeDir, ".rafter", "git-hooks");
  const hookPath = path.join(globalHooksDir, "pre-commit");

  // Create directory
  if (!fs.existsSync(globalHooksDir)) {
    fs.mkdirSync(globalHooksDir, { recursive: true });
  }

  // Get hook template path
  const templatePath = path.join(__dirname, "..", "..", "..", "resources", "pre-commit-hook.sh");

  if (!fs.existsSync(templatePath)) {
    console.error("❌ Error: Hook template not found");
    console.error(`   Expected at: ${templatePath}`);
    process.exit(1);
  }

  // Copy hook template
  const hookContent = fs.readFileSync(templatePath, "utf-8");
  fs.writeFileSync(hookPath, hookContent, "utf-8");

  // Make executable
  fs.chmodSync(hookPath, 0o755);

  // Configure git to use global hooks directory
  try {
    execSync(`git config --global core.hooksPath "${globalHooksDir}"`, { stdio: "pipe" });
    console.log("✓ Installed Rafter pre-commit hook globally");
    console.log(`  Location: ${hookPath}`);
    console.log(`  Git config: core.hooksPath = ${globalHooksDir}`);
    console.log();
    console.log("The hook will apply to ALL git repositories on this machine.");
    console.log();
    console.log("To disable globally:");
    console.log(`  git config --global --unset core.hooksPath`);
    console.log();
    console.log("To install per-repository instead:");
    console.log(`  cd <repo> && rafter agent install-hook`);
    console.log();
  } catch (e) {
    console.error("❌ Failed to configure global git hooks");
    console.error("   You may need to manually set: git config --global core.hooksPath ~/.rafter/git-hooks");
    process.exit(1);
  }
}
