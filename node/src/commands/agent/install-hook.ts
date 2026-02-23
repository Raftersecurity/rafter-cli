import { Command } from "commander";
import fs from "fs";
import os from "os";
import path from "path";
import { execSync } from "child_process";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createInstallHookCommand(): Command {
  return new Command("install-hook")
    .description("Install git hook to scan for secrets")
    .option("--global", "Install globally for all repos (via git config)")
    .option("--push", "Install pre-push hook instead of pre-commit")
    .action(async (opts: { global?: boolean; push?: boolean }) => {
      await installHook(opts);
    });
}

async function installHook(opts: { global?: boolean; push?: boolean }): Promise<void> {
  const hookName = opts.push ? "pre-push" : "pre-commit";
  const templateName = opts.push ? "pre-push-hook.sh" : "pre-commit-hook.sh";

  if (opts.global) {
    await installGlobalHook(hookName, templateName);
  } else {
    await installLocalHook(hookName, templateName);
  }
}

function getTemplatePath(templateName: string): string {
  const templatePath = path.join(__dirname, "..", "..", "..", "resources", templateName);
  if (!fs.existsSync(templatePath)) {
    console.error("❌ Error: Hook template not found");
    console.error(`   Expected at: ${templatePath}`);
    process.exit(1);
  }
  return templatePath;
}

/**
 * Install hook for current repository
 */
async function installLocalHook(hookName: string, templateName: string): Promise<void> {
  try {
    execSync("git rev-parse --git-dir", { stdio: "pipe" });
  } catch (e) {
    console.error("❌ Error: Not in a git repository");
    console.error("   Run this command from inside a git repository");
    process.exit(1);
  }

  const gitDir = execSync("git rev-parse --git-dir", { encoding: "utf-8" }).trim();
  const hooksDir = path.resolve(gitDir, "hooks");
  const hookPath = path.join(hooksDir, hookName);

  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, "utf-8");
    const marker = hookName === "pre-push" ? "Rafter Security Pre-Push Hook" : "Rafter Security Pre-Commit Hook";
    if (existing.includes(marker)) {
      console.log(`✓ Rafter ${hookName} hook already installed`);
      return;
    }
    const backupPath = `${hookPath}.backup-${Date.now()}`;
    fs.copyFileSync(hookPath, backupPath);
    console.log(`📦 Backed up existing hook to: ${path.basename(backupPath)}`);
  }

  const hookContent = fs.readFileSync(getTemplatePath(templateName), "utf-8");
  fs.writeFileSync(hookPath, hookContent, "utf-8");
  fs.chmodSync(hookPath, 0o755);

  console.log(`✓ Installed Rafter ${hookName} hook`);
  console.log(`  Location: ${hookPath}`);
  console.log();
  if (hookName === "pre-push") {
    console.log("The hook will:");
    console.log("  • Scan commits being pushed for secrets");
    console.log("  • Block pushes if secrets are detected");
    console.log("  • Can be bypassed with: git push --no-verify (not recommended)");
  } else {
    console.log("The hook will:");
    console.log("  • Scan staged files for secrets before each commit");
    console.log("  • Block commits if secrets are detected");
    console.log("  • Can be bypassed with: git commit --no-verify (not recommended)");
  }
  console.log();
}

/**
 * Install hook globally for all repositories
 */
async function installGlobalHook(hookName: string, templateName: string): Promise<void> {
  const homeDir = os.homedir();
  if (!homeDir) {
    console.error("❌ Error: Could not determine home directory");
    process.exit(1);
  }

  const globalHooksDir = path.join(homeDir, ".rafter", "git-hooks");
  const hookPath = path.join(globalHooksDir, hookName);

  if (!fs.existsSync(globalHooksDir)) {
    fs.mkdirSync(globalHooksDir, { recursive: true });
  }

  const hookContent = fs.readFileSync(getTemplatePath(templateName), "utf-8");
  fs.writeFileSync(hookPath, hookContent, "utf-8");
  fs.chmodSync(hookPath, 0o755);

  try {
    execSync(`git config --global core.hooksPath "${globalHooksDir}"`, { stdio: "pipe" });
    console.log(`✓ Installed Rafter ${hookName} hook globally`);
    console.log(`  Location: ${hookPath}`);
    console.log(`  Git config: core.hooksPath = ${globalHooksDir}`);
    console.log();
    console.log("The hook will apply to ALL git repositories on this machine.");
    console.log();
    console.log("To disable globally:");
    console.log(`  git config --global --unset core.hooksPath`);
    console.log();
    console.log("To install per-repository instead:");
    console.log(`  cd <repo> && rafter agent install-hook${hookName === "pre-push" ? " --push" : ""}`);
    console.log();
  } catch (e) {
    console.error("❌ Failed to configure global git hooks");
    console.error("   You may need to manually set: git config --global core.hooksPath ~/.rafter/git-hooks");
    process.exit(1);
  }
}
