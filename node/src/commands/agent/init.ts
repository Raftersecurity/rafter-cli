import { Command } from "commander";
import { ConfigManager } from "../../core/config-manager.js";
import { getRafterDir } from "../../core/config-defaults.js";
import { BinaryManager } from "../../utils/binary-manager.js";
import { SkillManager } from "../../utils/skill-manager.js";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";
import { fmt } from "../../utils/formatter.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function installClaudeCodeHooks(): void {
  const homeDir = os.homedir();
  const settingsPath = path.join(homeDir, ".claude", "settings.json");
  const claudeDir = path.join(homeDir, ".claude");

  if (!fs.existsSync(claudeDir)) {
    fs.mkdirSync(claudeDir, { recursive: true });
  }

  // Read existing settings or start fresh
  let settings: Record<string, any> = {};
  if (fs.existsSync(settingsPath)) {
    try {
      settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    } catch {
      // Corrupted file — start fresh but warn
      console.log(fmt.warning("Existing settings.json was unreadable, creating new one"));
    }
  }

  // Merge hooks — don't overwrite existing non-Rafter hooks
  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];
  if (!settings.hooks.PostToolUse) settings.hooks.PostToolUse = [];

  const preHook = { type: "command", command: "rafter hook pretool" };
  const postHook = { type: "command", command: "rafter hook posttool" };

  // Remove any existing Rafter hooks to avoid duplicates
  settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter(
    (entry: any) => {
      const hooks = entry.hooks || [];
      return !hooks.some((h: any) => h.command === "rafter hook pretool");
    }
  );
  settings.hooks.PostToolUse = settings.hooks.PostToolUse.filter(
    (entry: any) => {
      const hooks = entry.hooks || [];
      return !hooks.some((h: any) => h.command === "rafter hook posttool");
    }
  );

  // Add Rafter hooks
  settings.hooks.PreToolUse.push(
    { matcher: "Bash", hooks: [preHook] },
    { matcher: "Write|Edit", hooks: [preHook] },
  );
  settings.hooks.PostToolUse.push(
    { matcher: ".*", hooks: [postHook] },
  );

  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), "utf-8");
  console.log(fmt.success(`Installed PreToolUse hooks to ${settingsPath}`));
  console.log(fmt.success(`Installed PostToolUse hooks to ${settingsPath}`));
}

async function installClaudeCodeSkills(): Promise<void> {
  const homeDir = os.homedir();
  const claudeSkillsDir = path.join(homeDir, ".claude", "skills");

  // Ensure .claude/skills directory exists
  if (!fs.existsSync(claudeSkillsDir)) {
    fs.mkdirSync(claudeSkillsDir, { recursive: true });
  }

  // Install Backend Skill
  const backendSkillDir = path.join(claudeSkillsDir, "rafter");
  const backendSkillPath = path.join(backendSkillDir, "SKILL.md");
  const backendTemplatePath = path.join(__dirname, "..", "..", "..", ".claude", "skills", "rafter", "SKILL.md");

  if (!fs.existsSync(backendSkillDir)) {
    fs.mkdirSync(backendSkillDir, { recursive: true });
  }

  if (fs.existsSync(backendTemplatePath)) {
    fs.copyFileSync(backendTemplatePath, backendSkillPath);
    console.log(fmt.success(`Installed Rafter Backend skill to ${backendSkillPath}`));
  } else {
    console.log(fmt.warning(`Backend skill template not found at ${backendTemplatePath}`));
  }

  // Install Agent Security Skill
  const agentSkillDir = path.join(claudeSkillsDir, "rafter-agent-security");
  const agentSkillPath = path.join(agentSkillDir, "SKILL.md");
  const agentTemplatePath = path.join(__dirname, "..", "..", "..", ".claude", "skills", "rafter-agent-security", "SKILL.md");

  if (!fs.existsSync(agentSkillDir)) {
    fs.mkdirSync(agentSkillDir, { recursive: true });
  }

  if (fs.existsSync(agentTemplatePath)) {
    fs.copyFileSync(agentTemplatePath, agentSkillPath);
    console.log(fmt.success(`Installed Rafter Agent Security skill to ${agentSkillPath}`));
  } else {
    console.log(fmt.warning(`Agent Security skill template not found at ${agentTemplatePath}`));
  }
}

export function createInitCommand(): Command {
  return new Command("init")
    .description("Initialize agent security system")
    .option("--risk-level <level>", "Set risk level (minimal, moderate, aggressive)", "moderate")
    .option("--skip-openclaw", "Skip OpenClaw skill installation")
    .option("--skip-claude-code", "Skip Claude Code skill installation")
    .option("--claude-code", "Force Claude Code skill installation")
    .option("--skip-gitleaks", "Skip Gitleaks binary download")
    .option("--update", "Re-download gitleaks and reinstall integrations without resetting config")
    .action(async (opts) => {
      console.log(fmt.header("Rafter Agent Security Setup"));
      console.log(fmt.divider());
      console.log();

      const manager = new ConfigManager();

      // Detect environments
      const hasOpenClaw = fs.existsSync(path.join(os.homedir(), ".openclaw"));
      const hasClaudeCode = opts.claudeCode || fs.existsSync(path.join(os.homedir(), ".claude"));

      if (hasOpenClaw) {
        console.log(fmt.success("Detected environment: OpenClaw"));
      } else {
        console.log(fmt.info("OpenClaw not detected"));
      }

      if (hasClaudeCode) {
        console.log(fmt.success("Detected environment: Claude Code"));
      } else {
        console.log(fmt.info("Claude Code not detected"));
      }

      // Initialize directory structure
      try {
        await manager.initialize();
        console.log(fmt.success("Created config at ~/.rafter/config.json"));
      } catch (e) {
        console.error(fmt.error(`Failed to initialize: ${e}`));
        process.exit(1);
      }

      // Set risk level
      const validRiskLevels = ["minimal", "moderate", "aggressive"];
      if (!validRiskLevels.includes(opts.riskLevel)) {
        console.error(fmt.error(`Invalid risk level: ${opts.riskLevel}`));
        console.error(`Valid options: ${validRiskLevels.join(", ")}`);
        process.exit(1);
      }

      manager.set("agent.riskLevel", opts.riskLevel);
      console.log(fmt.success(`Set risk level: ${opts.riskLevel}`));

      // Check / download Gitleaks binary (optional)
      if (!opts.skipGitleaks) {
        const binaryManager = new BinaryManager();
        const platformInfo = binaryManager.getPlatformInfo();

        // Helper: show diagnostics for a failing binary (mirrors Python's agent init)
        const showDiagnostics = async (binaryPath: string, verResult: { ok: boolean; stdout: string; stderr: string }) => {
          if (verResult.stderr) {
            console.log(fmt.info(`  stderr: ${verResult.stderr}`));
          }
          const diag = await binaryManager.collectBinaryDiagnostics(binaryPath);
          if (diag) {
            console.log(fmt.info("Diagnostics:"));
            console.log(diag);
          }
          console.log(fmt.info("To fix: install gitleaks (https://github.com/gitleaks/gitleaks/releases) and ensure it is on PATH, then re-run 'rafter agent init'."));
          console.log();
        };

        if (!opts.update && binaryManager.isGitleaksInstalled()) {
          // Local binary exists — verify it actually works
          const verResult = await binaryManager.verifyGitleaksVerbose();
          if (verResult.ok) {
            console.log(fmt.success(`Gitleaks already installed (${verResult.stdout})`));
          } else {
            console.log(fmt.warning("Gitleaks binary found locally but failed to execute."));
            console.log(fmt.info(`  Binary: ${binaryManager.getGitleaksPath()}`));
            await showDiagnostics(binaryManager.getGitleaksPath(), verResult);
          }
        } else {
          // Not installed locally (or --update forcing re-download) — check PATH first
          // unless --update was passed (in that case force a fresh managed install)
          const pathBinary = opts.update ? null : binaryManager.findGitleaksOnPath();
          if (pathBinary) {
            const verResult = await binaryManager.verifyGitleaksVerbose(pathBinary);
            if (verResult.ok) {
              console.log(fmt.success(`Gitleaks available on PATH (${verResult.stdout})`));
            } else {
              console.log(fmt.warning("Gitleaks found on PATH but failed to execute."));
              console.log(fmt.info(`  Binary: ${pathBinary}`));
              await showDiagnostics(pathBinary, verResult);
            }
          } else if (!platformInfo.supported) {
            console.log(fmt.info(`Gitleaks not available for ${platformInfo.platform}/${platformInfo.arch}`));
            console.log(fmt.success("Using pattern-based scanning (21 patterns)"));
          } else {
            // Not on PATH, not installed locally — download
            console.log();
            console.log(fmt.info("Downloading Gitleaks (enhanced secret detection)..."));
            try {
              await binaryManager.downloadGitleaks((msg) => {
                console.log(`   ${msg}`);
              });
              console.log();
            } catch (e) {
              console.log();
              console.log(fmt.error(`Gitleaks setup failed — pattern-based scanning will be used instead.`));
              console.log(fmt.warning(String(e)));
              console.log();
              console.log(fmt.info("To fix: install gitleaks manually (https://github.com/gitleaks/gitleaks/releases) and ensure it is on PATH, then re-run 'rafter agent init'."));
              console.log();
            }
          }
        }
      }

      // Install OpenClaw skill if applicable
      if (hasOpenClaw && !opts.skipOpenclaw) {
        const skillManager = new SkillManager();
        const result = await skillManager.installRafterSkillVerbose();
        if (result.ok) {
          console.log(fmt.success("Installed Rafter Security skill to ~/.openclaw/skills/rafter-security.md"));
          manager.set("agent.environments.openclaw.enabled", true);
        } else {
          console.log(fmt.error("Failed to install Rafter Security skill"));
          console.log(fmt.warning(`  Source: ${result.sourcePath}`));
          console.log(fmt.warning(`  Destination: ${result.destPath}`));
          if (result.error) {
            console.log(fmt.warning(`  Error: ${result.error}`));
          }
        }
      }

      // Install Claude Code skills + hooks if applicable
      if (hasClaudeCode && !opts.skipClaudeCode) {
        try {
          await installClaudeCodeSkills();
          installClaudeCodeHooks();
          manager.set("agent.environments.claudeCode.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Claude Code integration: ${e}`));
        }
      }

      console.log();
      console.log(fmt.success("Agent security initialized!"));
      console.log();
      console.log("Next steps:");
      if (hasOpenClaw && !opts.skipOpenclaw) {
        console.log("  - Restart OpenClaw to load skill");
      }
      if (hasClaudeCode && !opts.skipClaudeCode) {
        console.log("  - Restart Claude Code to load skills");
      }
      console.log("  - Run: rafter agent scan . (test secret scanning)");
      console.log("  - Configure: rafter agent config show");
      console.log();
    });
}
