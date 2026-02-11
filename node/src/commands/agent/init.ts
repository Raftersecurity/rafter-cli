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

      // Download Gitleaks binary (optional)
      if (!opts.skipGitleaks) {
        const binaryManager = new BinaryManager();
        const platformInfo = binaryManager.getPlatformInfo();

        if (!platformInfo.supported) {
          console.log(fmt.info(`Gitleaks not available for ${platformInfo.platform}/${platformInfo.arch}`));
          console.log(fmt.success("Using pattern-based scanning (21 patterns)"));
        } else if (binaryManager.isGitleaksInstalled()) {
          const version = await binaryManager.getGitleaksVersion();
          console.log(fmt.success(`Gitleaks already installed (${version})`));
        } else {
          console.log();
          console.log(fmt.info("Downloading Gitleaks (enhanced secret detection)..."));
          try {
            await binaryManager.downloadGitleaks((msg) => {
              console.log(`   ${msg}`);
            });
            console.log();
          } catch (e) {
            console.log(fmt.warning(`Failed to download Gitleaks: ${e}`));
            console.log(fmt.success("Falling back to pattern-based scanning"));
            console.log();
          }
        }
      }

      // Install OpenClaw skill if applicable
      if (hasOpenClaw && !opts.skipOpenclaw) {
        try {
          const skillManager = new SkillManager();
          const installed = await skillManager.installRafterSkill();
          if (installed) {
            console.log(fmt.success("Installed Rafter Security skill to ~/.openclaw/skills/rafter-security.md"));
            manager.set("agent.environments.openclaw.enabled", true);
          } else {
            console.log(fmt.warning("Failed to install Rafter Security skill"));
          }
        } catch (e) {
          console.error(fmt.error(`Failed to install OpenClaw skill: ${e}`));
        }
      }

      // Install Claude Code skills if applicable
      if (hasClaudeCode && !opts.skipClaudeCode) {
        try {
          await installClaudeCodeSkills();
          manager.set("agent.environments.claudeCode.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Claude Code skills: ${e}`));
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
