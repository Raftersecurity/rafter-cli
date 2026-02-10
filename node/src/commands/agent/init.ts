import { Command } from "commander";
import { ConfigManager } from "../../core/config-manager.js";
import { getRafterDir } from "../../core/config-defaults.js";
import { BinaryManager } from "../../utils/binary-manager.js";
import { SkillManager } from "../../utils/skill-manager.js";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function installCodexSkills(): Promise<void> {
  const homeDir = os.homedir();
  const codexSkillsDir = path.join(homeDir, ".agents", "skills");

  // Ensure ~/.agents/skills directory exists
  if (!fs.existsSync(codexSkillsDir)) {
    fs.mkdirSync(codexSkillsDir, { recursive: true });
  }

  // Install Backend Skill
  const backendSkillDir = path.join(codexSkillsDir, "rafter");
  const backendSkillPath = path.join(backendSkillDir, "SKILL.md");
  const backendTemplatePath = path.join(__dirname, "..", "..", "..", ".agents", "skills", "rafter", "SKILL.md");

  if (!fs.existsSync(backendSkillDir)) {
    fs.mkdirSync(backendSkillDir, { recursive: true });
  }

  if (fs.existsSync(backendTemplatePath)) {
    fs.copyFileSync(backendTemplatePath, backendSkillPath);
    console.log(`✓ Installed Rafter Backend skill to ${backendSkillPath}`);
  } else {
    console.log(`⚠️  Backend skill template not found at ${backendTemplatePath}`);
  }

  // Install Agent Security Skill
  const agentSkillDir = path.join(codexSkillsDir, "rafter-agent-security");
  const agentSkillPath = path.join(agentSkillDir, "SKILL.md");
  const agentTemplatePath = path.join(__dirname, "..", "..", "..", ".agents", "skills", "rafter-agent-security", "SKILL.md");

  if (!fs.existsSync(agentSkillDir)) {
    fs.mkdirSync(agentSkillDir, { recursive: true });
  }

  if (fs.existsSync(agentTemplatePath)) {
    fs.copyFileSync(agentTemplatePath, agentSkillPath);
    console.log(`✓ Installed Rafter Agent Security skill to ${agentSkillPath}`);
  } else {
    console.log(`⚠️  Agent Security skill template not found at ${agentTemplatePath}`);
  }
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
    console.log(`✓ Installed Rafter Backend skill to ${backendSkillPath}`);
  } else {
    console.log(`⚠️  Backend skill template not found at ${backendTemplatePath}`);
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
    console.log(`✓ Installed Rafter Agent Security skill to ${agentSkillPath}`);
  } else {
    console.log(`⚠️  Agent Security skill template not found at ${agentTemplatePath}`);
  }
}

export function createInitCommand(): Command {
  return new Command("init")
    .description("Initialize agent security system")
    .option("--risk-level <level>", "Set risk level (minimal, moderate, aggressive)", "moderate")
    .option("--skip-openclaw", "Skip OpenClaw skill installation")
    .option("--skip-claude-code", "Skip Claude Code skill installation")
    .option("--claude-code", "Force Claude Code skill installation")
    .option("--skip-codex", "Skip Codex CLI skill installation")
    .option("--codex", "Force Codex CLI skill installation")
    .option("--skip-gitleaks", "Skip Gitleaks binary download")
    .action(async (opts) => {
      console.log("\n🛡️  Rafter Agent Security Setup");
      console.log("━".repeat(40));
      console.log();

      const manager = new ConfigManager();

      // Detect environments
      const hasOpenClaw = fs.existsSync(path.join(os.homedir(), ".openclaw"));
      const hasClaudeCode = opts.claudeCode || fs.existsSync(path.join(os.homedir(), ".claude"));
      const hasCodex = opts.codex || fs.existsSync(path.join(os.homedir(), ".codex"));

      if (hasOpenClaw) {
        console.log("✓ Detected environment: OpenClaw");
      } else {
        console.log("ℹ️  OpenClaw not detected");
      }

      if (hasClaudeCode) {
        console.log("✓ Detected environment: Claude Code");
      } else {
        console.log("ℹ️  Claude Code not detected");
      }

      if (hasCodex) {
        console.log("✓ Detected environment: Codex CLI");
      } else {
        console.log("ℹ️  Codex CLI not detected");
      }

      // Initialize directory structure
      try {
        await manager.initialize();
        console.log(`✓ Created config at ~/.rafter/config.json`);
      } catch (e) {
        console.error(`Failed to initialize: ${e}`);
        process.exit(1);
      }

      // Set risk level
      const validRiskLevels = ["minimal", "moderate", "aggressive"];
      if (!validRiskLevels.includes(opts.riskLevel)) {
        console.error(`Invalid risk level: ${opts.riskLevel}`);
        console.error(`Valid options: ${validRiskLevels.join(", ")}`);
        process.exit(1);
      }

      manager.set("agent.riskLevel", opts.riskLevel);
      console.log(`✓ Set risk level: ${opts.riskLevel}`);

      // Download Gitleaks binary (optional)
      if (!opts.skipGitleaks) {
        const binaryManager = new BinaryManager();
        const platformInfo = binaryManager.getPlatformInfo();

        if (!platformInfo.supported) {
          console.log(`ℹ️  Gitleaks not available for ${platformInfo.platform}/${platformInfo.arch}`);
          console.log("✓ Using pattern-based scanning (21 patterns)");
        } else if (binaryManager.isGitleaksInstalled()) {
          const version = await binaryManager.getGitleaksVersion();
          console.log(`✓ Gitleaks already installed (${version})`);
        } else {
          console.log();
          console.log("📦 Downloading Gitleaks (enhanced secret detection)...");
          try {
            await binaryManager.downloadGitleaks((msg) => {
              console.log(`   ${msg}`);
            });
            console.log();
          } catch (e) {
            console.log(`⚠️  Failed to download Gitleaks: ${e}`);
            console.log("✓ Falling back to pattern-based scanning");
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
            console.log("✓ Installed Rafter Security skill to ~/.openclaw/skills/rafter-security.md");
            manager.set("agent.environments.openclaw.enabled", true);
          } else {
            console.log("⚠️  Failed to install Rafter Security skill");
          }
        } catch (e) {
          console.error(`Failed to install OpenClaw skill: ${e}`);
        }
      }

      // Install Claude Code skills if applicable
      if (hasClaudeCode && !opts.skipClaudeCode) {
        try {
          await installClaudeCodeSkills();
          manager.set("agent.environments.claudeCode.enabled", true);
        } catch (e) {
          console.error(`Failed to install Claude Code skills: ${e}`);
        }
      }

      // Install Codex CLI skills if applicable
      if (hasCodex && !opts.skipCodex) {
        try {
          await installCodexSkills();
          manager.set("agent.environments.codex.enabled", true);
        } catch (e) {
          console.error(`Failed to install Codex CLI skills: ${e}`);
        }
      }

      console.log();
      console.log("✓ Agent security initialized!");
      console.log();
      console.log("Next steps:");
      if (hasOpenClaw && !opts.skipOpenclaw) {
        console.log("  - Restart OpenClaw to load skill");
      }
      if (hasClaudeCode && !opts.skipClaudeCode) {
        console.log("  - Restart Claude Code to load skills");
      }
      if (hasCodex && !opts.skipCodex) {
        console.log("  - Restart Codex CLI to load skills");
      }
      console.log("  - Run: rafter agent scan . (test secret scanning)");
      console.log("  - Configure: rafter agent config show");
      console.log();
    });
}
