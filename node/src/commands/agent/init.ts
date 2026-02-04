import { Command } from "commander";
import { ConfigManager } from "../../core/config-manager.js";
import { getRafterDir } from "../../core/config-defaults.js";
import { BinaryManager } from "../../utils/binary-manager.js";
import { SkillManager } from "../../utils/skill-manager.js";
import fs from "fs";
import path from "path";
import os from "os";

export function createInitCommand(): Command {
  return new Command("init")
    .description("Initialize agent security system")
    .option("--risk-level <level>", "Set risk level (minimal, moderate, aggressive)", "moderate")
    .option("--skip-openclaw", "Skip OpenClaw skill installation")
    .option("--skip-gitleaks", "Skip Gitleaks binary download")
    .action(async (opts) => {
      console.log("\n🛡️  Rafter Agent Security Setup");
      console.log("━".repeat(40));
      console.log();

      const manager = new ConfigManager();

      // Detect environment
      const hasOpenClaw = fs.existsSync(path.join(os.homedir(), ".openclaw"));
      if (hasOpenClaw) {
        console.log("✓ Detected environment: OpenClaw");
      } else {
        console.log("ℹ️  OpenClaw not detected");
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

      console.log();
      console.log("✓ Agent security initialized!");
      console.log();
      console.log("Next steps:");
      if (hasOpenClaw && !opts.skipOpenclaw) {
        console.log("  - Restart OpenClaw to load skill");
      }
      console.log("  - Run: rafter agent scan . (test secret scanning)");
      console.log("  - Configure: rafter agent config show");
      console.log();
    });
}
