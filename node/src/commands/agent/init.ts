import { Command } from "commander";
import { ConfigManager } from "../../core/config-manager.js";
import { getRafterDir } from "../../core/config-defaults.js";
import { BinaryManager } from "../../utils/binary-manager.js";
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
          installOpenClawSkill();
          console.log("✓ Installed OpenClaw skill to ~/.openclaw/skills/rafter-security.md");
          manager.set("agent.environments.openclaw.enabled", true);
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

function installOpenClawSkill(): void {
  const skillPath = path.join(os.homedir(), ".openclaw", "skills", "rafter-security.md");
  const skillDir = path.dirname(skillPath);

  // Ensure skills directory exists
  if (!fs.existsSync(skillDir)) {
    fs.mkdirSync(skillDir, { recursive: true });
  }

  const skillContent = `---
openclaw:
  skillKey: rafter-security
  primaryEnv: RAFTER_API_KEY
  emoji: 🛡️
  always: false
  requires:
    bins: [rafter]
---

# Rafter Security

Security layer for autonomous agents. Scans code, intercepts dangerous commands, and prevents vulnerabilities.

## Overview

Rafter provides real-time security checks for agent operations:
- **Secret Detection**: Scan files before commits
- **Command Validation**: Block dangerous shell commands
- **Output Filtering**: Redact secrets in responses
- **Audit Logging**: Track all security events

## Commands

### /rafter-scan

Scan files for secrets before committing.

\`\`\`bash
rafter agent scan <path>
\`\`\`

**When to use:**
- Before git commits
- When handling user-provided code
- When reading sensitive files

### /rafter-bash

Execute shell command with security validation (future).

\`\`\`bash
rafter agent exec <command>
\`\`\`

**Features:**
- Blocks destructive commands (rm -rf /, fork bombs)
- Requires approval for dangerous operations
- Logs all command attempts

### /rafter-audit

View recent security events.

\`\`\`bash
rafter agent audit --last 10
\`\`\`

## Security Levels

- **Minimal**: Basic guidance only
- **Moderate**: Standard protections (recommended)
- **Aggressive**: Maximum security, requires approval for most operations

Configure with: \`rafter agent config set agent.riskLevel moderate\`

## Best Practices

1. **Always scan before commits**: Run \`rafter agent scan\` before \`git commit\`
2. **Review audit logs**: Check \`rafter agent audit\` after suspicious activity
3. **Update patterns**: Keep secret patterns current with \`rafter agent update\` (future)
4. **Report false positives**: Help improve detection accuracy

## Configuration

View config: \`rafter agent config show\`
Set values: \`rafter agent config set <key> <value>\`

Key settings:
- \`agent.riskLevel\`: minimal | moderate | aggressive
- \`agent.commandPolicy.mode\`: allow-all | approve-dangerous | deny-list
- \`agent.outputFiltering.redactSecrets\`: true | false

---

**Note**: Rafter is a security aid, not a replacement for secure coding practices.
`;

  fs.writeFileSync(skillPath, skillContent, "utf-8");
}
