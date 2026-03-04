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

/** MCP server entry for rafter — shared across MCP-native clients */
const RAFTER_MCP_ENTRY = {
  command: "rafter",
  args: ["mcp", "serve"],
};

/**
 * Install MCP server config for Gemini CLI (~/.gemini/settings.json)
 */
function installGeminiMcp(): boolean {
  const homeDir = os.homedir();
  const geminiDir = path.join(homeDir, ".gemini");
  const settingsPath = path.join(geminiDir, "settings.json");

  if (!fs.existsSync(geminiDir)) {
    fs.mkdirSync(geminiDir, { recursive: true });
  }

  let settings: Record<string, any> = {};
  if (fs.existsSync(settingsPath)) {
    try {
      settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Gemini settings.json was unreadable, creating new one"));
    }
  }

  if (!settings.mcpServers) settings.mcpServers = {};
  settings.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };

  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${settingsPath}`));
  return true;
}

/**
 * Install MCP server config for Cursor (~/.cursor/mcp.json)
 */
function installCursorMcp(): boolean {
  const homeDir = os.homedir();
  const cursorDir = path.join(homeDir, ".cursor");
  const mcpPath = path.join(cursorDir, "mcp.json");

  if (!fs.existsSync(cursorDir)) {
    fs.mkdirSync(cursorDir, { recursive: true });
  }

  let config: Record<string, any> = {};
  if (fs.existsSync(mcpPath)) {
    try {
      config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Cursor mcp.json was unreadable, creating new one"));
    }
  }

  if (!config.mcpServers) config.mcpServers = {};
  config.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };

  fs.writeFileSync(mcpPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${mcpPath}`));
  return true;
}

/**
 * Install MCP server config for Windsurf (~/.codeium/windsurf/mcp_config.json)
 */
function installWindsurfMcp(): boolean {
  const homeDir = os.homedir();
  const windsurfDir = path.join(homeDir, ".codeium", "windsurf");
  const mcpPath = path.join(windsurfDir, "mcp_config.json");

  if (!fs.existsSync(windsurfDir)) {
    fs.mkdirSync(windsurfDir, { recursive: true });
  }

  let config: Record<string, any> = {};
  if (fs.existsSync(mcpPath)) {
    try {
      config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Windsurf mcp_config.json was unreadable, creating new one"));
    }
  }

  if (!config.mcpServers) config.mcpServers = {};
  config.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };

  fs.writeFileSync(mcpPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${mcpPath}`));
  return true;
}

/**
 * Install MCP server config for Continue.dev (~/.continue/config.json)
 */
function installContinueDevMcp(): boolean {
  const homeDir = os.homedir();
  const continueDir = path.join(homeDir, ".continue");
  const configPath = path.join(continueDir, "config.json");

  if (!fs.existsSync(continueDir)) {
    fs.mkdirSync(continueDir, { recursive: true });
  }

  let config: Record<string, any> = {};
  if (fs.existsSync(configPath)) {
    try {
      config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Continue.dev config.json was unreadable, creating new one"));
    }
  }

  if (!config.mcpServers) config.mcpServers = [];

  // Remove existing rafter entry if present (array format)
  if (Array.isArray(config.mcpServers)) {
    config.mcpServers = config.mcpServers.filter(
      (s: any) => s.name !== "rafter"
    );
    config.mcpServers.push({
      name: "rafter",
      command: RAFTER_MCP_ENTRY.command,
      args: RAFTER_MCP_ENTRY.args,
    });
  } else {
    // Object format (newer Continue.dev versions)
    config.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };
  }

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${configPath}`));
  return true;
}

/**
 * Install MCP config for Aider (~/.aider.conf.yml)
 * Aider uses YAML config with mcpServers list
 */
function installAiderMcp(): boolean {
  const homeDir = os.homedir();
  const configPath = path.join(homeDir, ".aider.conf.yml");

  // Aider's YAML config is simple — we append the MCP flag if not present
  let content = "";
  if (fs.existsSync(configPath)) {
    content = fs.readFileSync(configPath, "utf-8");
  }

  // Check if rafter MCP is already configured
  if (content.includes("rafter mcp serve")) {
    console.log(fmt.success("Rafter MCP already configured in Aider config"));
    return true;
  }

  // Append MCP server config
  const mcpLine = "\n# Rafter security MCP server\nmcp-server-command: rafter mcp serve\n";
  fs.writeFileSync(configPath, content + mcpLine, "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${configPath}`));
  return true;
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

function installCodexSkills(): void {
  const homeDir = os.homedir();
  const agentsSkillsDir = path.join(homeDir, ".agents", "skills");

  // Install Backend Skill
  const backendDir = path.join(agentsSkillsDir, "rafter");
  const backendSkillPath = path.join(backendDir, "SKILL.md");
  const backendTemplatePath = path.join(__dirname, "..", "..", "..", ".claude", "skills", "rafter", "SKILL.md");

  if (!fs.existsSync(backendDir)) {
    fs.mkdirSync(backendDir, { recursive: true });
  }

  if (fs.existsSync(backendTemplatePath)) {
    fs.copyFileSync(backendTemplatePath, backendSkillPath);
    console.log(fmt.success(`Installed Rafter Backend skill to ${backendSkillPath}`));
  } else {
    console.log(fmt.warning(`Backend skill template not found at ${backendTemplatePath}`));
  }

  // Install Agent Security Skill
  const agentDir = path.join(agentsSkillsDir, "rafter-agent-security");
  const agentSkillPath = path.join(agentDir, "SKILL.md");
  const agentTemplatePath = path.join(__dirname, "..", "..", "..", ".claude", "skills", "rafter-agent-security", "SKILL.md");

  if (!fs.existsSync(agentDir)) {
    fs.mkdirSync(agentDir, { recursive: true });
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
    .option("--skip-codex", "Skip Codex CLI skill installation")
    .option("--claude-code", "Force Claude Code skill installation")
    .option("--skip-gemini", "Skip Gemini CLI integration")
    .option("--skip-aider", "Skip Aider integration")
    .option("--skip-cursor", "Skip Cursor integration")
    .option("--skip-windsurf", "Skip Windsurf integration")
    .option("--skip-continue", "Skip Continue.dev integration")
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
      const hasCodex = fs.existsSync(path.join(os.homedir(), ".codex"));

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

      if (hasCodex) {
        console.log(fmt.success("Detected environment: Codex CLI"));
      } else {
        console.log(fmt.info("Codex CLI not detected"));
      }

      // Detect new AI engine environments
      const hasGemini = fs.existsSync(path.join(os.homedir(), ".gemini"));
      const hasCursor = fs.existsSync(path.join(os.homedir(), ".cursor"));
      const hasWindsurf = fs.existsSync(path.join(os.homedir(), ".codeium", "windsurf"));
      const hasContinueDev = fs.existsSync(path.join(os.homedir(), ".continue"));
      const hasAider = fs.existsSync(path.join(os.homedir(), ".aider.conf.yml"));

      if (hasGemini) console.log(fmt.success("Detected environment: Gemini CLI"));
      if (hasCursor) console.log(fmt.success("Detected environment: Cursor"));
      if (hasWindsurf) console.log(fmt.success("Detected environment: Windsurf"));
      if (hasContinueDev) console.log(fmt.success("Detected environment: Continue.dev"));
      if (hasAider) console.log(fmt.success("Detected environment: Aider"));

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
      let openclawOk = false;
      if (hasOpenClaw && !opts.skipOpenclaw) {
        const skillManager = new SkillManager();
        const result = await skillManager.installRafterSkillVerbose();
        openclawOk = result.ok;
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
      let claudeCodeOk = false;
      if (hasClaudeCode && !opts.skipClaudeCode) {
        try {
          await installClaudeCodeSkills();
          installClaudeCodeHooks();
          manager.set("agent.environments.claudeCode.enabled", true);
          claudeCodeOk = true;
        } catch (e) {
          console.error(fmt.error(`Failed to install Claude Code integration: ${e}`));
        }
      }

      // Install Codex CLI skills if applicable
      let codexOk = false;
      if (hasCodex && !opts.skipCodex) {
        try {
          installCodexSkills();
          manager.set("agent.environments.codex.enabled", true);
          codexOk = true;
        } catch (e) {
          console.error(fmt.error(`Failed to install Codex CLI integration: ${e}`));
        }
      }

      // Install Gemini CLI MCP if applicable
      let geminiOk = false;
      if (hasGemini && !opts.skipGemini) {
        try {
          geminiOk = installGeminiMcp();
          if (geminiOk) manager.set("agent.environments.gemini.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Gemini CLI integration: ${e}`));
        }
      }

      // Install Cursor MCP if applicable
      let cursorOk = false;
      if (hasCursor && !opts.skipCursor) {
        try {
          cursorOk = installCursorMcp();
          if (cursorOk) manager.set("agent.environments.cursor.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Cursor integration: ${e}`));
        }
      }

      // Install Windsurf MCP if applicable
      let windsurfOk = false;
      if (hasWindsurf && !opts.skipWindsurf) {
        try {
          windsurfOk = installWindsurfMcp();
          if (windsurfOk) manager.set("agent.environments.windsurf.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Windsurf integration: ${e}`));
        }
      }

      // Install Continue.dev MCP if applicable
      let continueOk = false;
      if (hasContinueDev && !opts.skipContinue) {
        try {
          continueOk = installContinueDevMcp();
          if (continueOk) manager.set("agent.environments.continueDev.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Continue.dev integration: ${e}`));
        }
      }

      // Install Aider MCP if applicable
      let aiderOk = false;
      if (hasAider && !opts.skipAider) {
        try {
          aiderOk = installAiderMcp();
          if (aiderOk) manager.set("agent.environments.aider.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Aider integration: ${e}`));
        }
      }

      console.log();
      console.log(fmt.success("Agent security initialized!"));
      console.log();
      console.log("Next steps:");
      if (openclawOk) {
        console.log("  - Restart OpenClaw to load skill");
      }
      if (claudeCodeOk) {
        console.log("  - Restart Claude Code to load skills");
      }
      if (codexOk) {
        console.log("  - Restart Codex CLI to load skills");
      }
      if (geminiOk) {
        console.log("  - Restart Gemini CLI to load MCP server");
      }
      if (cursorOk) {
        console.log("  - Restart Cursor to load MCP server");
      }
      if (windsurfOk) {
        console.log("  - Restart Windsurf to load MCP server");
      }
      if (continueOk) {
        console.log("  - Restart Continue.dev to load MCP server");
      }
      if (aiderOk) {
        console.log("  - Restart Aider to load MCP server");
      }
      console.log("  - Run: rafter scan local . (test secret scanning)");
      console.log("  - Configure: rafter agent config show");
      console.log();
    });
}
