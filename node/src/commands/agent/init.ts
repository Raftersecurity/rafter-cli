import { Command } from "commander";
import { ConfigManager } from "../../core/config-manager.js";
import { getRafterDir } from "../../core/config-defaults.js";
import { BinaryManager } from "../../utils/binary-manager.js";
import { SkillManager } from "../../utils/skill-manager.js";
import fs from "fs";
import path from "path";
import os from "os";
import { execSync } from "child_process";
import { fileURLToPath } from "url";
import { createRequire } from "module";
import { createInterface } from "readline";
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
  const backendTemplatePath = path.join(__dirname, "..", "..", "..", "resources", "skills", "rafter", "SKILL.md");

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
  const agentTemplatePath = path.join(__dirname, "..", "..", "..", "resources", "skills", "rafter-agent-security", "SKILL.md");

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
  const backendTemplatePath = path.join(__dirname, "..", "..", "..", "resources", "skills", "rafter", "SKILL.md");

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
  const agentTemplatePath = path.join(__dirname, "..", "..", "..", "resources", "skills", "rafter-agent-security", "SKILL.md");

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

async function askYesNo(question: string, defaultYes = true): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const suffix = defaultYes ? "[Y/n]" : "[y/N]";
  return new Promise((resolve) => {
    rl.question(`  ${question} ${suffix} `, (answer) => {
      rl.close();
      const trimmed = answer.trim().toLowerCase();
      if (trimmed === "") resolve(defaultYes);
      else resolve(trimmed === "y" || trimmed === "yes");
    });
  });
}

export function createInitCommand(): Command {
  return new Command("init")
    .description("Initialize agent security system")
    .option("--risk-level <level>", "Set risk level (minimal, moderate, aggressive)", "moderate")
    .option("--with-openclaw", "Install OpenClaw integration")
    .option("--with-claude-code", "Install Claude Code integration")
    .option("--with-codex", "Install Codex CLI integration")
    .option("--with-gemini", "Install Gemini CLI integration")
    .option("--with-aider", "Install Aider integration")
    .option("--with-cursor", "Install Cursor integration")
    .option("--with-windsurf", "Install Windsurf integration")
    .option("--with-continue", "Install Continue.dev integration")
    .option("--with-gitleaks", "Download and install Gitleaks binary")
    .option("--all", "Install all detected integrations and download Gitleaks")
    .option("-i, --interactive", "Guided setup — prompts for each detected integration")
    .option("--update", "Re-download gitleaks and reinstall integrations without resetting config")
    .action(async (opts) => {
      console.log(fmt.header("Rafter Agent Security Setup"));
      console.log(fmt.divider());
      console.log();

      const manager = new ConfigManager();

      // Detect environments
      const hasOpenClaw = fs.existsSync(path.join(os.homedir(), ".openclaw"));
      const hasClaudeCode = fs.existsSync(path.join(os.homedir(), ".claude"));
      const hasCodex = fs.existsSync(path.join(os.homedir(), ".codex"));
      const hasGemini = fs.existsSync(path.join(os.homedir(), ".gemini"));
      const hasCursor = fs.existsSync(path.join(os.homedir(), ".cursor"));
      const hasWindsurf = fs.existsSync(path.join(os.homedir(), ".codeium", "windsurf"));
      const hasContinueDev = fs.existsSync(path.join(os.homedir(), ".continue"));
      const hasAider = fs.existsSync(path.join(os.homedir(), ".aider.conf.yml"));

      // Resolve opt-in flags (--all enables all detected, --interactive prompts)
      let wantOpenClaw = opts.withOpenclaw || opts.all;
      let wantClaudeCode = opts.withClaudeCode || opts.all;
      let wantCodex = opts.withCodex || opts.all;
      let wantGemini = opts.withGemini || opts.all;
      let wantCursor = opts.withCursor || opts.all;
      let wantWindsurf = opts.withWindsurf || opts.all;
      let wantContinue = opts.withContinue || opts.all;
      let wantAider = opts.withAider || opts.all;
      let wantGitleaks = opts.withGitleaks || opts.all;

      // Interactive mode: prompt for each detected integration
      if (opts.interactive && !opts.all) {
        console.log();
        console.log(fmt.info("Select integrations to install:"));
        console.log();
        if (hasClaudeCode && !wantClaudeCode) wantClaudeCode = await askYesNo("Install Claude Code hooks + skills?");
        if (hasCodex && !wantCodex) wantCodex = await askYesNo("Install Codex CLI skills?");
        if (hasOpenClaw && !wantOpenClaw) wantOpenClaw = await askYesNo("Install OpenClaw skill?");
        if (hasGemini && !wantGemini) wantGemini = await askYesNo("Install Gemini CLI MCP server?");
        if (hasCursor && !wantCursor) wantCursor = await askYesNo("Install Cursor MCP server?");
        if (hasWindsurf && !wantWindsurf) wantWindsurf = await askYesNo("Install Windsurf MCP server?");
        if (hasContinueDev && !wantContinue) wantContinue = await askYesNo("Install Continue.dev MCP server?");
        if (hasAider && !wantAider) wantAider = await askYesNo("Install Aider MCP server?");
        if (!wantGitleaks) wantGitleaks = await askYesNo("Download Gitleaks binary (enhanced scanning)?");
        console.log();
      }

      // Show detected environments with opt-in hints
      const detected: string[] = [];
      if (hasOpenClaw) detected.push("OpenClaw");
      if (hasClaudeCode) detected.push("Claude Code");
      if (hasCodex) detected.push("Codex CLI");
      if (hasGemini) detected.push("Gemini CLI");
      if (hasCursor) detected.push("Cursor");
      if (hasWindsurf) detected.push("Windsurf");
      if (hasContinueDev) detected.push("Continue.dev");
      if (hasAider) detected.push("Aider");

      if (detected.length > 0) {
        console.log(fmt.info(`Detected environments: ${detected.join(", ")}`));
      } else {
        console.log(fmt.info("No agent environments detected"));
      }

      // Warn about requested but undetected environments
      if (wantOpenClaw && !hasOpenClaw) console.log(fmt.warning("OpenClaw requested but not detected (~/.openclaw not found)"));
      if (wantClaudeCode && !hasClaudeCode) console.log(fmt.warning("Claude Code requested but not detected (~/.claude not found)"));
      if (wantCodex && !hasCodex) console.log(fmt.warning("Codex CLI requested but not detected (~/.codex not found)"));
      if (wantGemini && !hasGemini) console.log(fmt.warning("Gemini CLI requested but not detected (~/.gemini not found)"));
      if (wantCursor && !hasCursor) console.log(fmt.warning("Cursor requested but not detected (~/.cursor not found)"));
      if (wantWindsurf && !hasWindsurf) console.log(fmt.warning("Windsurf requested but not detected (~/.codeium/windsurf not found)"));
      if (wantContinue && !hasContinueDev) console.log(fmt.warning("Continue.dev requested but not detected (~/.continue not found)"));
      if (wantAider && !hasAider) console.log(fmt.warning("Aider requested but not detected (~/.aider.conf.yml not found)"));

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

      // Check / download Gitleaks binary (opt-in via --with-gitleaks or --all)
      if (wantGitleaks) {
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

      // Install OpenClaw skill if opted in
      let openclawOk = false;
      if (hasOpenClaw && wantOpenClaw) {
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

      // Install Claude Code skills + hooks if opted in
      let claudeCodeOk = false;
      if (hasClaudeCode && wantClaudeCode) {
        try {
          await installClaudeCodeSkills();
          installClaudeCodeHooks();
          manager.set("agent.environments.claudeCode.enabled", true);
          claudeCodeOk = true;
        } catch (e) {
          console.error(fmt.error(`Failed to install Claude Code integration: ${e}`));
        }
      }

      // Install Codex CLI skills if opted in
      let codexOk = false;
      if (hasCodex && wantCodex) {
        try {
          installCodexSkills();
          manager.set("agent.environments.codex.enabled", true);
          codexOk = true;
        } catch (e) {
          console.error(fmt.error(`Failed to install Codex CLI integration: ${e}`));
        }
      }

      // Install Gemini CLI MCP if opted in
      let geminiOk = false;
      if (hasGemini && wantGemini) {
        try {
          geminiOk = installGeminiMcp();
          if (geminiOk) manager.set("agent.environments.gemini.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Gemini CLI integration: ${e}`));
        }
      }

      // Install Cursor MCP if opted in
      let cursorOk = false;
      if (hasCursor && wantCursor) {
        try {
          cursorOk = installCursorMcp();
          if (cursorOk) manager.set("agent.environments.cursor.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Cursor integration: ${e}`));
        }
      }

      // Install Windsurf MCP if opted in
      let windsurfOk = false;
      if (hasWindsurf && wantWindsurf) {
        try {
          windsurfOk = installWindsurfMcp();
          if (windsurfOk) manager.set("agent.environments.windsurf.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Windsurf integration: ${e}`));
        }
      }

      // Install Continue.dev MCP if opted in
      let continueOk = false;
      if (hasContinueDev && wantContinue) {
        try {
          continueOk = installContinueDevMcp();
          if (continueOk) manager.set("agent.environments.continueDev.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Continue.dev integration: ${e}`));
        }
      }

      // Install Aider MCP if opted in
      let aiderOk = false;
      if (hasAider && wantAider) {
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

      const anyIntegration = openclawOk || claudeCodeOk || codexOk || geminiOk || cursorOk || windsurfOk || continueOk || aiderOk;

      if (anyIntegration) {
        console.log("Next steps:");
        if (openclawOk) console.log("  - Restart OpenClaw to load skill");
        if (claudeCodeOk) console.log("  - Restart Claude Code to load skills");
        if (codexOk) console.log("  - Restart Codex CLI to load skills");
        if (geminiOk) console.log("  - Restart Gemini CLI to load MCP server");
        if (cursorOk) console.log("  - Restart Cursor to load MCP server");
        if (windsurfOk) console.log("  - Restart Windsurf to load MCP server");
        if (continueOk) console.log("  - Restart Continue.dev to load MCP server");
        if (aiderOk) console.log("  - Restart Aider to load MCP server");
      } else if (detected.length > 0) {
        console.log("No integrations were installed. To install, re-run with opt-in flags:");
        console.log("  rafter agent init --all                  # Install all detected");
        if (hasClaudeCode) console.log("  rafter agent init --with-claude-code     # Claude Code only");
        if (hasOpenClaw) console.log("  rafter agent init --with-openclaw        # OpenClaw only");
        if (hasCodex) console.log("  rafter agent init --with-codex           # Codex CLI only");
        if (hasGemini) console.log("  rafter agent init --with-gemini          # Gemini CLI only");
        if (hasCursor) console.log("  rafter agent init --with-cursor          # Cursor only");
        if (hasWindsurf) console.log("  rafter agent init --with-windsurf        # Windsurf only");
        if (hasContinueDev) console.log("  rafter agent init --with-continue        # Continue.dev only");
        if (hasAider) console.log("  rafter agent init --with-aider           # Aider only");
      } else {
        console.log("No agent environments detected. Install an agent tool and re-run with --with-<tool>.");
      }
      console.log();
      console.log("  - Run: rafter scan local . (test secret scanning)");
      console.log("  - Configure: rafter agent config show");
      console.log();

      // Warn if a different rafter version shadows this one on PATH
      try {
        const _require = createRequire(import.meta.url);
        const { version: thisVersion } = _require("../../../package.json");
        const pathVersion = execSync("rafter --version", {
          encoding: "utf-8",
          timeout: 5000,
          stdio: ["pipe", "pipe", "ignore"],
        }).trim();
        if (pathVersion && pathVersion !== thisVersion && !pathVersion.includes(thisVersion)) {
          console.log(fmt.warning(`PATH version mismatch: 'rafter --version' reports ${pathVersion}, but this install is ${thisVersion}.`));
          console.log(fmt.info("Another rafter binary may be shadowing this one. Check: which rafter"));
          console.log();
        }
      } catch {
        // Ignore — rafter may not be on PATH yet
      }
    });
}
