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
import { injectInstructionFile } from "./instruction-block.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Skills installed by `rafter agent init` for Claude Code / Codex.
 *
 * Sourced from `resources/skills/<name>/SKILL.md` in the shipped package.
 * Keep this list in sync with Python's installer and the skills that actually
 * ship in both resources/skills/ trees.
 */
const AGENT_SKILLS: { name: string; description: string }[] = [
  { name: "rafter", description: "Rafter Remote" },
  { name: "rafter-secure-design", description: "Rafter Secure Design" },
  { name: "rafter-code-review", description: "Rafter Code Review" },
];

/**
 * Install instruction files for platforms that support them, at either user
 * or project scope.
 *
 * Path layout:
 *   Claude Code — user: ~/.claude/CLAUDE.md       project: <cwd>/.claude/CLAUDE.md
 *   Codex CLI  — user: ~/.codex/AGENTS.md        project: <cwd>/AGENTS.md
 *   Gemini CLI — user: ~/.gemini/GEMINI.md       project: <cwd>/GEMINI.md
 *   Cursor     — user: ~/.cursor/rules/…mdc       project: <cwd>/.cursor/rules/…mdc
 *
 * Codex (AGENTS.md) and Gemini (GEMINI.md) each have the same filename at
 * user and project scope — only the location differs — which is why scope
 * is passed in explicitly.
 *
 * Windsurf, Continue.dev, and Aider are project-only and handled by
 * `rafter agent init-project`.
 */
function installGlobalInstructions(
  platforms: {
    claudeCode?: boolean;
    codex?: boolean;
    gemini?: boolean;
    cursor?: boolean;
  },
  root: string,
  scope: "user" | "project",
): void {
  // Claude Code — <root>/.claude/CLAUDE.md
  if (platforms.claudeCode) {
    try {
      const filePath = path.join(root, ".claude", "CLAUDE.md");
      injectInstructionFile(filePath);
      console.log(fmt.success(`Installed Rafter instructions to ${filePath}`));
    } catch (e) {
      console.log(fmt.warning(`Failed to write Claude Code instructions: ${e}`));
    }
  }

  // Codex — ~/.codex/AGENTS.md (user) or <cwd>/AGENTS.md (project)
  if (platforms.codex) {
    try {
      const filePath = scope === "user"
        ? path.join(root, ".codex", "AGENTS.md")
        : path.join(root, "AGENTS.md");
      injectInstructionFile(filePath);
      console.log(fmt.success(`Installed Rafter instructions to ${filePath}`));
    } catch (e) {
      console.log(fmt.warning(`Failed to write Codex instructions: ${e}`));
    }
  }

  // Gemini — ~/.gemini/GEMINI.md (user) or <cwd>/GEMINI.md (project)
  if (platforms.gemini) {
    try {
      const filePath = scope === "user"
        ? path.join(root, ".gemini", "GEMINI.md")
        : path.join(root, "GEMINI.md");
      injectInstructionFile(filePath);
      console.log(fmt.success(`Installed Rafter instructions to ${filePath}`));
    } catch (e) {
      console.log(fmt.warning(`Failed to write Gemini instructions: ${e}`));
    }
  }

  // Cursor — <root>/.cursor/rules/rafter-security.mdc
  if (platforms.cursor) {
    try {
      const filePath = path.join(root, ".cursor", "rules", "rafter-security.mdc");
      injectInstructionFile(filePath);
      console.log(fmt.success(`Installed Rafter instructions to ${filePath}`));
    } catch (e) {
      console.log(fmt.warning(`Failed to write Cursor instructions: ${e}`));
    }
  }
}

function installClaudeCodeHooks(root: string): void {
  const settingsPath = path.join(root, ".claude", "settings.json");
  const claudeDir = path.join(root, ".claude");

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
  // Strip legacy SessionStart entry left over from <=0.7.4 installs.
  if (Array.isArray(settings.hooks.SessionStart)) {
    settings.hooks.SessionStart = settings.hooks.SessionStart.filter(
      (entry: any) => {
        const hooks = entry.hooks || [];
        return !hooks.some((h: any) => h.command === "rafter hook session-start");
      }
    );
    if (settings.hooks.SessionStart.length === 0) delete settings.hooks.SessionStart;
  }

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

function installCodexHooks(root: string): void {
  const codexDir = path.join(root, ".codex");

  if (!fs.existsSync(codexDir)) {
    fs.mkdirSync(codexDir, { recursive: true });
  }

  const hooksPath = path.join(codexDir, "hooks.json");

  let config: Record<string, any> = {};
  if (fs.existsSync(hooksPath)) {
    try {
      config = JSON.parse(fs.readFileSync(hooksPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Codex hooks.json was unreadable, creating new one"));
    }
  }

  if (!config.hooks) config.hooks = {};
  if (!config.hooks.PreToolUse) config.hooks.PreToolUse = [];
  if (!config.hooks.PostToolUse) config.hooks.PostToolUse = [];

  // Codex uses the same hookSpecificOutput protocol as Claude Code (format=claude)
  const preHook = { type: "command", command: "rafter hook pretool" };
  const postHook = { type: "command", command: "rafter hook posttool" };

  // Remove existing rafter hooks
  config.hooks.PreToolUse = config.hooks.PreToolUse.filter(
    (entry: any) => !(entry.hooks || []).some((h: any) => h.command?.startsWith("rafter hook pretool"))
  );
  config.hooks.PostToolUse = config.hooks.PostToolUse.filter(
    (entry: any) => !(entry.hooks || []).some((h: any) => h.command?.startsWith("rafter hook posttool"))
  );

  config.hooks.PreToolUse.push(
    { matcher: "Bash", hooks: [preHook] },
  );
  config.hooks.PostToolUse.push(
    { matcher: ".*", hooks: [postHook] },
  );

  fs.writeFileSync(hooksPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed hooks to ${hooksPath}`));
}

function installCursorHooks(root: string): void {
  const cursorDir = path.join(root, ".cursor");

  if (!fs.existsSync(cursorDir)) {
    fs.mkdirSync(cursorDir, { recursive: true });
  }

  const hooksPath = path.join(cursorDir, "hooks.json");

  let config: Record<string, any> = {};
  if (fs.existsSync(hooksPath)) {
    try {
      config = JSON.parse(fs.readFileSync(hooksPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Cursor hooks.json was unreadable, creating new one"));
    }
  }

  if (!config.version) config.version = 1;
  if (!config.hooks) config.hooks = {};
  if (!config.hooks.beforeShellExecution) config.hooks.beforeShellExecution = [];

  // Remove existing rafter hooks
  config.hooks.beforeShellExecution = config.hooks.beforeShellExecution.filter(
    (entry: any) => !entry.command?.includes("rafter hook pretool")
  );

  config.hooks.beforeShellExecution.push({
    command: "rafter hook pretool --format cursor",
    type: "command",
    timeout: 5000,
  });

  fs.writeFileSync(hooksPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed hooks to ${hooksPath}`));
}

function installGeminiHooks(root: string): void {
  const geminiDir = path.join(root, ".gemini");

  if (!fs.existsSync(geminiDir)) {
    fs.mkdirSync(geminiDir, { recursive: true });
  }

  const settingsPath = path.join(geminiDir, "settings.json");

  let settings: Record<string, any> = {};
  if (fs.existsSync(settingsPath)) {
    try {
      settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Gemini settings.json was unreadable, creating new one"));
    }
  }

  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.BeforeTool) settings.hooks.BeforeTool = [];
  if (!settings.hooks.AfterTool) settings.hooks.AfterTool = [];

  // Remove existing rafter hooks
  settings.hooks.BeforeTool = settings.hooks.BeforeTool.filter(
    (entry: any) => !(entry.hooks || []).some((h: any) => h.command?.includes("rafter hook pretool"))
  );
  settings.hooks.AfterTool = settings.hooks.AfterTool.filter(
    (entry: any) => !(entry.hooks || []).some((h: any) => h.command?.includes("rafter hook posttool"))
  );

  settings.hooks.BeforeTool.push({
    matcher: "shell|write_file",
    hooks: [{ type: "command", command: "rafter hook pretool --format gemini", timeout: 5000 }],
  });
  settings.hooks.AfterTool.push({
    matcher: ".*",
    hooks: [{ type: "command", command: "rafter hook posttool --format gemini", timeout: 5000 }],
  });

  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), "utf-8");
  console.log(fmt.success(`Installed hooks to ${settingsPath}`));
}

function installWindsurfHooks(root: string): void {
  const windsurfDir = path.join(root, ".windsurf");

  if (!fs.existsSync(windsurfDir)) {
    fs.mkdirSync(windsurfDir, { recursive: true });
  }

  const hooksPath = path.join(windsurfDir, "hooks.json");

  let config: Record<string, any> = {};
  if (fs.existsSync(hooksPath)) {
    try {
      config = JSON.parse(fs.readFileSync(hooksPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Windsurf hooks.json was unreadable, creating new one"));
    }
  }

  if (!config.hooks) config.hooks = {};
  if (!config.hooks.pre_run_command) config.hooks.pre_run_command = [];
  if (!config.hooks.pre_write_code) config.hooks.pre_write_code = [];

  // Remove existing rafter hooks
  config.hooks.pre_run_command = config.hooks.pre_run_command.filter(
    (entry: any) => !entry.command?.includes("rafter hook pretool")
  );
  config.hooks.pre_write_code = config.hooks.pre_write_code.filter(
    (entry: any) => !entry.command?.includes("rafter hook pretool")
  );

  config.hooks.pre_run_command.push({
    command: "rafter hook pretool --format windsurf",
    show_output: true,
  });
  config.hooks.pre_write_code.push({
    command: "rafter hook pretool --format windsurf",
    show_output: true,
  });

  fs.writeFileSync(hooksPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed hooks to ${hooksPath}`));
}

function installContinueDevHooks(root: string): void {
  const continueDir = path.join(root, ".continue");

  if (!fs.existsSync(continueDir)) {
    fs.mkdirSync(continueDir, { recursive: true });
  }

  const settingsPath = path.join(continueDir, "settings.json");

  let settings: Record<string, any> = {};
  if (fs.existsSync(settingsPath)) {
    try {
      settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Continue.dev settings.json was unreadable, creating new one"));
    }
  }

  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];
  if (!settings.hooks.PostToolUse) settings.hooks.PostToolUse = [];

  // Continue.dev uses the same protocol as Claude Code
  const preHook = { type: "command", command: "rafter hook pretool" };
  const postHook = { type: "command", command: "rafter hook posttool" };

  settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter(
    (entry: any) => !(entry.hooks || []).some((h: any) => h.command?.startsWith("rafter hook pretool"))
  );
  settings.hooks.PostToolUse = settings.hooks.PostToolUse.filter(
    (entry: any) => !(entry.hooks || []).some((h: any) => h.command?.startsWith("rafter hook posttool"))
  );

  settings.hooks.PreToolUse.push(
    { matcher: "Bash", hooks: [preHook] },
    { matcher: "Write|Edit", hooks: [preHook] },
  );
  settings.hooks.PostToolUse.push(
    { matcher: ".*", hooks: [postHook] },
  );

  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), "utf-8");
  console.log(fmt.success(`Installed hooks to ${settingsPath}`));
}

/** MCP server entry for rafter — shared across MCP-native clients */
const RAFTER_MCP_ENTRY = {
  command: "rafter",
  args: ["mcp", "serve"],
};

/**
 * Install MCP server config for Claude Code (<root>/.mcp.json).
 * Project-scope MCP config that Claude Code auto-loads on startup.
 */
function installClaudeCodeMcp(root: string): boolean {
  const mcpPath = path.join(root, ".mcp.json");

  let config: Record<string, any> = {};
  if (fs.existsSync(mcpPath)) {
    try {
      config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing .mcp.json was unreadable, creating new one"));
    }
  }

  if (!config.mcpServers) config.mcpServers = {};
  config.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };

  fs.writeFileSync(mcpPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${mcpPath}`));
  return true;
}

/**
 * Install MCP server config for Gemini CLI (~/.gemini/settings.json)
 */
function installGeminiMcp(root: string): boolean {
  const geminiDir = path.join(root, ".gemini");
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
function installCursorMcp(root: string): boolean {
  const cursorDir = path.join(root, ".cursor");
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
function installWindsurfMcp(root: string): boolean {
  const windsurfDir = path.join(root, ".codeium", "windsurf");
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
function installContinueDevMcp(root: string): boolean {
  const continueDir = path.join(root, ".continue");
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
function installAiderMcp(root: string): boolean {
  const configPath = path.join(root, ".aider.conf.yml");

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

function installSkillsTo(skillsDir: string): void {
  if (!fs.existsSync(skillsDir)) {
    fs.mkdirSync(skillsDir, { recursive: true });
  }
  for (const skill of AGENT_SKILLS) {
    const destDir = path.join(skillsDir, skill.name);
    const destPath = path.join(destDir, "SKILL.md");
    const srcPath = path.join(
      __dirname, "..", "..", "..", "resources", "skills", skill.name, "SKILL.md",
    );
    if (!fs.existsSync(destDir)) {
      fs.mkdirSync(destDir, { recursive: true });
    }
    if (fs.existsSync(srcPath)) {
      fs.copyFileSync(srcPath, destPath);
      console.log(fmt.success(`Installed ${skill.description} skill to ${destPath}`));
    } else {
      console.log(fmt.warning(`${skill.description} skill template not found at ${srcPath}`));
    }
  }
}

async function installClaudeCodeSkills(root: string): Promise<void> {
  installSkillsTo(path.join(root, ".claude", "skills"));
}

/**
 * Sub-agents shipped by `rafter agent init --with-claude-code`.
 *
 * These land in <root>/.claude/agents/<name>.md and become first-class
 * delegation targets (Agent(subagent_type='<name>')) in the calling Claude
 * Code session — distinct from skills, which only surface in the activation
 * prompt. Source files live in `resources/agents/<name>.md`.
 *
 * Keep this list in sync with the Python installer.
 */
const CLAUDE_CODE_SUBAGENTS: { name: string; description: string }[] = [
  { name: "rafter", description: "Rafter Security" },
];

function installClaudeCodeSubAgents(root: string): void {
  const agentsDir = path.join(root, ".claude", "agents");
  if (!fs.existsSync(agentsDir)) {
    fs.mkdirSync(agentsDir, { recursive: true });
  }
  for (const sub of CLAUDE_CODE_SUBAGENTS) {
    const destPath = path.join(agentsDir, `${sub.name}.md`);
    const srcPath = path.join(
      __dirname, "..", "..", "..", "resources", "agents", `${sub.name}.md`,
    );
    if (fs.existsSync(srcPath)) {
      fs.copyFileSync(srcPath, destPath);
      console.log(fmt.success(`Installed ${sub.description} sub-agent to ${destPath}`));
    } else {
      console.log(fmt.warning(`${sub.description} sub-agent template not found at ${srcPath}`));
    }
  }
}

function installCodexSkills(root: string): void {
  installSkillsTo(path.join(root, ".agents", "skills"));
}

function installGeminiSkills(root: string): void {
  installSkillsTo(path.join(root, ".agents", "skills"));
}

/**
 * Register installed skills with Gemini CLI via `gemini skills link <abs-path>`.
 *
 * Requires gemini CLI >= 0.35 (the version that added `gemini skills`).
 * Missing CLI, missing subcommand, and per-skill registration failures are
 * non-fatal: we warn and continue so the on-disk install still succeeds.
 */
function registerGeminiSkills(skillsDir: string): void {
  // Probe for the `gemini` binary. Absence is expected on CI / fresh machines.
  try {
    execSync("gemini --version", { stdio: ["ignore", "pipe", "ignore"], timeout: 5000 });
  } catch {
    console.log(fmt.warning(
      "gemini CLI not found on PATH — skipping skill registration. " +
      "Skills are installed to disk; re-run after installing gemini ≥ 0.35.",
    ));
    return;
  }

  // Probe `gemini skills` subcommand (added in 0.35).
  try {
    execSync("gemini skills --help", { stdio: ["ignore", "pipe", "ignore"], timeout: 5000 });
  } catch {
    console.log(fmt.warning(
      "gemini CLI does not support `skills` subcommand (needs ≥ 0.35). " +
      "Skipping registration — skills are still installed to disk.",
    ));
    return;
  }

  for (const skill of AGENT_SKILLS) {
    const absPath = path.resolve(skillsDir, skill.name);
    if (!fs.existsSync(absPath)) continue;
    try {
      execSync(`gemini skills link ${JSON.stringify(absPath)}`, {
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 10000,
      });
      console.log(fmt.success(`Registered ${skill.name} with Gemini CLI`));
    } catch (e: any) {
      const msg = (e?.stderr?.toString?.() || e?.message || "").trim();
      console.log(fmt.warning(
        `Failed to register ${skill.name} with Gemini CLI: ${msg.split("\n")[0] || "unknown error"}`,
      ));
    }
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
    .option(
      "--local",
      "Install integration configs project-locally (in CWD) instead of user-globally. " +
      "Supported for Claude Code, Codex, Gemini, Cursor. Other platforms are skipped in local mode.",
    )
    .action(async (opts) => {
      console.log(fmt.header("Rafter Agent Security Setup"));
      console.log(fmt.divider());
      console.log();

      const manager = new ConfigManager();
      const root = opts.local ? process.cwd() : os.homedir();
      const scope: "project" | "user" = opts.local ? "project" : "user";
      if (opts.local) {
        console.log(fmt.info(`Project-local install — writing configs under ${root}`));
      }

      // Platforms supported in --local scope: Claude Code, Codex, Gemini, Cursor.
      // Windsurf, Continue.dev, Aider are skipped in --local because their
      // project-local config story is not established in their CLIs today.

      // Detect environments. In local scope, don't probe user-global paths —
      // the user must opt in explicitly via --with-<platform>.
      const hasOpenClaw = scope === "user" && fs.existsSync(path.join(os.homedir(), ".openclaw"));
      const hasClaudeCode = scope === "user" && fs.existsSync(path.join(os.homedir(), ".claude"));
      const hasCodex = scope === "user" && fs.existsSync(path.join(os.homedir(), ".codex"));
      const hasGemini = scope === "user" && fs.existsSync(path.join(os.homedir(), ".gemini"));
      const hasCursor = scope === "user" && fs.existsSync(path.join(os.homedir(), ".cursor"));
      const hasWindsurf = scope === "user" && fs.existsSync(path.join(os.homedir(), ".codeium", "windsurf"));
      const hasContinueDev = scope === "user" && fs.existsSync(path.join(os.homedir(), ".continue"));
      const hasAider = scope === "user" && fs.existsSync(path.join(os.homedir(), ".aider.conf.yml"));

      // Resolve opt-in flags (--all enables all detected, --interactive prompts).
      // In --local scope, --all is restricted to platforms that have a project-local
      // config story (claudeCode, codex, gemini, cursor). The rest require user scope.
      let wantOpenClaw = opts.withOpenclaw || (opts.all && !opts.local);
      let wantClaudeCode = opts.withClaudeCode || opts.all;
      let wantCodex = opts.withCodex || opts.all;
      let wantGemini = opts.withGemini || opts.all;
      let wantCursor = opts.withCursor || opts.all;
      let wantWindsurf = opts.withWindsurf || (opts.all && !opts.local);
      let wantContinue = opts.withContinue || (opts.all && !opts.local);
      let wantAider = opts.withAider || (opts.all && !opts.local);
      let wantGitleaks = opts.withGitleaks || (opts.all && !opts.local);

      // Interactive mode: prompt for each detected integration
      if (opts.interactive && !opts.all) {
        console.log();
        console.log(fmt.info("Select integrations to install:"));
        console.log();
        if (hasClaudeCode && !wantClaudeCode) wantClaudeCode = await askYesNo("Install Claude Code hooks + skills?");
        if (hasCodex && !wantCodex) wantCodex = await askYesNo("Install Codex CLI skills + hooks?");
        if (hasOpenClaw && !wantOpenClaw) wantOpenClaw = await askYesNo("Install OpenClaw skill?");
        if (hasGemini && !wantGemini) wantGemini = await askYesNo("Install Gemini CLI MCP + hooks?");
        if (hasCursor && !wantCursor) wantCursor = await askYesNo("Install Cursor MCP + hooks?");
        if (hasWindsurf && !wantWindsurf) wantWindsurf = await askYesNo("Install Windsurf MCP + hooks?");
        if (hasContinueDev && !wantContinue) wantContinue = await askYesNo("Install Continue.dev MCP + hooks?");
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

      // Warn about requested but undetected environments (user scope only —
      // in --local scope we create the directories in CWD as needed).
      if (scope === "user") {
        if (wantOpenClaw && !hasOpenClaw) console.log(fmt.warning("OpenClaw requested but not detected (~/.openclaw not found)"));
        if (wantClaudeCode && !hasClaudeCode) console.log(fmt.warning("Claude Code requested but not detected (~/.claude not found)"));
        if (wantCodex && !hasCodex) console.log(fmt.warning("Codex CLI requested but not detected (~/.codex not found)"));
        if (wantGemini && !hasGemini) console.log(fmt.warning("Gemini CLI requested but not detected (~/.gemini not found)"));
        if (wantCursor && !hasCursor) console.log(fmt.warning("Cursor requested but not detected (~/.cursor not found)"));
        if (wantWindsurf && !hasWindsurf) console.log(fmt.warning("Windsurf requested but not detected (~/.codeium/windsurf not found)"));
        if (wantContinue && !hasContinueDev) console.log(fmt.warning("Continue.dev requested but not detected (~/.continue not found)"));
        if (wantAider && !hasAider) console.log(fmt.warning("Aider requested but not detected (~/.aider.conf.yml not found)"));
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

      // Helper: warn that a platform is not supported in --local mode.
      const localUnsupported = (label: string): void => {
        console.log(fmt.warning(
          `${label} is not supported in --local mode yet. Skipping. ` +
          `Re-run without --local to install for this platform user-globally.`,
        ));
      };

      // Install Claude Code skills + hooks if opted in
      // When --with-claude-code is explicitly passed (or --local), install even if <root>/.claude doesn't exist yet
      let claudeCodeOk = false;
      if ((hasClaudeCode || opts.withClaudeCode || (opts.local && wantClaudeCode)) && wantClaudeCode) {
        try {
          await installClaudeCodeSkills(root);
          installClaudeCodeSubAgents(root);
          installClaudeCodeHooks(root);
          if (scope === "project") {
            const components = (manager.get("agent.components") ?? {}) as Record<string, any>;
            if (components["claude-code.mcp"]?.enabled === false) {
              console.log(fmt.info("Skipped .mcp.json (claude-code.mcp disabled; re-enable with `rafter agent enable claude-code.mcp`)"));
            } else {
              installClaudeCodeMcp(root);
              components["claude-code.mcp"] = { enabled: true, updatedAt: new Date().toISOString() };
              manager.set("agent.components", components);
            }
          }
          if (scope === "user") manager.set("agent.environments.claudeCode.enabled", true);
          claudeCodeOk = true;
        } catch (e) {
          console.error(fmt.error(`Failed to install Claude Code integration: ${e}`));
        }
      }

      // Install Codex CLI skills + hooks if opted in
      let codexOk = false;
      if ((hasCodex || (opts.local && wantCodex)) && wantCodex) {
        try {
          installCodexSkills(root);
          installCodexHooks(root);
          if (scope === "user") manager.set("agent.environments.codex.enabled", true);
          codexOk = true;
        } catch (e) {
          console.error(fmt.error(`Failed to install Codex CLI integration: ${e}`));
        }
      }

      // Install Gemini CLI MCP + skills + hooks if opted in
      let geminiOk = false;
      if ((hasGemini || (opts.local && wantGemini)) && wantGemini) {
        try {
          geminiOk = installGeminiMcp(root);
          installGeminiSkills(root);
          registerGeminiSkills(path.join(root, ".agents", "skills"));
          installGeminiHooks(root);
          if (geminiOk && scope === "user") manager.set("agent.environments.gemini.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Gemini CLI integration: ${e}`));
        }
      }

      // Install Cursor MCP + hooks if opted in
      let cursorOk = false;
      if ((hasCursor || (opts.local && wantCursor)) && wantCursor) {
        try {
          cursorOk = installCursorMcp(root);
          installCursorHooks(root);
          if (cursorOk && scope === "user") manager.set("agent.environments.cursor.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Cursor integration: ${e}`));
        }
      }

      // Install Windsurf MCP + hooks if opted in
      let windsurfOk = false;
      if (hasWindsurf && wantWindsurf) {
        try {
          windsurfOk = installWindsurfMcp(root);
          installWindsurfHooks(root);
          if (windsurfOk) manager.set("agent.environments.windsurf.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Windsurf integration: ${e}`));
        }
      } else if (opts.local && wantWindsurf) {
        localUnsupported("Windsurf");
      }

      // Install Continue.dev MCP + hooks if opted in
      let continueOk = false;
      if (hasContinueDev && wantContinue) {
        try {
          continueOk = installContinueDevMcp(root);
          installContinueDevHooks(root);
          if (continueOk) manager.set("agent.environments.continueDev.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Continue.dev integration: ${e}`));
        }
      } else if (opts.local && wantContinue) {
        localUnsupported("Continue.dev");
      }

      // Install Aider MCP if opted in
      let aiderOk = false;
      if (hasAider && wantAider) {
        try {
          aiderOk = installAiderMcp(root);
          if (aiderOk) manager.set("agent.environments.aider.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Aider integration: ${e}`));
        }
      } else if (opts.local && wantAider) {
        localUnsupported("Aider");
      }

      // Install global instruction files for platforms that support them
      installGlobalInstructions({
        claudeCode: claudeCodeOk,
        codex: codexOk,
        gemini: geminiOk,
        cursor: cursorOk,
      }, root, scope);

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
      } else if (scope === "project") {
        console.log("No integrations were installed. In --local mode, pass one or more opt-in flags:");
        console.log("  rafter agent init --local --with-claude-code");
        console.log("  rafter agent init --local --with-codex");
        console.log("  rafter agent init --local --with-gemini");
        console.log("  rafter agent init --local --with-cursor");
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
      console.log("  - Run: rafter secrets . (test secret scanning)");
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
