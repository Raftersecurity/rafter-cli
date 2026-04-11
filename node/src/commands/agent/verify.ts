import { Command } from "commander";
import { ConfigManager } from "../../core/config-manager.js";
import { BinaryManager } from "../../utils/binary-manager.js";
import { SkillManager } from "../../utils/skill-manager.js";
import fs from "fs";
import path from "path";
import os from "os";
import { fmt } from "../../utils/formatter.js";

interface CheckResult {
  name: string;
  passed: boolean;
  detail: string;
  optional?: boolean;  // optional checks warn but don't fail exit code
}

async function checkGitleaks(): Promise<CheckResult> {
  const binaryManager = new BinaryManager();
  const name = "Gitleaks";

  // Check PATH first (e.g. Homebrew), then fall back to ~/.rafter/bin
  const pathBinary = binaryManager.findGitleaksOnPath();
  const hasBinary = pathBinary !== null || binaryManager.isGitleaksInstalled();

  if (!hasBinary) {
    return { name, passed: false, detail: `Not found on PATH or at ${binaryManager.getGitleaksPath()}` };
  }

  const binaryPath = pathBinary ?? binaryManager.getGitleaksPath();
  const { ok, stdout, stderr } = await binaryManager.verifyGitleaksVerbose(binaryPath);
  if (!ok) {
    const diag = await binaryManager.collectBinaryDiagnostics(binaryPath);
    return { name, passed: false, detail: `Binary found at ${binaryPath} but failed to execute\n${stdout ? `  stdout: ${stdout}\n` : ""}${stderr ? `  stderr: ${stderr}\n` : ""}${diag}` };
  }

  return { name, passed: true, detail: `${stdout} (${binaryPath})` };
}

function checkConfig(): CheckResult {
  const name = "Config";
  const configPath = path.join(os.homedir(), ".rafter", "config.json");

  if (!fs.existsSync(configPath)) {
    return { name, passed: false, detail: `Not found: ${configPath}` };
  }

  try {
    const content = fs.readFileSync(configPath, "utf-8");
    JSON.parse(content);
    return { name, passed: true, detail: configPath };
  } catch (e) {
    return { name, passed: false, detail: `Invalid JSON: ${configPath} — ${e}` };
  }
}

function checkClaudeCode(): CheckResult {
  const name = "Claude Code";
  const homeDir = os.homedir();
  // optional: warn if absent but don't fail exit code
  const claudeDir = path.join(homeDir, ".claude");

  if (!fs.existsSync(claudeDir)) {
    return { name, passed: false, optional: true, detail: `Not detected — run 'rafter agent init --with-claude-code' to enable` };
  }

  const settingsPath = path.join(claudeDir, "settings.json");
  if (!fs.existsSync(settingsPath)) {
    return { name, passed: false, optional: true, detail: `Settings file not found: ${settingsPath}` };
  }

  try {
    const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    const hooks = settings?.hooks?.PreToolUse || [];
    const hasRafterHook = hooks.some((entry: any) =>
      (entry.hooks || []).some((h: any) => h.command === "rafter hook pretool")
    );
    if (!hasRafterHook) {
      return { name, passed: false, optional: true, detail: "Rafter hooks not installed — run 'rafter agent init --with-claude-code'" };
    }
    return { name, passed: true, detail: "Hooks installed" };
  } catch (e) {
    return { name, passed: false, optional: true, detail: `Cannot read settings: ${e}` };
  }
}

function checkOpenClaw(): CheckResult {
  const name = "OpenClaw";
  const skillManager = new SkillManager();

  if (!skillManager.isOpenClawInstalled()) {
    return { name, passed: false, optional: true, detail: `Not detected — run 'rafter agent init --with-openclaw' to enable` };
  }

  if (!skillManager.isRafterSkillInstalled()) {
    return { name, passed: false, optional: true, detail: `Rafter skill not installed — run 'rafter agent init --with-openclaw'` };
  }

  const version = skillManager.getInstalledVersion();
  return { name, passed: true, detail: `Rafter skill installed${version ? ` (v${version})` : ""}` };
}

function checkCodex(): CheckResult {
  const name = "Codex CLI";
  const homeDir = os.homedir();
  const codexDir = path.join(homeDir, ".codex");

  if (!fs.existsSync(codexDir)) {
    return { name, passed: false, optional: true, detail: `Not detected — run 'rafter agent init --with-codex' to enable` };
  }

  const skillPath = path.join(homeDir, ".agents", "skills", "rafter", "SKILL.md");
  if (!fs.existsSync(skillPath)) {
    return { name, passed: false, optional: true, detail: `Rafter skills not installed — run 'rafter agent init --with-codex'` };
  }

  return { name, passed: true, detail: `Skills installed (${path.join(homeDir, ".agents", "skills")})` };
}

function checkGemini(): CheckResult {
  const name = "Gemini CLI";
  const homeDir = os.homedir();
  const geminiDir = path.join(homeDir, ".gemini");

  if (!fs.existsSync(geminiDir)) {
    return { name, passed: false, optional: true, detail: `Not detected — run 'rafter agent init --with-gemini' to enable` };
  }

  const settingsPath = path.join(geminiDir, "settings.json");
  if (!fs.existsSync(settingsPath)) {
    return { name, passed: false, optional: true, detail: `Settings file not found: ${settingsPath} — run 'rafter agent init --with-gemini'` };
  }

  try {
    const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    const hasRafterMcp = settings?.mcpServers?.rafter != null;
    if (!hasRafterMcp) {
      return { name, passed: false, optional: true, detail: "Rafter MCP server not configured — run 'rafter agent init --with-gemini'" };
    }
    return { name, passed: true, detail: "MCP server configured" };
  } catch (e) {
    return { name, passed: false, optional: true, detail: `Cannot read settings: ${e}` };
  }
}

function checkCursor(): CheckResult {
  const name = "Cursor";
  const homeDir = os.homedir();
  const cursorDir = path.join(homeDir, ".cursor");

  if (!fs.existsSync(cursorDir)) {
    return { name, passed: false, optional: true, detail: `Not detected — run 'rafter agent init --with-cursor' to enable` };
  }

  const mcpPath = path.join(cursorDir, "mcp.json");
  if (!fs.existsSync(mcpPath)) {
    return { name, passed: false, optional: true, detail: `MCP config not found: ${mcpPath} — run 'rafter agent init --with-cursor'` };
  }

  try {
    const config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
    const hasRafterMcp = config?.mcpServers?.rafter != null;
    if (!hasRafterMcp) {
      return { name, passed: false, optional: true, detail: "Rafter MCP server not configured — run 'rafter agent init --with-cursor'" };
    }
    return { name, passed: true, detail: "MCP server configured" };
  } catch (e) {
    return { name, passed: false, optional: true, detail: `Cannot read config: ${e}` };
  }
}

function checkWindsurf(): CheckResult {
  const name = "Windsurf";
  const homeDir = os.homedir();
  const windsurfDir = path.join(homeDir, ".codeium", "windsurf");

  if (!fs.existsSync(windsurfDir)) {
    return { name, passed: false, optional: true, detail: `Not detected — run 'rafter agent init --with-windsurf' to enable` };
  }

  const mcpPath = path.join(windsurfDir, "mcp_config.json");
  if (!fs.existsSync(mcpPath)) {
    return { name, passed: false, optional: true, detail: `MCP config not found: ${mcpPath} — run 'rafter agent init --with-windsurf'` };
  }

  try {
    const config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
    const hasRafterMcp = config?.mcpServers?.rafter != null;
    if (!hasRafterMcp) {
      return { name, passed: false, optional: true, detail: "Rafter MCP server not configured — run 'rafter agent init --with-windsurf'" };
    }
    return { name, passed: true, detail: "MCP server configured" };
  } catch (e) {
    return { name, passed: false, optional: true, detail: `Cannot read config: ${e}` };
  }
}

export function createVerifyCommand(): Command {
  return new Command("verify")
    .description("Check agent security integration status")
    .action(async () => {
      console.log(fmt.header("Rafter Agent Verify"));
      console.log(fmt.divider());
      console.log();

      const results: CheckResult[] = [
        checkConfig(),
        await checkGitleaks(),
        checkClaudeCode(),
        checkOpenClaw(),
        checkCodex(),
        checkGemini(),
        checkCursor(),
        checkWindsurf(),
      ];

      for (const r of results) {
        if (r.passed) {
          console.log(fmt.success(`${r.name}: ${r.detail}`));
        } else if (r.optional) {
          console.log(fmt.warning(`${r.name}: ${r.detail}`));
        } else {
          console.log(fmt.error(`${r.name}: FAIL — ${r.detail}`));
        }
      }

      console.log();
      const hardFailed = results.filter((r) => !r.passed && !r.optional);
      const warned = results.filter((r) => !r.passed && r.optional);
      const passed = results.filter((r) => r.passed);

      if (hardFailed.length === 0) {
        const warnNote = warned.length > 0 ? ` (${warned.length} optional check${warned.length > 1 ? "s" : ""} not configured)` : "";
        console.log(fmt.success(`${passed.length}/${results.length} core checks passed${warnNote}`));
      } else {
        console.log(fmt.error(`${passed.length}/${results.length} checks passed — ${hardFailed.length} failed`));
      }
      console.log();

      if (hardFailed.length > 0) {
        process.exit(1);
      }
    });
}
