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
}

async function checkGitleaks(): Promise<CheckResult> {
  const binaryManager = new BinaryManager();
  const name = "Gitleaks";

  if (!binaryManager.isGitleaksInstalled()) {
    return { name, passed: false, detail: `Binary not found at ${binaryManager.getGitleaksPath()}` };
  }

  const { ok, stdout, stderr } = await binaryManager.verifyGitleaksVerbose();
  if (!ok) {
    const diag = await binaryManager.collectBinaryDiagnostics();
    return { name, passed: false, detail: `Binary exists but failed to execute\n${stdout ? `  stdout: ${stdout}\n` : ""}${stderr ? `  stderr: ${stderr}\n` : ""}${diag}` };
  }

  return { name, passed: true, detail: stdout };
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
  const claudeDir = path.join(homeDir, ".claude");

  if (!fs.existsSync(claudeDir)) {
    return { name, passed: false, detail: `Directory not found: ${claudeDir}` };
  }

  const settingsPath = path.join(claudeDir, "settings.json");
  if (!fs.existsSync(settingsPath)) {
    return { name, passed: false, detail: `Settings file not found: ${settingsPath}` };
  }

  try {
    const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    const hooks = settings?.hooks?.PreToolUse || [];
    const hasRafterHook = hooks.some((entry: any) =>
      (entry.hooks || []).some((h: any) => h.command === "rafter hook pretool")
    );
    if (!hasRafterHook) {
      return { name, passed: false, detail: "Rafter hooks not found in settings.json — run 'rafter agent init'" };
    }
    return { name, passed: true, detail: "Hooks installed" };
  } catch (e) {
    return { name, passed: false, detail: `Cannot read settings: ${e}` };
  }
}

function checkOpenClaw(): CheckResult {
  const name = "OpenClaw";
  const skillManager = new SkillManager();

  if (!skillManager.isOpenClawInstalled()) {
    return { name, passed: false, detail: `Not installed (${skillManager.getOpenClawSkillsDir()} not found)` };
  }

  if (!skillManager.isRafterSkillInstalled()) {
    return { name, passed: false, detail: `Rafter skill not found at ${skillManager.getRafterSkillPath()}` };
  }

  const version = skillManager.getInstalledVersion();
  return { name, passed: true, detail: `Rafter skill installed${version ? ` (v${version})` : ""}` };
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
      ];

      for (const r of results) {
        if (r.passed) {
          console.log(fmt.success(`${r.name}: ${r.detail}`));
        } else {
          console.log(fmt.error(`${r.name}: FAIL`));
          console.log(`   ${r.detail}`);
        }
      }

      console.log();
      const allPassed = results.every((r) => r.passed);
      const passCount = results.filter((r) => r.passed).length;

      if (allPassed) {
        console.log(fmt.success(`All ${results.length} checks passed`));
      } else {
        console.log(fmt.warning(`${passCount}/${results.length} checks passed`));
      }
      console.log();

      if (!allPassed) {
        process.exit(1);
      }
    });
}
