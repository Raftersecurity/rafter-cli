import { Command } from "commander";
import { ConfigManager } from "../../core/config-manager.js";
import { BinaryManager } from "../../utils/binary-manager.js";
import { SkillManager } from "../../utils/skill-manager.js";
import { spawnSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import yaml from "js-yaml";
import { fmt } from "../../utils/formatter.js";

interface CheckResult {
  name: string;
  passed: boolean;
  detail: string;
  optional?: boolean;  // optional checks warn but don't fail exit code
}

async function checkBetterleaks(): Promise<CheckResult> {
  const binaryManager = new BinaryManager();
  const name = "Betterleaks";

  // Check PATH first (e.g. Homebrew), then fall back to ~/.rafter/bin
  const pathBinary = binaryManager.findBetterleaksOnPath();
  const hasBinary = pathBinary !== null || binaryManager.isBetterleaksInstalled();

  if (!hasBinary) {
    // Soft-degrade if a legacy gitleaks install is still present — the user
    // upgraded rafter but hasn't rerun `agent init --with-betterleaks` yet.
    const legacy = binaryManager.findLegacyGitleaks();
    if (legacy) {
      return {
        name,
        passed: false,
        optional: true,
        detail: `Not installed; found legacy gitleaks at ${legacy}. Run: rafter agent update-betterleaks`,
      };
    }
    return { name, passed: false, detail: `Not found on PATH or at ${binaryManager.getBetterleaksPath()}` };
  }

  const binaryPath = pathBinary ?? binaryManager.getBetterleaksPath();
  const { ok, stdout, stderr } = await binaryManager.verifyBetterleaksVerbose(binaryPath);
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
    // Substring match — Python install writes an absolute path
    // (/home/foo/bin/rafter hook pretool), Node writes the bare command.
    const hooks = settings?.hooks?.PreToolUse || [];
    const hasRafterHook = hooks.some((entry: any) =>
      (entry.hooks || []).some((h: any) => String(h?.command ?? "").includes("rafter hook pretool"))
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
    // rf-zgwj: surface the legacy install path so users on rafter ≤ 0.7.7
    // know they need to re-run to migrate.
    if (skillManager.hasLegacyRafterSkill()) {
      return {
        name,
        passed: false,
        optional: true,
        detail: `Legacy skill at ${skillManager.getLegacyRafterSkillPath()} (not loaded by OpenClaw) — re-run 'rafter agent init --with-openclaw' to migrate to ${skillManager.getRafterSkillPath()}`,
      };
    }
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

function checkContinueDev(): CheckResult {
  const name = "Continue.dev";
  const homeDir = os.homedir();
  const continueDir = path.join(homeDir, ".continue");

  if (!fs.existsSync(continueDir)) {
    return { name, passed: false, optional: true, detail: `Not detected — run 'rafter agent init --with-continue' to enable` };
  }

  const configPath = path.join(continueDir, "config.json");
  if (!fs.existsSync(configPath)) {
    return { name, passed: false, optional: true, detail: `MCP config not found: ${configPath} — run 'rafter agent init --with-continue'` };
  }

  try {
    const cfg = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    const servers = cfg?.mcpServers;
    let hasRafter = false;
    if (Array.isArray(servers)) hasRafter = servers.some((s: any) => s?.name === "rafter");
    else if (servers && typeof servers === "object") hasRafter = !!servers.rafter;
    if (!hasRafter) {
      return { name, passed: false, optional: true, detail: "Rafter MCP server not configured — run 'rafter agent init --with-continue'" };
    }
    return { name, passed: true, detail: "MCP server configured" };
  } catch (e) {
    return { name, passed: false, optional: true, detail: `Cannot read config: ${e}` };
  }
}

function checkAider(): CheckResult {
  // Aider has no platform dir of its own; presence of ~/.aider.conf.yml or
  // a project-local .aider.conf.yml is the install signal. We check the
  // user-scope file plus the cwd file (rf-du2o ships at --local scope too).
  const name = "Aider";
  const home = os.homedir();
  const userConf = path.join(home, ".aider.conf.yml");
  const projectConf = path.join(process.cwd(), ".aider.conf.yml");
  const userRafterMd = path.join(home, "RAFTER.md");
  const projectRafterMd = path.join(process.cwd(), "RAFTER.md");

  // Pick whichever scope has a config file; prefer cwd.
  const conf = fs.existsSync(projectConf) ? projectConf
    : fs.existsSync(userConf) ? userConf
    : null;
  if (!conf) {
    return { name, passed: false, optional: true, detail: `Not detected — run 'rafter agent init --with-aider' to enable` };
  }

  let raw = "";
  try {
    raw = fs.readFileSync(conf, "utf-8");
  } catch (e) {
    return { name, passed: false, optional: true, detail: `Cannot read config: ${e}` };
  }

  let parsed: Record<string, any> = {};
  try {
    const loaded = yaml.load(raw);
    if (loaded && typeof loaded === "object" && !Array.isArray(loaded)) {
      parsed = loaded as Record<string, any>;
    }
  } catch {
    // Unparseable — fall back to substring check
    const hasReadEntry = /\bRAFTER\.md\b/.test(raw);
    if (!hasReadEntry) {
      return { name, passed: false, optional: true, detail: "RAFTER.md not in read: list — run 'rafter agent init --with-aider'" };
    }
    return { name, passed: true, detail: "RAFTER.md in read: list (config not strict-YAML)" };
  }

  const reads: string[] = Array.isArray(parsed.read) ? parsed.read.map(String)
    : typeof parsed.read === "string" ? [parsed.read] : [];
  if (!reads.includes("RAFTER.md")) {
    return { name, passed: false, optional: true, detail: `RAFTER.md not in read: list (${conf}) — run 'rafter agent init --with-aider'` };
  }

  const rafterMd = conf === projectConf ? projectRafterMd : userRafterMd;
  if (!fs.existsSync(rafterMd)) {
    return { name, passed: false, optional: true, detail: `RAFTER.md missing at ${rafterMd} — run 'rafter agent init --with-aider'` };
  }

  return { name, passed: true, detail: `RAFTER.md + read: entry in ${conf}` };
}

function checkHermes(): CheckResult {
  // Hermes uses ~/.hermes/config.yaml with a snake_case `mcp_servers:` block
  // (MCP-only v0 — no hook surface confirmed yet; sable-gyw).
  const name = "Hermes";
  const homeDir = os.homedir();
  const hermesDir = path.join(homeDir, ".hermes");

  if (!fs.existsSync(hermesDir)) {
    return { name, passed: false, optional: true, detail: `Not detected — run 'rafter agent init --with-hermes' to enable` };
  }

  const configPath = path.join(hermesDir, "config.yaml");
  if (!fs.existsSync(configPath)) {
    return { name, passed: false, optional: true, detail: `Config not found: ${configPath} — run 'rafter agent init --with-hermes'` };
  }

  try {
    const loaded = yaml.load(fs.readFileSync(configPath, "utf-8"));
    const servers = (loaded && typeof loaded === "object" && !Array.isArray(loaded))
      ? (loaded as Record<string, any>).mcp_servers
      : undefined;
    const hasRafterMcp = servers && typeof servers === "object" && servers.rafter != null;
    if (!hasRafterMcp) {
      return { name, passed: false, optional: true, detail: "Rafter MCP server not configured — run 'rafter agent init --with-hermes'" };
    }
    return { name, passed: true, detail: "MCP server configured" };
  } catch (e) {
    return { name, passed: false, optional: true, detail: `Cannot read config: ${e}` };
  }
}

/**
 * Probe the Claude Code hook integration end-to-end (rf-65zg).
 *
 * Synthesizes a stdin payload that mimics Claude's PreToolUse hook contract
 * with a known-dangerous test command, invokes `rafter hook pretool` (the
 * command Claude would invoke), and asserts ~/.rafter/audit.jsonl received
 * a `command_intercepted` entry for the probe command.
 *
 * Catches the rf-luk-style "wrote file but the command never fires the
 * audit log" failure without needing to drive Claude Code itself.
 */
function probeClaudeCode(): CheckResult {
  const name = "Claude Code (probe)";
  const home = os.homedir();
  const settingsPath = path.join(home, ".claude", "settings.json");
  if (!fs.existsSync(settingsPath)) {
    return { name, passed: false, optional: true, detail: "Not installed — skip" };
  }

  // Use a unique sentinel command per probe run so we don't collide with
  // real-world audit entries.
  const sentinel = `rafter-probe-${process.pid}-${Date.now()}`;
  const probeCommand = `rm -rf /tmp/${sentinel}`;
  const stdinPayload = JSON.stringify({
    session_id: sentinel,
    transcript_path: "",
    cwd: process.cwd(),
    permission_mode: "default",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: probeCommand },
  });

  const auditPath = path.join(home, ".rafter", "audit.jsonl");
  const sizeBefore = fs.existsSync(auditPath) ? fs.statSync(auditPath).size : 0;

  // Resolve the rafter binary the same way Claude Code would: `rafter hook
  // pretool` on PATH. Fall back to argv[0] if PATH lookup fails.
  const result = spawnSync(process.execPath, [process.argv[1], "hook", "pretool"], {
    input: stdinPayload,
    encoding: "utf-8",
    timeout: 10_000,
  });

  if (result.error) {
    return { name, passed: false, detail: `rafter hook pretool failed to spawn: ${result.error.message}` };
  }

  if (!fs.existsSync(auditPath)) {
    return { name, passed: false, detail: `Hook ran but ${auditPath} was not created (exit=${result.status})` };
  }

  const newContent = fs.readFileSync(auditPath, "utf-8").slice(sizeBefore);
  const lines = newContent.split("\n").filter((l) => l.trim().length > 0);
  const hit = lines.some((line) => {
    try {
      const entry = JSON.parse(line);
      const cmd = String(entry?.action?.command ?? entry?.command ?? "");
      return entry?.eventType === "command_intercepted" && cmd.includes(sentinel);
    } catch {
      return false;
    }
  });

  if (!hit) {
    return {
      name,
      passed: false,
      detail: `Probe ran (exit=${result.status}) but no command_intercepted entry for sentinel "${sentinel}" landed in ${auditPath}`,
    };
  }

  return { name, passed: true, detail: `Probe fired → command_intercepted recorded in ${auditPath}` };
}

export function createVerifyCommand(): Command {
  return new Command("verify")
    .description("Check agent security integration status")
    .option("--json", "Emit results as JSON (one object per check + summary)")
    .option(
      "--probe",
      "Runtime probe: invoke rafter hook commands with synthetic platform-format payloads and assert ~/.rafter/audit.jsonl recorded the interception. Catches the 'wrote file but never fires' failure mode (rf-65zg).",
    )
    .action(async (opts: { json?: boolean; probe?: boolean }) => {
      const json = !!opts.json;

      if (!json) {
        console.log(fmt.header("Rafter Agent Verify"));
        console.log(fmt.divider());
        console.log();
      }

      const results: CheckResult[] = [
        checkConfig(),
        await checkBetterleaks(),
        checkClaudeCode(),
        checkOpenClaw(),
        checkCodex(),
        checkGemini(),
        checkCursor(),
        checkWindsurf(),
        checkContinueDev(),
        checkAider(),
        checkHermes(),
      ];

      if (opts.probe) {
        // Only Claude Code has a probe today (rf-65zg). Codex/Cursor/Gemini
        // hook payloads can be added in follow-ups.
        results.push(probeClaudeCode());
      }

      const hardFailed = results.filter((r) => !r.passed && !r.optional);
      const warned = results.filter((r) => !r.passed && r.optional);
      const passed = results.filter((r) => r.passed);

      if (json) {
        const payload = {
          checks: results.map((r) => ({
            name: r.name,
            status: r.passed ? "pass" : r.optional ? "warn" : "fail",
            detail: r.detail,
          })),
          summary: {
            passed: passed.length,
            warned: warned.length,
            failed: hardFailed.length,
            total: results.length,
            probe: !!opts.probe,
          },
        };
        process.stdout.write(JSON.stringify(payload) + "\n");
      } else {
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
        if (hardFailed.length === 0) {
          const warnNote = warned.length > 0 ? ` (${warned.length} optional check${warned.length > 1 ? "s" : ""} not configured)` : "";
          console.log(fmt.success(`${passed.length}/${results.length} core checks passed${warnNote}`));
        } else {
          console.log(fmt.error(`${passed.length}/${results.length} checks passed — ${hardFailed.length} failed`));
        }
        console.log();
      }

      if (hardFailed.length > 0) {
        process.exit(1);
      }
    });
}
