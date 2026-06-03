import { Command } from "commander";
import fs from "fs";
import path from "path";
import os from "os";
import { execSync } from "child_process";
import { fileURLToPath } from "url";
import { getRafterDir, getAuditLogPath, getBinDir } from "../../core/config-defaults.js";
import { AuditLogger } from "../../core/audit-logger.js";
import { ConfigManager } from "../../core/config-manager.js";
import { BinaryManager } from "../../utils/binary-manager.js";
import { SkillManager } from "../../utils/skill-manager.js";

interface AgentStatusJson {
  installed: boolean;
  version: string;
  agents_detected: string[];
  hooks_installed: string[];
  betterleaks_available: boolean;
  config_path: string;
  audit_log_path: string;
}

export function createStatusCommand(): Command {
  return new Command("status")
    .description("Show agent security status dashboard")
    .option("--json", "Output status as JSON")
    .action(async (opts: { json?: boolean }) => {
      const rafterDir = getRafterDir();
      const auditPath = getAuditLogPath();
      const home = os.homedir();
      const configPath = path.join(rafterDir, "config.json");

      if (opts.json) {
        console.log(JSON.stringify(buildStatusJson(home, configPath, auditPath), null, 2));
        return;
      }

      console.log("Rafter Agent Status");
      console.log("=".repeat(50));

      // --- Config ---
      if (fs.existsSync(configPath)) {
        try {
          const cfg = new ConfigManager().load();
          console.log(`\nConfig:       ${configPath}`);
          console.log(`Risk level:   ${cfg.agent?.riskLevel ?? "moderate"}`);
        } catch {
          console.log(`\nConfig:       ${configPath} (parse error)`);
        }
      } else {
        console.log(`\nConfig:       not found — run: rafter agent init`);
      }

      // --- Betterleaks ---
      const exeExt = process.platform === "win32" ? ".exe" : "";
      const localBetterleaks = path.join(getBinDir(), `betterleaks${exeExt}`);
      let betterleaksStatus = "not found — run: rafter agent init --with-betterleaks";
      try {
        const ver = execSync("betterleaks version", { timeout: 5000, encoding: "utf-8", stdio: ["pipe", "pipe", "ignore"] }).trim();
        betterleaksStatus = `${ver} (PATH)`;
      } catch {
        if (fs.existsSync(localBetterleaks)) {
          try {
            const ver = execSync(`"${localBetterleaks}" version`, { timeout: 5000, encoding: "utf-8", stdio: ["pipe", "pipe", "ignore"] }).trim();
            betterleaksStatus = `${ver} (local)`;
          } catch {
            betterleaksStatus = `${localBetterleaks} (binary error)`;
          }
        } else {
          // Legacy install — surface a hint instead of "not found"
          const legacy = new BinaryManager().findLegacyGitleaks();
          if (legacy) {
            betterleaksStatus = `not found — legacy gitleaks at ${legacy}; run: rafter agent update-betterleaks`;
          }
        }
      }
      console.log(`Betterleaks:  ${betterleaksStatus}`);

      // --- Claude Code hooks ---
      const settingsPath = path.join(home, ".claude", "settings.json");
      let pretoolOk = false;
      let posttoolOk = false;
      if (fs.existsSync(settingsPath)) {
        try {
          const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
          const hooks = settings.hooks ?? {};
          for (const entry of hooks.PreToolUse ?? []) {
            for (const h of entry.hooks ?? []) {
              if (String(h.command ?? "").includes("rafter hook pretool")) pretoolOk = true;
            }
          }
          for (const entry of hooks.PostToolUse ?? []) {
            for (const h of entry.hooks ?? []) {
              if (String(h.command ?? "").includes("rafter hook posttool")) posttoolOk = true;
            }
          }
        } catch {
          // unreadable settings
        }
      }
      console.log(`PreToolUse:   ${pretoolOk ? "installed" : "not installed — run: rafter agent init --with-claude-code"}`);
      console.log(`PostToolUse:  ${posttoolOk ? "installed" : "not installed — run: rafter agent init --with-claude-code"}`);

      // --- OpenClaw skill ---
      // rf-zgwj moved the skill to the canonical ClawHub workspace path
      // (~/.openclaw/workspace/skills/rafter-security/SKILL.md) and strips the
      // legacy flat file. Detect via SkillManager so this matches `agent verify`
      // and the installer — checking the legacy path here is a false negative.
      const skillManager = new SkillManager();
      if (skillManager.isRafterSkillInstalled()) {
        console.log(`OpenClaw:     skill installed (${skillManager.getRafterSkillPath()})`);
      } else if (skillManager.isOpenClawInstalled()) {
        if (skillManager.hasLegacyRafterSkill()) {
          console.log(`OpenClaw:     legacy skill at ${skillManager.getLegacyRafterSkillPath()} (not loaded) — run: rafter agent init --with-openclaw to migrate`);
        } else {
          console.log("OpenClaw:     detected but skill missing — run: rafter agent init --with-openclaw");
        }
      } else {
        console.log("OpenClaw:     not detected (optional)");
      }

      // --- Codex CLI skills ---
      const codexDir = path.join(home, ".codex");
      const codexSkillPath = path.join(home, ".agents", "skills", "rafter", "SKILL.md");
      if (fs.existsSync(codexSkillPath)) {
        console.log(`Codex CLI:    skills installed (${path.join(home, ".agents", "skills")})`);
      } else if (fs.existsSync(codexDir)) {
        console.log("Codex CLI:    detected but skills missing — run: rafter agent init --with-codex");
      } else {
        console.log("Codex CLI:    not detected (optional)");
      }

      // --- MCP-native AI engine integrations ---
      const mcpAgents: Array<{ name: string; flag: string; configDir: string; configFile: string; needle: string }> = [
        { name: "Gemini CLI", flag: "--with-gemini", configDir: path.join(home, ".gemini"), configFile: path.join(home, ".gemini", "settings.json"), needle: "rafter" },
        { name: "Cursor", flag: "--with-cursor", configDir: path.join(home, ".cursor"), configFile: path.join(home, ".cursor", "mcp.json"), needle: "rafter" },
        { name: "Windsurf", flag: "--with-windsurf", configDir: path.join(home, ".codeium", "windsurf"), configFile: path.join(home, ".codeium", "windsurf", "mcp_config.json"), needle: "rafter" },
        { name: "Continue.dev", flag: "--with-continue", configDir: path.join(home, ".continue"), configFile: path.join(home, ".continue", "config.json"), needle: "rafter" },
        { name: "Hermes", flag: "--with-hermes", configDir: path.join(home, ".hermes"), configFile: path.join(home, ".hermes", "config.yaml"), needle: "rafter" },
      ];

      for (const agent of mcpAgents) {
        const label = `${agent.name}:`.padEnd(14);
        if (fs.existsSync(agent.configFile)) {
          try {
            const content = fs.readFileSync(agent.configFile, "utf-8");
            if (content.includes(agent.needle)) {
              console.log(`${label}MCP installed (${agent.configFile})`);
            } else {
              console.log(`${label}detected but MCP missing — run: rafter agent init ${agent.flag}`);
            }
          } catch {
            console.log(`${label}config unreadable (${agent.configFile})`);
          }
        } else if (fs.existsSync(agent.configDir)) {
          console.log(`${label}detected but MCP missing — run: rafter agent init ${agent.flag}`);
        } else {
          console.log(`${label}not detected (optional)`);
        }
      }

      // --- Aider ---
      const aiderConfig = path.join(home, ".aider.conf.yml");
      if (fs.existsSync(aiderConfig)) {
        try {
          const content = fs.readFileSync(aiderConfig, "utf-8");
          if (content.includes("rafter mcp serve")) {
            console.log(`Aider:        MCP installed (${aiderConfig})`);
          } else {
            console.log("Aider:        detected but MCP missing — run: rafter agent init --with-aider");
          }
        } catch {
          console.log(`Aider:        config unreadable (${aiderConfig})`);
        }
      } else {
        console.log("Aider:        not detected (optional)");
      }

      // --- Audit log summary ---
      console.log(`\nAudit log:    ${auditPath}`);
      if (fs.existsSync(auditPath)) {
        const logger = new AuditLogger();
        const allEntries = logger.read();
        const total = allEntries.length;
        const secrets = allEntries.filter((e) => e.eventType === "secret_detected").length;
        const blocked = allEntries.filter(
          (e) => e.eventType === "command_intercepted" && e.resolution?.actionTaken === "blocked"
        ).length;
        console.log(
          `Total events: ${total}  |  Secrets detected: ${secrets}  |  Commands blocked: ${blocked}`
        );

        const recent = logger.read({ limit: 5 });
        if (recent.length > 0) {
          console.log("\nRecent events:");
          for (const e of [...recent].reverse()) {
            const ts = (e.timestamp ?? "").slice(0, 19).replace("T", " ");
            const action = e.resolution?.actionTaken ?? "";
            console.log(`  ${ts}  ${e.eventType ?? "unknown"}  [${action}]`);
          }
        }
      } else {
        console.log("No events logged yet.");
      }

      console.log();
    });
}

function buildStatusJson(home: string, configPath: string, auditPath: string): AgentStatusJson {
  return {
    installed: fs.existsSync(configPath),
    version: getPkgVersion(),
    agents_detected: detectAgents(home),
    hooks_installed: detectGitHooks(home),
    betterleaks_available: isBetterleaksAvailable(),
    config_path: formatHomePath(configPath, home),
    audit_log_path: formatHomePath(auditPath, home),
  };
}

function detectAgents(home: string): string[] {
  const candidates: Array<[string, string]> = [
    ["claude-code", path.join(home, ".claude")],
    ["openclaw", path.join(home, ".openclaw")],
    ["codex", path.join(home, ".codex")],
    ["gemini", path.join(home, ".gemini")],
    ["cursor", path.join(home, ".cursor")],
    ["windsurf", path.join(home, ".codeium", "windsurf")],
    ["continue", path.join(home, ".continue")],
    ["aider", path.join(home, ".aider.conf.yml")],
    ["hermes", path.join(home, ".hermes")],
  ];
  return candidates
    .filter(([, p]) => fs.existsSync(p))
    .map(([name]) => name);
}

function detectGitHooks(home: string): string[] {
  const hooks = new Set<string>();
  const specs: Array<[string, string]> = [
    ["pre-commit", "Rafter Security Pre-Commit Hook"],
    ["pre-push", "Rafter Security Pre-Push Hook"],
  ];

  for (const [hookName, marker] of specs) {
    const globalHook = path.join(home, ".rafter", "git-hooks", hookName);
    if (fileContains(globalHook, marker)) hooks.add(hookName);
  }

  try {
    const gitDir = execSync("git rev-parse --git-dir", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"],
      timeout: 5000,
    }).trim();
    const hooksDir = path.resolve(gitDir, "hooks");
    for (const [hookName, marker] of specs) {
      if (fileContains(path.join(hooksDir, hookName), marker)) hooks.add(hookName);
    }
  } catch {
    // Not in a git repository, or git unavailable.
  }

  return [...hooks].sort();
}

function isBetterleaksAvailable(): boolean {
  const exeExt = process.platform === "win32" ? ".exe" : "";
  const localBetterleaks = path.join(getBinDir(), `betterleaks${exeExt}`);
  try {
    execSync("betterleaks version", {
      timeout: 5000,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"],
    });
    return true;
  } catch {
    if (fs.existsSync(localBetterleaks)) return true;
    return Boolean(new BinaryManager().findLegacyGitleaks());
  }
}

function fileContains(filePath: string, needle: string): boolean {
  try {
    return fs.readFileSync(filePath, "utf-8").includes(needle);
  } catch {
    return false;
  }
}

function formatHomePath(filePath: string, home: string): string {
  const relative = path.relative(home, filePath);
  if (relative && !relative.startsWith("..") && !path.isAbsolute(relative)) {
    return path.join("~", relative).replace(/\\/g, "/");
  }
  return filePath;
}

function getPkgVersion(): string {
  try {
    const __filename = fileURLToPath(import.meta.url);
    let dir = path.dirname(__filename);
    for (let i = 0; i < 6; i++) {
      const candidate = path.join(dir, "package.json");
      if (fs.existsSync(candidate)) {
        const pkg = JSON.parse(fs.readFileSync(candidate, "utf-8"));
        if (pkg.version) return pkg.version;
      }
      dir = path.dirname(dir);
    }
  } catch {
    // fall through
  }
  return "unknown";
}
