import { Command } from "commander";
import fs from "fs";
import path from "path";
import os from "os";
import { execSync } from "child_process";
import { getRafterDir, getAuditLogPath, getBinDir } from "../../core/config-defaults.js";
import { AuditLogger } from "../../core/audit-logger.js";
import { ConfigManager } from "../../core/config-manager.js";

export function createStatusCommand(): Command {
  return new Command("status")
    .description("Show agent security status dashboard")
    .action(async () => {
      const rafterDir = getRafterDir();
      const auditPath = getAuditLogPath();
      const home = os.homedir();

      console.log("Rafter Agent Status");
      console.log("=".repeat(50));

      // --- Config ---
      const configPath = path.join(rafterDir, "config.json");
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

      // --- Gitleaks ---
      const localGitleaks = path.join(getBinDir(), "gitleaks");
      let gitleaksStatus = "not found — run: rafter agent init";
      try {
        const ver = execSync("gitleaks version", { timeout: 5000, encoding: "utf-8" }).trim();
        gitleaksStatus = `${ver} (PATH)`;
      } catch {
        if (fs.existsSync(localGitleaks)) {
          try {
            const ver = execSync(`"${localGitleaks}" version`, { timeout: 5000, encoding: "utf-8" }).trim();
            gitleaksStatus = `${ver} (local)`;
          } catch {
            gitleaksStatus = `${localGitleaks} (binary error)`;
          }
        }
      }
      console.log(`Gitleaks:     ${gitleaksStatus}`);

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
      console.log(`PreToolUse:   ${pretoolOk ? "installed" : "not installed — run: rafter agent init"}`);
      console.log(`PostToolUse:  ${posttoolOk ? "installed" : "not installed — run: rafter agent init"}`);

      // --- OpenClaw skill ---
      const skillPath = path.join(home, ".openclaw", "skills", "rafter-security.md");
      const openclawDir = path.join(home, ".openclaw");
      if (fs.existsSync(skillPath)) {
        console.log(`OpenClaw:     skill installed (${skillPath})`);
      } else if (fs.existsSync(openclawDir)) {
        console.log("OpenClaw:     detected but skill missing — run: rafter agent init");
      } else {
        console.log("OpenClaw:     not detected (optional)");
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
            console.log(`  ${ts}  ${e.eventType}  [${action}]`);
          }
        }
      } else {
        console.log("No events logged yet.");
      }

      console.log();
    });
}
