import { RafterConfig } from "./config-schema.js";
import os from "os";
import path from "path";

export const CONFIG_VERSION = "1.0.0";

export function getDefaultConfig(): RafterConfig {
  return {
    version: CONFIG_VERSION,
    initialized: new Date().toISOString(),

    backend: {
      endpoint: "https://rafter.so/api/"
    },

    agent: {
      riskLevel: "moderate",
      environments: {
        openclaw: {
          enabled: false,
          skillPath: path.join(os.homedir(), ".openclaw", "skills", "rafter-security.md")
        },
        claudeCode: {
          enabled: false,
          mcpPath: path.join(os.homedir(), ".claude", "mcp", "rafter-security.json")
        }
      },
      commandPolicy: {
        mode: "approve-dangerous",
        blockedPatterns: [
          "rm -rf /",
          ":(){ :|:& };:",  // fork bomb
          "dd if=/dev/zero of=/dev/sda",
          "> /dev/sda"
        ],
        requireApproval: [
          "rm -rf",
          "sudo rm",
          "curl.*|.*sh",
          "wget.*|.*sh",
          "chmod 777",
          "git push --force"
        ]
      },
      outputFiltering: {
        redactSecrets: true,
        blockPatterns: true
      },
      audit: {
        logAllActions: true,
        retentionDays: 30,
        logLevel: "info"
      }
    }
  };
}

export function getRafterDir(): string {
  return path.join(os.homedir(), ".rafter");
}

export function getConfigPath(): string {
  return path.join(getRafterDir(), "config.json");
}

export function getAuditLogPath(): string {
  return path.join(getRafterDir(), "audit.log");
}

export function getBinDir(): string {
  return path.join(getRafterDir(), "bin");
}

export function getPatternsDir(): string {
  return path.join(getRafterDir(), "patterns");
}
