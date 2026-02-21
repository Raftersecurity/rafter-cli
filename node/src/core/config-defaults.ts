import { RafterConfig } from "./config-schema.js";
import { DEFAULT_BLOCKED_PATTERNS, DEFAULT_REQUIRE_APPROVAL } from "./risk-rules.js";
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
      skills: {
        autoUpdate: true,
        installOnInit: true,
        backupBeforeUpdate: true
      },
      commandPolicy: {
        mode: "approve-dangerous",
        blockedPatterns: [...DEFAULT_BLOCKED_PATTERNS],
        requireApproval: [...DEFAULT_REQUIRE_APPROVAL],
      },
      outputFiltering: {
        redactSecrets: true,
        blockPatterns: true
      },
      audit: {
        logAllActions: true,
        retentionDays: 30,
        logLevel: "info"
      },
      notifications: {
        webhook: undefined,
        minRiskLevel: "high"
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
  return path.join(getRafterDir(), "audit.jsonl");
}

export function getBinDir(): string {
  return path.join(getRafterDir(), "bin");
}

export function getPatternsDir(): string {
  return path.join(getRafterDir(), "patterns");
}
