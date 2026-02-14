import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import yaml from "js-yaml";

export interface PolicyCustomPattern {
  name: string;
  regex: string;
  severity: "low" | "medium" | "high" | "critical";
}

export interface PolicyFile {
  version?: string;
  riskLevel?: string;
  commandPolicy?: {
    mode?: string;
    blockedPatterns?: string[];
    requireApproval?: string[];
  };
  scan?: {
    excludePaths?: string[];
    customPatterns?: PolicyCustomPattern[];
  };
  audit?: {
    retentionDays?: number;
    logLevel?: string;
  };
}

const POLICY_FILENAMES = [".rafter.yml", ".rafter.yaml"];

/**
 * Find a policy file by walking from cwd up to git root
 */
export function findPolicyFile(): string | null {
  let dir = process.cwd();
  const root = getGitRoot() || path.parse(dir).root;

  while (true) {
    for (const filename of POLICY_FILENAMES) {
      const candidate = path.join(dir, filename);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir || dir === root) {
      break;
    }
    dir = parent;
  }

  return null;
}

/**
 * Load and parse the policy file, returning null if not found
 */
export function loadPolicy(): PolicyFile | null {
  const policyPath = findPolicyFile();
  if (!policyPath) return null;

  try {
    const content = fs.readFileSync(policyPath, "utf-8");
    const parsed = yaml.load(content) as Record<string, any>;
    if (!parsed || typeof parsed !== "object") return null;
    return mapPolicy(parsed);
  } catch (e: any) {
    console.error(`Warning: Failed to parse policy file ${policyPath}: ${e.message}`);
    return null;
  }
}

/**
 * Map snake_case YAML keys to camelCase PolicyFile
 */
function mapPolicy(raw: Record<string, any>): PolicyFile {
  const policy: PolicyFile = {};

  if (raw.version) policy.version = String(raw.version);
  if (raw.risk_level) policy.riskLevel = raw.risk_level;

  if (raw.command_policy && typeof raw.command_policy === "object") {
    policy.commandPolicy = {};
    if (raw.command_policy.mode) policy.commandPolicy.mode = raw.command_policy.mode;
    if (Array.isArray(raw.command_policy.blocked_patterns)) {
      policy.commandPolicy.blockedPatterns = raw.command_policy.blocked_patterns;
    }
    if (Array.isArray(raw.command_policy.require_approval)) {
      policy.commandPolicy.requireApproval = raw.command_policy.require_approval;
    }
  }

  if (raw.scan && typeof raw.scan === "object") {
    policy.scan = {};
    if (Array.isArray(raw.scan.exclude_paths)) {
      policy.scan.excludePaths = raw.scan.exclude_paths;
    }
    if (Array.isArray(raw.scan.custom_patterns)) {
      policy.scan.customPatterns = raw.scan.custom_patterns.map((p: any) => ({
        name: p.name,
        regex: p.regex,
        severity: p.severity || "high",
      }));
    }
  }

  if (raw.audit && typeof raw.audit === "object") {
    policy.audit = {};
    if (raw.audit.retention_days != null) {
      policy.audit.retentionDays = Number(raw.audit.retention_days);
    }
    if (raw.audit.log_level) policy.audit.logLevel = raw.audit.log_level;
  }

  return policy;
}

function getGitRoot(): string | null {
  try {
    return execSync("git rev-parse --show-toplevel", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();
  } catch {
    return null;
  }
}
