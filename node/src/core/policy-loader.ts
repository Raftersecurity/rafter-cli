import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import yaml from "js-yaml";

export interface PolicyCustomPattern {
  name: string;
  regex: string;
  severity: "low" | "medium" | "high" | "critical";
}

export interface PolicyDocEntry {
  id: string;
  path?: string;
  url?: string;
  description?: string;
  tags?: string[];
  cache?: {
    ttlSeconds: number;
  };
}

export interface PolicyIgnoreRule {
  /** Glob patterns matching files where findings should be suppressed. Required. */
  paths: string[];
  /** Pattern names to suppress (case-insensitive). Omitted = suppress all rules. */
  rules?: string[];
  /** Human-readable rationale, surfaced in the JSON `_suppressed` output. */
  reason?: string;
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
    autoUpdateBetterleaks?: boolean;
  };
  ignore?: PolicyIgnoreRule[];
  audit?: {
    retentionDays?: number;
    logLevel?: string;
    logPath?: string;
  };
  docs?: PolicyDocEntry[];
}

/**
 * Policy file candidates, in precedence order.
 *
 * sable-c1c — the cloud scanner (rafter-backend) reads `.rafter/config.yml`
 * (subdir + `config.yml`), while the CLI canonical is `.rafter.yml`. To
 * unbreak customers writing either shape, the CLI now reads both
 * indefinitely. Precedence: canonical dotfile first; backend file is the
 * fallback. If both are present, the dotfile wins (canonical).
 *
 * Schema compatibility is handled separately in `mapPolicy` — top-level
 * `exclude_paths` / `custom_patterns` (backend flat shape) is accepted
 * alongside `scan.exclude_paths` / `scan.custom_patterns` (CLI nested).
 */
const POLICY_FILE_CANDIDATES: string[] = [
  ".rafter.yml",
  ".rafter.yaml",
  path.join(".rafter", "config.yml"),
  path.join(".rafter", "config.yaml"),
];

/**
 * Find a policy file by walking from cwd up to git root.
 *
 * For each directory, check candidates in precedence order; the first hit
 * wins. The walk only ascends — siblings are not considered.
 */
export function findPolicyFile(): string | null {
  let dir = process.cwd();
  const root = getGitRoot() || path.parse(dir).root;

  while (true) {
    for (const filename of POLICY_FILE_CANDIDATES) {
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
    return validatePolicy(mapPolicy(parsed), parsed);
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
    if (typeof raw.scan.auto_update_betterleaks === "boolean") {
      policy.scan.autoUpdateBetterleaks = raw.scan.auto_update_betterleaks;
    }
  }

  // sable-c1c — backend flat-shape compat. rafter-backend reads
  // exclude_paths / custom_patterns at the top level (no `scan:` nesting),
  // so customers writing the backend shape get the same behavior locally.
  // Nested form takes precedence if both are present in the same file.
  if (!policy.scan?.excludePaths && Array.isArray(raw.exclude_paths)) {
    policy.scan = policy.scan || {};
    policy.scan.excludePaths = raw.exclude_paths;
  }
  if (!policy.scan?.customPatterns && Array.isArray(raw.custom_patterns)) {
    policy.scan = policy.scan || {};
    policy.scan.customPatterns = raw.custom_patterns.map((p: any) => ({
      name: p.name,
      regex: p.regex,
      severity: p.severity || "high",
    }));
  }

  if (Array.isArray(raw.ignore)) {
    const rules: PolicyIgnoreRule[] = [];
    for (const entry of raw.ignore) {
      if (!entry || typeof entry !== "object") {
        console.error(`Warning: skipping malformed ignore entry — must be an object with paths.`);
        continue;
      }
      const paths = entry.paths;
      if (!Array.isArray(paths) || paths.length === 0) {
        console.error(`Warning: skipping ignore entry — "paths" must be a non-empty array of strings.`);
        continue;
      }
      const rule: PolicyIgnoreRule = { paths: paths.map((p: any) => String(p)) };
      if (Array.isArray(entry.rules)) {
        rule.rules = entry.rules.map((r: any) => String(r));
      }
      if (typeof entry.reason === "string" && entry.reason) {
        rule.reason = entry.reason;
      }
      rules.push(rule);
    }
    if (rules.length > 0) {
      policy.ignore = rules;
    }
  }

  if (raw.audit && typeof raw.audit === "object") {
    policy.audit = {};
    if (raw.audit.retention_days != null) {
      policy.audit.retentionDays = Number(raw.audit.retention_days);
    }
    if (raw.audit.log_level) policy.audit.logLevel = raw.audit.log_level;
    if (raw.audit.log_path) policy.audit.logPath = String(raw.audit.log_path);
  }

  if (Array.isArray(raw.docs)) {
    policy.docs = [];
    const seenIds = new Set<string>();
    for (const entry of raw.docs) {
      if (!entry || typeof entry !== "object") {
        console.error(`Warning: skipping malformed docs entry — must be an object.`);
        continue;
      }
      const hasPath = typeof entry.path === "string" && entry.path.length > 0;
      const hasUrl = typeof entry.url === "string" && entry.url.length > 0;
      if (hasPath === hasUrl) {
        console.error(`Warning: skipping docs entry — must have exactly one of "path" or "url".`);
        continue;
      }
      const id = typeof entry.id === "string" && entry.id.length > 0
        ? entry.id
        : deriveDocId(hasPath ? entry.path : entry.url, hasPath ? "path" : "url");
      if (seenIds.has(id)) {
        console.error(`Warning: skipping docs entry with duplicate id "${id}".`);
        continue;
      }
      seenIds.add(id);

      const doc: PolicyDocEntry = { id };
      if (hasPath) doc.path = entry.path;
      if (hasUrl) doc.url = entry.url;
      if (typeof entry.description === "string") doc.description = entry.description;
      if (Array.isArray(entry.tags) && entry.tags.every((t: any) => typeof t === "string")) {
        doc.tags = entry.tags;
      } else if (entry.tags !== undefined) {
        console.error(`Warning: docs entry "${id}" — tags must be a list of strings, ignoring.`);
      }
      if (entry.cache && typeof entry.cache === "object") {
        const ttl = entry.cache.ttl_seconds;
        if (!hasUrl) {
          console.error(`Warning: docs entry "${id}" — cache is only valid with url, ignoring.`);
        } else if (typeof ttl === "number" && ttl > 0 && Number.isFinite(ttl)) {
          doc.cache = { ttlSeconds: Math.floor(ttl) };
        } else {
          console.error(`Warning: docs entry "${id}" — cache.ttl_seconds must be a positive number, ignoring.`);
        }
      }
      const known = new Set(["id", "path", "url", "description", "tags", "cache"]);
      for (const key of Object.keys(entry)) {
        if (!known.has(key)) {
          console.error(`Warning: docs entry "${id}" — unknown key "${key}", ignoring.`);
        }
      }
      policy.docs.push(doc);
    }
  }

  return policy;
}

function deriveDocId(source: string, kind: "path" | "url"): string {
  if (kind === "path") {
    const base = path.basename(source);
    const withoutExt = base.replace(/\.[^./]+$/, "");
    return withoutExt || base;
  }
  const crypto = require("crypto") as typeof import("crypto");
  return crypto.createHash("sha256").update(source).digest("hex").slice(0, 8);
}

const VALID_TOP_LEVEL_KEYS = new Set([
  "version", "risk_level", "command_policy", "scan", "ignore", "audit", "docs",
  // sable-c1c — backend flat-shape compat keys.
  "exclude_paths", "custom_patterns",
]);
const VALID_RISK_LEVELS = new Set(["minimal", "moderate", "aggressive"]);
const VALID_COMMAND_MODES = new Set(["allow-all", "approve-dangerous", "deny-list"]);
const VALID_LOG_LEVELS = new Set(["debug", "info", "warn", "error"]);

/**
 * Validate a mapped policy, warn on stderr for invalid fields, strip them out.
 * `raw` is the original parsed YAML (snake_case keys) for unknown-key detection.
 */
function validatePolicy(policy: PolicyFile, raw: Record<string, any>): PolicyFile {
  // 1. Unknown top-level keys
  for (const key of Object.keys(raw)) {
    if (!VALID_TOP_LEVEL_KEYS.has(key)) {
      console.error(`Warning: Unknown policy key "${key}" — ignoring.`);
    }
  }

  // 2. Type checking + strip invalid
  if (policy.version !== undefined && typeof policy.version !== "string") {
    console.error(`Warning: "version" must be a string — ignoring.`);
    delete policy.version;
  }

  if (policy.riskLevel !== undefined && !VALID_RISK_LEVELS.has(policy.riskLevel)) {
    console.error(`Warning: "risk_level" must be one of: minimal, moderate, aggressive — ignoring.`);
    delete policy.riskLevel;
  }

  if (policy.commandPolicy) {
    if (policy.commandPolicy.mode !== undefined && !VALID_COMMAND_MODES.has(policy.commandPolicy.mode)) {
      console.error(`Warning: "command_policy.mode" must be one of: allow-all, approve-dangerous, deny-list — ignoring.`);
      delete policy.commandPolicy.mode;
    }
    if (policy.commandPolicy.blockedPatterns !== undefined) {
      if (!Array.isArray(policy.commandPolicy.blockedPatterns) || !policy.commandPolicy.blockedPatterns.every((v: any) => typeof v === "string")) {
        console.error(`Warning: "command_policy.blocked_patterns" must be an array of strings — ignoring.`);
        delete policy.commandPolicy.blockedPatterns;
      }
    }
    if (policy.commandPolicy.requireApproval !== undefined) {
      if (!Array.isArray(policy.commandPolicy.requireApproval) || !policy.commandPolicy.requireApproval.every((v: any) => typeof v === "string")) {
        console.error(`Warning: "command_policy.require_approval" must be an array of strings — ignoring.`);
        delete policy.commandPolicy.requireApproval;
      }
    }
  }

  if (policy.scan) {
    if (policy.scan.excludePaths !== undefined) {
      if (!Array.isArray(policy.scan.excludePaths) || !policy.scan.excludePaths.every((v: any) => typeof v === "string")) {
        console.error(`Warning: "scan.exclude_paths" must be an array of strings — ignoring.`);
        delete policy.scan.excludePaths;
      }
    }
    if (policy.scan.customPatterns !== undefined) {
      if (!Array.isArray(policy.scan.customPatterns)) {
        console.error(`Warning: "scan.custom_patterns" must be an array — ignoring.`);
        delete policy.scan.customPatterns;
      } else {
        const valid: PolicyCustomPattern[] = [];
        for (const v of policy.scan.customPatterns) {
          if (!v || typeof v !== "object" || typeof v.name !== "string" || !v.name || typeof v.regex !== "string" || !v.regex || typeof v.severity !== "string") {
            console.error(`Warning: skipping malformed custom_patterns entry — must have name, regex, severity.`);
            continue;
          }
          try {
            new RegExp(v.regex);
          } catch {
            console.error(`Warning: skipping custom pattern "${v.name}" — invalid regex.`);
            continue;
          }
          valid.push(v);
        }
        if (valid.length > 0) {
          policy.scan.customPatterns = valid;
        } else {
          delete policy.scan.customPatterns;
        }
      }
    }
    // sable-o4k — only a boolean reaches policy.scan (mapping guards the type),
    // so warn directly off the raw value when it's present but malformed.
    if (raw.scan && typeof raw.scan === "object" &&
        raw.scan.auto_update_betterleaks !== undefined &&
        typeof raw.scan.auto_update_betterleaks !== "boolean") {
      console.error(`Warning: "scan.auto_update_betterleaks" must be a boolean — ignoring.`);
    }
  }

  if (policy.ignore !== undefined) {
    if (!Array.isArray(policy.ignore)) {
      console.error(`Warning: "ignore" must be an array — ignoring.`);
      delete policy.ignore;
    } else {
      const valid: PolicyIgnoreRule[] = [];
      for (const entry of policy.ignore) {
        if (!entry || typeof entry !== "object") {
          console.error(`Warning: skipping malformed ignore entry — must be an object with paths.`);
          continue;
        }
        if (!Array.isArray(entry.paths) || entry.paths.length === 0 || !entry.paths.every((p) => typeof p === "string" && p)) {
          console.error(`Warning: skipping ignore entry — "paths" must be a non-empty array of strings.`);
          continue;
        }
        if (entry.rules !== undefined && (!Array.isArray(entry.rules) || !entry.rules.every((r) => typeof r === "string"))) {
          console.error(`Warning: skipping ignore entry — "rules" must be an array of strings.`);
          continue;
        }
        if (entry.reason !== undefined && typeof entry.reason !== "string") {
          console.error(`Warning: ignore entry "reason" must be a string — dropping reason.`);
          delete entry.reason;
        }
        valid.push(entry);
      }
      if (valid.length > 0) {
        policy.ignore = valid;
      } else {
        delete policy.ignore;
      }
    }
  }

  if (policy.audit) {
    if (policy.audit.retentionDays !== undefined && (typeof policy.audit.retentionDays !== "number" || isNaN(policy.audit.retentionDays))) {
      console.error(`Warning: "audit.retention_days" must be a number — ignoring.`);
      delete policy.audit.retentionDays;
    }
    if (policy.audit.logLevel !== undefined && !VALID_LOG_LEVELS.has(policy.audit.logLevel)) {
      console.error(`Warning: "audit.log_level" must be one of: debug, info, warn, error — ignoring.`);
      delete policy.audit.logLevel;
    }
    if (policy.audit.logPath !== undefined && typeof policy.audit.logPath !== "string") {
      console.error(`Warning: "audit.log_path" must be a string — ignoring.`);
      delete policy.audit.logPath;
    }
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
