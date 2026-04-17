import fs from "fs";
import path from "path";
import { RafterConfig } from "./config-schema.js";
import { getDefaultConfig, getConfigPath, getRafterDir, CONFIG_VERSION } from "./config-defaults.js";
import { loadPolicy } from "./policy-loader.js";

const VALID_RISK_LEVELS = new Set(["minimal", "moderate", "aggressive"]);
const VALID_COMMAND_MODES = new Set(["allow-all", "approve-dangerous", "deny-list"]);
const VALID_LOG_LEVELS = new Set(["debug", "info", "warn", "error"]);

/**
 * Validate a parsed config JSON object, warning and falling back to defaults for invalid fields.
 */
function validateConfig(raw: any): RafterConfig {
  if (!raw || typeof raw !== "object") {
    console.error("Warning: config file is not a JSON object — using defaults.");
    return getDefaultConfig();
  }

  const defaults = getDefaultConfig();

  // Top-level scalars
  if (raw.version !== undefined && typeof raw.version !== "string") {
    console.error('Warning: config "version" must be a string — using default.');
    raw.version = defaults.version;
  }
  if (raw.initialized !== undefined && typeof raw.initialized !== "string") {
    console.error('Warning: config "initialized" must be a string — using default.');
    raw.initialized = defaults.initialized;
  }

  const agent = raw.agent;
  if (agent && typeof agent === "object") {
    // riskLevel
    if (agent.riskLevel !== undefined && !VALID_RISK_LEVELS.has(agent.riskLevel)) {
      console.error(`Warning: config "agent.riskLevel" must be one of: minimal, moderate, aggressive — using default.`);
      agent.riskLevel = defaults.agent!.riskLevel;
    }

    // commandPolicy
    const cp = agent.commandPolicy;
    if (cp && typeof cp === "object") {
      if (cp.mode !== undefined && !VALID_COMMAND_MODES.has(cp.mode)) {
        console.error(`Warning: config "agent.commandPolicy.mode" must be one of: allow-all, approve-dangerous, deny-list — using default.`);
        cp.mode = defaults.agent!.commandPolicy.mode;
      }
      if (cp.blockedPatterns !== undefined && (!Array.isArray(cp.blockedPatterns) || !cp.blockedPatterns.every((v: any) => typeof v === "string"))) {
        console.error('Warning: config "agent.commandPolicy.blockedPatterns" must be an array of strings — using default.');
        cp.blockedPatterns = [...defaults.agent!.commandPolicy.blockedPatterns];
      }
      if (cp.requireApproval !== undefined && (!Array.isArray(cp.requireApproval) || !cp.requireApproval.every((v: any) => typeof v === "string"))) {
        console.error('Warning: config "agent.commandPolicy.requireApproval" must be an array of strings — using default.');
        cp.requireApproval = [...defaults.agent!.commandPolicy.requireApproval];
      }
    }

    // audit
    const audit = agent.audit;
    if (audit && typeof audit === "object") {
      if (audit.retentionDays !== undefined && (typeof audit.retentionDays !== "number" || isNaN(audit.retentionDays))) {
        console.error('Warning: config "agent.audit.retentionDays" must be a number — using default.');
        audit.retentionDays = defaults.agent!.audit.retentionDays;
      }
      if (audit.logLevel !== undefined && !VALID_LOG_LEVELS.has(audit.logLevel)) {
        console.error(`Warning: config "agent.audit.logLevel" must be one of: debug, info, warn, error — using default.`);
        audit.logLevel = defaults.agent!.audit.logLevel;
      }
    }

    // outputFiltering
    const of = agent.outputFiltering;
    if (of && typeof of === "object") {
      if (of.redactSecrets !== undefined && typeof of.redactSecrets !== "boolean") {
        console.error('Warning: config "agent.outputFiltering.redactSecrets" must be a boolean — using default.');
        of.redactSecrets = defaults.agent!.outputFiltering.redactSecrets;
      }
      if (of.blockPatterns !== undefined && typeof of.blockPatterns !== "boolean") {
        console.error('Warning: config "agent.outputFiltering.blockPatterns" must be a boolean — using default.');
        of.blockPatterns = defaults.agent!.outputFiltering.blockPatterns;
      }
    }

    // scan.customPatterns — validate regex compilation
    const scan = agent.scan;
    if (scan && typeof scan === "object") {
      if (scan.excludePaths !== undefined && (!Array.isArray(scan.excludePaths) || !scan.excludePaths.every((v: any) => typeof v === "string"))) {
        console.error('Warning: config "agent.scan.excludePaths" must be an array of strings — using default.');
        delete scan.excludePaths;
      }
      if (Array.isArray(scan.customPatterns)) {
        scan.customPatterns = scan.customPatterns.filter((p: any) => {
          if (!p || typeof p !== "object" || typeof p.name !== "string" || !p.name || typeof p.regex !== "string" || !p.regex) {
            console.error(`Warning: skipping malformed scan.customPatterns entry — must have name and regex.`);
            return false;
          }
          try {
            new RegExp(p.regex);
          } catch {
            console.error(`Warning: skipping custom pattern "${p.name}" — invalid regex.`);
            return false;
          }
          return true;
        });
      }
    }
  }

  return raw as RafterConfig;
}

export class ConfigManager {
  private configPath: string;

  constructor(configPath?: string) {
    this.configPath = configPath || getConfigPath();
  }

  /**
   * Load config from disk, creating default if it doesn't exist
   */
  load(): RafterConfig {
    if (!fs.existsSync(this.configPath)) {
      return getDefaultConfig();
    }

    try {
      const content = fs.readFileSync(this.configPath, "utf-8");
      const parsed = JSON.parse(content);
      const config = validateConfig(parsed);

      // Migrate config if needed
      return this.migrate(config);
    } catch (e) {
      console.error(`Failed to load config from ${this.configPath}: ${e}`);
      return getDefaultConfig();
    }
  }

  /**
   * Save config to disk
   */
  save(config: RafterConfig): void {
    // Ensure directory exists
    const dir = path.dirname(this.configPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Write config
    fs.writeFileSync(this.configPath, JSON.stringify(config, null, 2), "utf-8");
  }

  /**
   * Update specific config values
   */
  update(updates: Partial<RafterConfig>): RafterConfig {
    const config = this.load();
    const merged = this.deepMerge(config, updates);
    this.save(merged);
    return merged;
  }

  /**
   * Get a specific config value by path (e.g., "agent.riskLevel")
   */
  get(keyPath: string): any {
    const config = this.load();
    const keys = keyPath.split(".");
    let value: any = config;
    for (const key of keys) {
      if (value && typeof value === "object" && key in value) {
        value = value[key];
      } else {
        return undefined;
      }
    }
    return value;
  }

  /**
   * Set a specific config value by path
   */
  set(keyPath: string, value: any): void {
    const config = this.load();
    const keys = keyPath.split(".");
    let current: any = config;

    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i];
      if (!(key in current)) {
        current[key] = {};
      }
      current = current[key];
    }

    const lastKey = keys[keys.length - 1];
    current[lastKey] = value;

    this.save(config);
  }

  /**
   * Initialize config directory structure
   */
  async initialize(): Promise<void> {
    const rafterDir = getRafterDir();

    // Create directories
    const dirs = [
      rafterDir,
      path.join(rafterDir, "bin"),
      path.join(rafterDir, "patterns")
    ];

    for (const dir of dirs) {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }

    // Write patterns/ README if missing
    const patternsReadme = path.join(rafterDir, "patterns", "README.md");
    if (!fs.existsSync(patternsReadme)) {
      fs.writeFileSync(
        patternsReadme,
        [
          "# Custom Secret Patterns",
          "",
          "Place custom secret-detection pattern files here.",
          "Each file should contain one regex pattern per line.",
          "",
          "Rafter ships 21 built-in patterns (AWS, GitHub, Stripe, etc.).",
          "Files in this directory extend that set for your environment.",
          "",
          "Support for loading custom patterns from this directory is planned",
          "for a future release.",
        ].join("\n"),
        "utf-8"
      );
    }

    // Create default config if it doesn't exist
    if (!fs.existsSync(this.configPath)) {
      const config = getDefaultConfig();
      this.save(config);
    }
  }

  /**
   * Load config merged with .rafter.yml policy (policy wins)
   */
  loadWithPolicy(): RafterConfig {
    const config = this.load();
    const policy = loadPolicy();
    if (!policy) return config;

    // Ensure agent block exists
    if (!config.agent) {
      const defaults = getDefaultConfig();
      config.agent = defaults.agent;
    }

    // Risk level
    if (policy.riskLevel && config.agent) {
      config.agent.riskLevel = policy.riskLevel as any;
    }

    // Command policy — arrays replace, not append
    if (policy.commandPolicy && config.agent) {
      if (policy.commandPolicy.mode) {
        config.agent.commandPolicy.mode = policy.commandPolicy.mode as any;
      }
      if (policy.commandPolicy.blockedPatterns) {
        config.agent.commandPolicy.blockedPatterns = policy.commandPolicy.blockedPatterns;
      }
      if (policy.commandPolicy.requireApproval) {
        config.agent.commandPolicy.requireApproval = policy.commandPolicy.requireApproval;
      }
    }

    // Scan settings
    if (policy.scan && config.agent) {
      if (!config.agent.scan) config.agent.scan = {};
      if (policy.scan.excludePaths) {
        config.agent.scan.excludePaths = policy.scan.excludePaths;
      }
      if (policy.scan.customPatterns) {
        config.agent.scan.customPatterns = policy.scan.customPatterns;
      }
    }

    // Audit settings
    if (policy.audit && config.agent) {
      if (policy.audit.retentionDays != null) {
        config.agent.audit.retentionDays = policy.audit.retentionDays;
      }
      if (policy.audit.logLevel) {
        config.agent.audit.logLevel = policy.audit.logLevel as any;
      }
      if (policy.audit.logPath) {
        config.agent.audit.logPath = policy.audit.logPath;
      }
    }

    return config;
  }

  /**
   * Check if config exists
   */
  exists(): boolean {
    return fs.existsSync(this.configPath);
  }

  /**
   * Migrate config to latest version
   */
  private migrate(config: RafterConfig): RafterConfig {
    let dirty = false;

    if (config.version !== CONFIG_VERSION) {
      config.version = CONFIG_VERSION;
      dirty = true;
    }

    // Fix overly broad curl/wget pipe-to-shell patterns.
    // Old pattern: "curl.*\|.*sh" — matches any command containing "sh" after a pipe
    // (e.g. `grep "curl\|sh"` or `git push`). Replace with word-bounded shell names.
    const badToGood: Record<string, string> = {
      "curl.*\\|.*sh": "curl.*\\|\\s*(bash|sh|zsh|dash)\\b",
      "wget.*\\|.*sh": "wget.*\\|\\s*(bash|sh|zsh|dash)\\b",
    };
    const approval = config.agent?.commandPolicy?.requireApproval;
    if (Array.isArray(approval)) {
      const fixed = approval.map(p => badToGood[p] ?? p);
      if (fixed.some((p, i) => p !== approval[i])) {
        config.agent!.commandPolicy!.requireApproval = fixed;
        dirty = true;
      }
    }

    if (dirty) {
      this.save(config);
    }
    return config;
  }

  /**
   * Deep merge two objects
   */
  private deepMerge(target: any, source: any): any {
    const output = { ...target };

    if (this.isObject(target) && this.isObject(source)) {
      Object.keys(source).forEach(key => {
        if (this.isObject(source[key])) {
          if (!(key in target)) {
            output[key] = source[key];
          } else {
            output[key] = this.deepMerge(target[key], source[key]);
          }
        } else {
          output[key] = source[key];
        }
      });
    }

    return output;
  }

  private isObject(item: any): boolean {
    return item && typeof item === "object" && !Array.isArray(item);
  }
}
