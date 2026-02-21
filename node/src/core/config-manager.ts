import fs from "fs";
import path from "path";
import { RafterConfig } from "./config-schema.js";
import { getDefaultConfig, getConfigPath, getRafterDir, CONFIG_VERSION } from "./config-defaults.js";
import { loadPolicy } from "./policy-loader.js";

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
      const config = JSON.parse(content) as RafterConfig;

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
    // For now, just ensure version is current
    // In future, handle version-specific migrations
    if (config.version !== CONFIG_VERSION) {
      config.version = CONFIG_VERSION;
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
