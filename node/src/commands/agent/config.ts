import { Command } from "commander";
import { ConfigManager, redactConfigSecrets, isSecretConfigKey, maskSecretValue } from "../../core/config-manager.js";
import { fmt } from "../../utils/formatter.js";

export function createConfigCommand(): Command {
  const config = new Command("config")
    .description("Manage agent configuration");

  // Show all config
  config
    .command("show")
    .description("Show current configuration")
    .action(() => {
      const manager = new ConfigManager();
      const cfg = manager.load();
      console.log(JSON.stringify(redactConfigSecrets(cfg), null, 2));
    });

  // Get specific value
  config
    .command("get")
    .description("Get a configuration value")
    .argument("<key>", "Config key (e.g., agent.riskLevel)")
    .action((key) => {
      const manager = new ConfigManager();
      const value = manager.get(key);

      if (value === undefined) {
        console.error(`Key not found: ${key}`);
        process.exit(1);
      }

      const leaf = key.split(".").pop() ?? key;
      if (typeof value === "object") {
        console.log(JSON.stringify(redactConfigSecrets(value), null, 2));
      } else if (isSecretConfigKey(leaf) && typeof value === "string") {
        console.log(maskSecretValue(value));
      } else {
        console.log(value);
      }
    });

  // Set specific value
  config
    .command("set")
    .description("Set a configuration value")
    .argument("<key>", "Config key (e.g., agent.riskLevel)")
    .argument("<value>", "Value to set")
    .action((key, value) => {
      const manager = new ConfigManager();

      // Try to parse value as JSON, otherwise use as string
      let parsedValue: any = value;
      try {
        parsedValue = JSON.parse(value);
      } catch {
        // Use as string
      }

      manager.set(key, parsedValue);
      const leaf = key.split(".").pop() ?? key;
      const echo = isSecretConfigKey(leaf) && typeof parsedValue === "string"
        ? JSON.stringify(maskSecretValue(parsedValue))
        : JSON.stringify(parsedValue);
      console.log(fmt.success(`Set ${key} = ${echo}`));
    });

  return config;
}
