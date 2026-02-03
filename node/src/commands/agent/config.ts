import { Command } from "commander";
import { ConfigManager } from "../../core/config-manager.js";

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
      console.log(JSON.stringify(cfg, null, 2));
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

      if (typeof value === "object") {
        console.log(JSON.stringify(value, null, 2));
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
      console.log(`✓ Set ${key} = ${JSON.stringify(parsedValue)}`);
    });

  return config;
}
