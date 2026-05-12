import { Command } from "commander";
import { execSync } from "child_process";
import axios from "axios";
import { fmt } from "../utils/formatter.js";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const { version: CURRENT_VERSION } = require("../../package.json");

const NPM_PACKAGE = "@rafter-security/cli";
const NPM_REGISTRY_URL = `https://registry.npmjs.org/${NPM_PACKAGE}/latest`;

function isCI(): boolean {
  return !!(
    process.env.CI ||
    process.env.CONTINUOUS_INTEGRATION ||
    process.env.GITHUB_ACTIONS ||
    process.env.GITLAB_CI ||
    process.env.CIRCLECI ||
    process.env.TRAVIS ||
    process.env.JENKINS_URL
  );
}

function isNewer(current: string, latest: string): boolean {
  const c = current.split(".").map(Number);
  const l = latest.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((l[i] || 0) > (c[i] || 0)) return true;
    if ((l[i] || 0) < (c[i] || 0)) return false;
  }
  return false;
}

async function fetchLatestVersion(): Promise<string> {
  const res = await axios.get(NPM_REGISTRY_URL, { timeout: 5000 });
  return res.data.version as string;
}

type PackageManager = "npm" | "pnpm" | "yarn" | "unknown";
type InstallScope = "global" | "local" | "unknown";

interface InstallContext {
  manager: PackageManager;
  scope: InstallScope;
}

function detectInstallContext(): InstallContext {
  // npm_config_user_agent is set by npm, pnpm, and yarn when running scripts
  const userAgent = process.env.npm_config_user_agent || "";
  let manager: PackageManager = "unknown";
  if (userAgent.startsWith("pnpm/")) {
    manager = "pnpm";
  } else if (userAgent.startsWith("yarn/")) {
    manager = "yarn";
  } else if (userAgent.startsWith("npm/")) {
    manager = "npm";
  }

  // Fallback: check PNPM_HOME (set by pnpm global installs)
  if (manager === "unknown" && process.env.PNPM_HOME) {
    manager = "pnpm";
  }

  // Check executable path for clues
  const binPath = process.argv[1] ?? "";
  if (manager === "unknown") {
    if (binPath.includes("pnpm") || binPath.includes(".pnpm")) {
      manager = "pnpm";
    } else if (binPath.includes("yarn")) {
      manager = "yarn";
    }
  }

  // Scope detection
  let scope: InstallScope = "unknown";
  if (process.env.npm_config_global === "true") {
    scope = "global";
  } else if (binPath.includes("node_modules")) {
    scope = "local";
  } else {
    // Binary outside node_modules → likely global
    scope = "global";
  }

  return { manager, scope };
}

function buildUpgradeCommand(ctx: InstallContext): string | null {
  const pkg = `${NPM_PACKAGE}@latest`;
  if (ctx.manager === "unknown") return null;

  switch (ctx.manager) {
    case "npm":
      return ctx.scope === "local"
        ? `npm install ${pkg}`
        : `npm install -g ${pkg}`;
    case "pnpm":
      return ctx.scope === "local"
        ? `pnpm add ${pkg}`
        : `pnpm add -g ${pkg}`;
    case "yarn":
      return ctx.scope === "local"
        ? `yarn add ${pkg}`
        : `yarn global add ${pkg}`;
  }
}

export function createUpgradeCommand(): Command {
  const cmd = new Command("upgrade")
    .alias("update")
    .description("Upgrade rafter to the latest version")
    .option("--check", "Check for updates without installing")
    .option("-y, --yes", "Run the upgrade command automatically without prompting")
    .action(async (opts: { check?: boolean; yes?: boolean }) => {
      // No-op in CI
      if (isCI()) {
        console.log(fmt.info("CI environment detected — skipping upgrade check."));
        process.exit(0);
      }

      let latestVersion: string;
      try {
        latestVersion = await fetchLatestVersion();
      } catch {
        console.error(fmt.error("Could not reach npm registry. Check your network connection."));
        process.exit(1);
      }

      if (opts.check) {
        console.log(latestVersion);
        return;
      }

      console.log(fmt.info(`Current version: ${CURRENT_VERSION}`));
      console.log(fmt.info(`Latest version:  ${latestVersion}`));
      console.log();

      if (!isNewer(CURRENT_VERSION, latestVersion)) {
        console.log(fmt.success("Already up to date."));
        return;
      }

      const ctx = detectInstallContext();
      const upgradeCmd = buildUpgradeCommand(ctx);

      if (upgradeCmd && opts.yes) {
        console.log(fmt.info(`Running: ${upgradeCmd}`));
        console.log();
        try {
          execSync(upgradeCmd, { stdio: "inherit" });
          console.log();
          console.log(fmt.success(`Upgraded to ${latestVersion}`));
        } catch {
          console.error(fmt.error("Upgrade failed. Try running the command manually:"));
          console.log(`  ${upgradeCmd}`);
          process.exit(1);
        }
        return;
      }

      // Print the command(s) to run
      if (upgradeCmd) {
        console.log(fmt.info("Run to upgrade:"));
        console.log(`  ${upgradeCmd}`);
      } else {
        console.log(fmt.info("Run one of the following to upgrade:"));
        console.log(`  npm install -g ${NPM_PACKAGE}@latest`);
        console.log(`  pnpm add -g ${NPM_PACKAGE}@latest`);
        console.log(`  yarn global add ${NPM_PACKAGE}@latest`);
        console.log();
        console.log(fmt.info("Or for a local install:"));
        console.log(`  npm install ${NPM_PACKAGE}@latest`);
      }

      console.log();
      console.log(fmt.info("Also available via pip:"));
      console.log(`  pip install --upgrade rafter-cli`);
    });

  return cmd;
}
