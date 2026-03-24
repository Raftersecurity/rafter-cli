import { Command } from "commander";
import fs from "fs";
import os from "os";
import path from "path";
import { fmt, isAgentMode } from "../utils/formatter.js";

export type Platform =
  | "claude-code"
  | "gemini"
  | "cursor"
  | "windsurf"
  | "codex"
  | "aider"
  | "continue"
  | "generic";

interface PlatformInfo {
  name: string;
  detected: boolean;
  configPath: string;
  snippet: string;
  oneLiner: string;
}

/** Detect which agent platforms are present on this machine. */
export function detectPlatforms(): Platform[] {
  const home = os.homedir();
  const found: Platform[] = [];

  if (fs.existsSync(path.join(home, ".claude"))) found.push("claude-code");
  if (fs.existsSync(path.join(home, ".gemini"))) found.push("gemini");
  if (fs.existsSync(path.join(home, ".cursor"))) found.push("cursor");
  if (fs.existsSync(path.join(home, ".codeium", "windsurf"))) found.push("windsurf");
  if (fs.existsSync(path.join(home, ".codex"))) found.push("codex");
  if (fs.existsSync(path.join(home, ".aider.conf.yml"))) found.push("aider");
  if (fs.existsSync(path.join(home, ".continue"))) found.push("continue");

  return found;
}

/** Get the config snippet for a given platform. */
export function getSnippet(platform: Platform): PlatformInfo {
  const home = os.homedir();

  switch (platform) {
    case "claude-code":
      return {
        name: "Claude Code",
        detected: fs.existsSync(path.join(home, ".claude")),
        configPath: "~/.claude/settings.json",
        oneLiner: "rafter agent init --with-claude-code",
        snippet: JSON.stringify(
          {
            hooks: {
              PreToolUse: [
                {
                  matcher: "Bash",
                  hooks: [{ type: "command", command: "rafter hook pretool" }],
                },
              ],
            },
          },
          null,
          2
        ),
      };

    case "gemini":
      return {
        name: "Gemini CLI",
        detected: fs.existsSync(path.join(home, ".gemini")),
        configPath: "~/.gemini/settings.json",
        oneLiner: "rafter agent init --with-gemini",
        snippet: JSON.stringify(
          {
            mcpServers: {
              rafter: { command: "rafter", args: ["mcp", "serve"] },
            },
          },
          null,
          2
        ),
      };

    case "cursor":
      return {
        name: "Cursor",
        detected: fs.existsSync(path.join(home, ".cursor")),
        configPath: "~/.cursor/mcp.json",
        oneLiner: "rafter agent init --with-cursor",
        snippet: JSON.stringify(
          {
            mcpServers: {
              rafter: { command: "rafter", args: ["mcp", "serve"] },
            },
          },
          null,
          2
        ),
      };

    case "windsurf":
      return {
        name: "Windsurf",
        detected: fs.existsSync(path.join(home, ".codeium", "windsurf")),
        configPath: "~/.codeium/windsurf/mcp_config.json",
        oneLiner: "rafter agent init --with-windsurf",
        snippet: JSON.stringify(
          {
            mcpServers: {
              rafter: { command: "rafter", args: ["mcp", "serve"] },
            },
          },
          null,
          2
        ),
      };

    case "codex":
      return {
        name: "Codex CLI",
        detected: fs.existsSync(path.join(home, ".codex")),
        configPath: "~/.codex/config",
        oneLiner: "rafter agent init --with-codex",
        snippet: [
          "# Add to CLAUDE.md or agent instructions:",
          "npx rafter agent init --with-codex",
        ].join("\n"),
      };

    case "aider":
      return {
        name: "Aider",
        detected: fs.existsSync(path.join(home, ".aider.conf.yml")),
        configPath: "~/.aider.conf.yml",
        oneLiner: "rafter agent init --with-aider",
        snippet: [
          "# Rafter security MCP server",
          "mcp-server-command: rafter mcp serve",
        ].join("\n"),
      };

    case "continue":
      return {
        name: "Continue.dev",
        detected: fs.existsSync(path.join(home, ".continue")),
        configPath: "~/.continue/config.json",
        oneLiner: "rafter agent init --with-continue",
        snippet: JSON.stringify(
          {
            mcpServers: {
              rafter: { command: "rafter", args: ["mcp", "serve"] },
            },
          },
          null,
          2
        ),
      };

    case "generic":
    default:
      return {
        name: "Generic",
        detected: true,
        configPath: "CLAUDE.md / agent config",
        oneLiner: "npx rafter agent init --all",
        snippet: [
          "# Add to your CLAUDE.md or agent instructions:",
          "# Security: run `npx rafter agent init --all` to install Rafter security hooks.",
          "# This adds command interception, secret scanning, and audit logging.",
        ].join("\n"),
      };
  }
}

/** Format output for a single platform. */
function formatPlatformOutput(info: PlatformInfo, agent: boolean): string {
  if (agent) {
    return [
      `platform: ${info.name}`,
      `config: ${info.configPath}`,
      `install: ${info.oneLiner}`,
      "",
      info.snippet,
    ].join("\n");
  }

  const lines: string[] = [];
  lines.push(fmt.header(`Rafter setup for ${info.name}`));
  lines.push("");
  lines.push(`${fmt.info("Quick install:")} ${info.oneLiner}`);
  lines.push("");
  lines.push(`${fmt.info("Config file:")} ${info.configPath}`);
  lines.push("");
  lines.push(fmt.info("Manual config snippet:"));
  lines.push(info.snippet);
  return lines.join("\n");
}

export function createRecommendCommand(): Command {
  return new Command("recommend")
    .description(
      "Output platform-specific config snippet for installing Rafter"
    )
    .argument("[platform]", "Target platform (claude-code, gemini, cursor, windsurf, codex, aider, continue, generic)")
    .option("--json", "Output as JSON")
    .option("--all", "Show snippets for all detected platforms")
    .action(async (platformArg: string | undefined, opts: { json?: boolean; all?: boolean }) => {
      const agent = isAgentMode();

      // If --all, show all detected platforms
      if (opts.all) {
        const detected = detectPlatforms();
        if (detected.length === 0) {
          const generic = getSnippet("generic");
          if (opts.json) {
            console.log(JSON.stringify({ platforms: [{ platform: "generic", ...generic }] }, null, 2));
          } else {
            console.log(agent
              ? "No agent platforms detected. Use the generic snippet:"
              : fmt.warning("No agent platforms detected. Use the generic snippet:"));
            console.log();
            console.log(formatPlatformOutput(generic, agent));
          }
          return;
        }

        if (opts.json) {
          const results = detected.map((p) => ({
            platform: p,
            ...getSnippet(p),
          }));
          console.log(JSON.stringify({ platforms: results }, null, 2));
          return;
        }

        for (const p of detected) {
          const info = getSnippet(p);
          console.log(formatPlatformOutput(info, agent));
          console.log();
        }
        return;
      }

      // Single platform mode
      let target: Platform;
      if (platformArg) {
        const valid: Platform[] = [
          "claude-code", "gemini", "cursor", "windsurf",
          "codex", "aider", "continue", "generic",
        ];
        if (!valid.includes(platformArg as Platform)) {
          console.error(
            agent
              ? `[ERROR] Unknown platform: ${platformArg}. Valid: ${valid.join(", ")}`
              : fmt.error(`Unknown platform: ${platformArg}. Valid: ${valid.join(", ")}`)
          );
          process.exit(1);
        }
        target = platformArg as Platform;
      } else {
        // Auto-detect: pick the first detected platform, or generic
        const detected = detectPlatforms();
        target = detected.length > 0 ? detected[0] : "generic";
        if (!agent && detected.length > 1) {
          console.error(
            fmt.info(
              `Multiple platforms detected (${detected.join(", ")}). Showing ${detected[0]}. Use --all or specify a platform.`
            )
          );
          console.error();
        }
      }

      const info = getSnippet(target);

      if (opts.json) {
        console.log(JSON.stringify({ platform: target, ...info }, null, 2));
        return;
      }

      console.log(formatPlatformOutput(info, agent));
    });
}
