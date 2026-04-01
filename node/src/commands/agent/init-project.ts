import { Command } from "commander";
import { ConfigManager } from "../../core/config-manager.js";
import { injectInstructionFile } from "./instruction-block.js";
import { fmt } from "../../utils/formatter.js";
import fs from "fs";
import path from "path";
import { execSync } from "child_process";

/** Find the git root directory, or null if not in a git repo */
function findGitRoot(): string | null {
  try {
    return execSync("git rev-parse --show-toplevel", {
      encoding: "utf-8",
      timeout: 5000,
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();
  } catch {
    return null;
  }
}

/**
 * All project-level instruction file targets.
 *
 * These are files that AI agents read at session start when working in a project.
 * Unlike global files (~/.claude/CLAUDE.md), these live in the repo and are
 * committed alongside the code so every agent session sees them.
 */
function getProjectTargets(projectRoot: string): Array<{
  platform: string;
  filePath: string;
  description: string;
}> {
  return [
    {
      platform: "Claude Code",
      filePath: path.join(projectRoot, ".claude", "CLAUDE.md"),
      description: "Claude Code project instructions",
    },
    {
      platform: "Codex CLI",
      filePath: path.join(projectRoot, "AGENTS.md"),
      description: "Codex CLI project instructions",
    },
    {
      platform: "Gemini CLI",
      filePath: path.join(projectRoot, "GEMINI.md"),
      description: "Gemini CLI project instructions",
    },
    {
      platform: "Cursor",
      filePath: path.join(projectRoot, ".cursor", "rules", "rafter-security.mdc"),
      description: "Cursor project rules",
    },
    {
      platform: "Windsurf",
      filePath: path.join(projectRoot, ".windsurfrules"),
      description: "Windsurf project rules",
    },
    {
      platform: "Continue.dev",
      filePath: path.join(projectRoot, ".continuerules"),
      description: "Continue.dev project rules",
    },
    {
      platform: "Aider",
      filePath: path.join(projectRoot, ".aider", "conventions.md"),
      description: "Aider project conventions",
    },
  ];
}

export function createInitProjectCommand(): Command {
  return new Command("init-project")
    .description("Generate project-level instruction files so AI agents discover Rafter at session start")
    .option("--only <platforms>", "Comma-separated list of platforms (claude-code,codex,gemini,cursor,windsurf,continue,aider)")
    .option("--list", "List which files would be created without writing them")
    .action(async (opts) => {
      const gitRoot = findGitRoot();
      if (!gitRoot) {
        console.error(fmt.error("Not in a git repository. Run this command from inside a project."));
        process.exit(1);
      }

      console.log(fmt.header("Rafter Project Setup"));
      console.log(fmt.info(`Project root: ${gitRoot}`));
      console.log();

      const allTargets = getProjectTargets(gitRoot);

      // Filter by --only if specified
      let targets = allTargets;
      if (opts.only) {
        const platformMap: Record<string, string> = {
          "claude-code": "Claude Code",
          "claude": "Claude Code",
          "codex": "Codex CLI",
          "gemini": "Gemini CLI",
          "cursor": "Cursor",
          "windsurf": "Windsurf",
          "continue": "Continue.dev",
          "aider": "Aider",
        };
        const requested = (opts.only as string).split(",").map((s: string) => s.trim().toLowerCase());
        const platformNames = requested.map(r => platformMap[r]).filter(Boolean);
        if (platformNames.length === 0) {
          console.error(fmt.error(`Unknown platforms: ${opts.only}`));
          console.error("Valid: claude-code, codex, gemini, cursor, windsurf, continue, aider");
          process.exit(1);
        }
        targets = allTargets.filter(t => platformNames.includes(t.platform));
      }

      // --list mode: show what would be created
      if (opts.list) {
        for (const target of targets) {
          const exists = fs.existsSync(target.filePath);
          const hasMarker = exists && fs.readFileSync(target.filePath, "utf-8").includes("<!-- rafter:start -->");
          const status = hasMarker ? "update" : exists ? "append" : "create";
          const rel = path.relative(gitRoot, target.filePath);
          console.log(`  [${status}]  ${rel} — ${target.description}`);
        }
        console.log();
        console.log(fmt.info("Run without --list to write files."));
        return;
      }

      // Write instruction files
      let created = 0;
      let updated = 0;
      let failed = 0;

      for (const target of targets) {
        const rel = path.relative(gitRoot, target.filePath);
        const existed = fs.existsSync(target.filePath);
        const hadMarker = existed && fs.readFileSync(target.filePath, "utf-8").includes("<!-- rafter:start -->");

        try {
          injectInstructionFile(target.filePath);
          if (hadMarker) {
            console.log(fmt.success(`[updated]  ${rel}`));
            updated++;
          } else {
            console.log(fmt.success(`[created]  ${rel}`));
            created++;
          }
        } catch (e) {
          console.log(fmt.error(`[failed]   ${rel} — ${e}`));
          failed++;
        }
      }

      // Check for .rafter.yml
      const policyPath = path.join(gitRoot, ".rafter.yml");
      if (!fs.existsSync(policyPath)) {
        console.log(fmt.info(`[skipped]  .rafter.yml — not found (optional: create one for project-specific policy)`));
      }

      // Check for pre-commit hook
      const hookPath = path.join(gitRoot, ".git", "hooks", "pre-commit");
      const hasRafterHook = fs.existsSync(hookPath) &&
        fs.readFileSync(hookPath, "utf-8").includes("rafter");
      if (!hasRafterHook) {
        console.log(fmt.info(`[hint]     Run \`rafter agent install-hook\` to add pre-commit secret scanning`));
      }

      console.log();
      if (created > 0 || updated > 0) {
        console.log(fmt.success(`Done: ${created} created, ${updated} updated${failed > 0 ? `, ${failed} failed` : ""}`));
        console.log();
        console.log("Agents starting sessions in this project will now see Rafter security context.");
        console.log("Consider committing these files so all contributors benefit.");
      } else if (failed > 0) {
        console.log(fmt.error(`All ${failed} files failed to write.`));
      }
      console.log();
    });
}
