import { Command } from "commander";
import fs from "fs";
import os from "os";
import path from "path";
import { fmt } from "../../utils/formatter.js";
import { RAFTER_MARKER_START } from "./instruction-block.js";
import {
  InstallSession,
  RULE_SKILLS,
  WHOLE_FILE_PLATFORMS,
  cliVersion,
  manifestPath,
  NEW_VERSION_SUFFIX,
  platformArtifacts,
  reconcileInstruction,
} from "./install-files.js";
import { KNOWN_SKILL_NAMES } from "../skill/registry.js";

/**
 * `rafter agent update`: re-apply every rafter integration that is already
 * installed, using this CLI's skills, rules, instruction blocks, hooks and
 * MCP entries. Platforms come from the install manifest and from rafter's own
 * files on disk (installs made before the manifest existed have only the
 * latter); a platform the user never installed is never added. The work is
 * `agent init` itself (runAgentInit) with those platforms' --with flags.
 * Mirrors python/rafter_cli/commands/agent_update.py.
 */

export type UpdatePlatform =
  | "claude-code" | "codex" | "gemini" | "cursor" | "windsurf" | "continue"
  | "aider" | "hermes" | "opencode" | "openclaw";

/** init's --with-<platform> option, as commander names it. */
const INIT_FLAG: Record<UpdatePlatform, string> = {
  "claude-code": "withClaudeCode",
  codex: "withCodex",
  gemini: "withGemini",
  cursor: "withCursor",
  windsurf: "withWindsurf",
  continue: "withContinue",
  aider: "withAider",
  hermes: "withHermes",
  opencode: "withOpencode",
  openclaw: "withOpenclaw",
};

const USER_ONLY: readonly UpdatePlatform[] = ["hermes", "opencode", "openclaw"];

function contains(file: string, needle: string): boolean {
  try {
    return fs.readFileSync(file, "utf-8").includes(needle);
  } catch {
    return false;
  }
}

function readManifestPlatforms(root: string): Set<string> {
  try {
    const doc = JSON.parse(fs.readFileSync(manifestPath(root), "utf-8"));
    return new Set(Object.values(doc?.files ?? {}).map((e: any) => String(e?.platform ?? "")));
  } catch {
    return new Set();
  }
}

/**
 * Platforms rafter is installed for under `root`. A platform counts when the
 * manifest lists a file for it or rafter's own entries are on disk: its
 * skills, rules or sub-agent, its marker block, or a rafter hook / MCP entry
 * in its config (the same signals `agent list` and `agent verify` read).
 */
export function detectInstalledPlatforms(root: string, scope: "user" | "project"): UpdatePlatform[] {
  const p = (...parts: string[]) => path.join(root, ...parts);
  const anyExists = (paths: string[]) => paths.some((f) => fs.existsSync(f));
  const marker = (f: string) => contains(f, RAFTER_MARKER_START);
  const skillFiles = (dir: string) => KNOWN_SKILL_NAMES.map((n) => p(dir, "skills", n, "SKILL.md"));
  const rules = (dir: string, ext: string) => RULE_SKILLS.map((n) => p(dir, "rules", `${n}${ext}`));
  const user = scope === "user";
  const recorded = readManifestPlatforms(root);

  const signals: Record<UpdatePlatform, () => boolean> = {
    "claude-code": () =>
      contains(p(".claude", "settings.json"), "hook pretool") ||
      anyExists([...skillFiles(".claude"), p(".claude", "agents", "rafter.md")]) ||
      marker(p(".claude", "CLAUDE.md")),
    codex: () =>
      contains(p(".codex", "hooks.json"), "hook pretool") ||
      (user && marker(p(".codex", "AGENTS.md"))),
    gemini: () =>
      contains(p(".gemini", "settings.json"), "rafter") ||
      marker(user ? p(".gemini", "GEMINI.md") : p("GEMINI.md")),
    cursor: () =>
      anyExists([...rules(".cursor", ".mdc"), p(".cursor", "agents", "rafter.md")]) ||
      contains(p(".cursor", "hooks.json"), "hook pretool") ||
      contains(p(".cursor", "mcp.json"), '"rafter"'),
    windsurf: () =>
      anyExists(rules(".windsurf", ".md")) ||
      (user && contains(p(".codeium", "windsurf", "mcp_config.json"), '"rafter"')),
    continue: () =>
      anyExists(rules(".continue", ".md")) ||
      (user && contains(p(".continue", "config.json"), '"rafter"')),
    aider: () => marker(p("RAFTER.md")) || contains(p(".aider.conf.yml"), "RAFTER.md"),
    hermes: () => contains(p(".hermes", "config.yaml"), "rafter"),
    opencode: () => contains(p(".config", "opencode", "opencode.json"), '"rafter"'),
    openclaw: () => fs.existsSync(p(".openclaw", "workspace", "skills", "rafter-security", "SKILL.md")),
  };

  return (Object.keys(signals) as UpdatePlatform[]).filter(
    (name) => !(scope === "project" && USER_ONLY.includes(name)) && (recorded.has(name) || signals[name]()),
  );
}

export interface InstallStaleness {
  stale: boolean;
  /** cliVersion from the install manifest; null when there is none. */
  installedVersion: string | null;
  cliVersion: string;
  /** Installed rafter files whose content is older than what this CLI ships. */
  outdatedFiles: number;
  /** Installed files the user modified that have a newer version waiting in <file>.rafter-new. */
  needsReconcile: string[];
  platforms: UpdatePlatform[];
}

export function versionOlder(a: string, b: string): boolean {
  const parse = (v: string) => v.match(/^(\d+)\.(\d+)\.(\d+)/)?.slice(1).map(Number);
  const x = parse(a);
  const y = parse(b);
  if (!x || !y) return false;
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i];
  return false;
}

/**
 * Whether what is installed under `root` is older than what this CLI ships.
 * Stale when the manifest names an older CLI version, when any installed
 * rafter file would be updated (an unmodified older copy, by manifest or
 * shipped hash), or when rafter's files are present with no manifest at all
 * (they predate install records). Files the user modified do not count. No
 * network, no writes.
 */
export function installStaleness(root: string, scope: "user" | "project"): InstallStaleness {
  const version = cliVersion();
  const platforms = detectInstalledPlatforms(root, scope);
  const silent = { info: () => {}, warn: () => {} };
  const session = new InstallSession({ root, out: silent, dryRun: true, version });
  let installedVersion: string | null = null;
  let hasRecord = false;
  try {
    const doc = JSON.parse(fs.readFileSync(manifestPath(root), "utf-8"));
    // A manifest with no cliVersion was written only by the hook's
    // auto-update: the files are recorded, the install as a whole is not.
    if (doc && typeof doc.files === "object" && typeof doc.cliVersion === "string") {
      hasRecord = true;
      installedVersion = doc.cliVersion;
    }
  } catch {
    /* no usable record */
  }
  let outdatedFiles = 0;
  let presentFiles = 0;
  for (const platform of WHOLE_FILE_PLATFORMS) {
    if (!platforms.includes(platform)) continue;
    for (const a of platformArtifacts(platform, root)) {
      if (fs.existsSync(a.dest)) presentFiles++;
      if (session.apply(a) === "updated") outdatedFiles++;
    }
  }
  const stale =
    outdatedFiles > 0 ||
    (installedVersion !== null && versionOlder(installedVersion, version)) ||
    (!hasRecord && presentFiles > 0);
  return { stale, installedVersion, cliVersion: version, outdatedFiles, needsReconcile: session.keptFiles(), platforms };
}

/** The one line verify / status print when the install is stale. */
export function stalenessLine(s: InstallStaleness): string {
  const from = s.installedVersion ? `installed by rafter ${s.installedVersion}` : "installed before rafter kept an install record";
  const files = s.outdatedFiles > 0 ? `, ${s.outdatedFiles} file${s.outdatedFiles === 1 ? "" : "s"} older than this CLI ships` : "";
  return `Rafter integrations are out of date (${from}; this CLI is ${s.cliVersion}${files}). Run: rafter agent update`;
}

/** The lines verify / status print for modified files waiting on the user: each file, then how to reconcile. */
export function reconcileLines(s: InstallStaleness, updateCommand: string = "rafter agent update"): string[] {
  if (s.needsReconcile.length === 0) return [];
  const n = s.needsReconcile.length;
  return [
    `${n} rafter file${n === 1 ? "" : "s"} you modified ${n === 1 ? "has" : "have"} a newer version waiting:`,
    ...s.needsReconcile.map((f) => `  ${f}  (new: ${f}${NEW_VERSION_SUFFIX})`),
    reconcileInstruction(updateCommand),
  ];
}

export function createUpdateCommand(): Command {
  return new Command("update")
    .description("Re-apply every installed rafter integration (skills, rules, instructions, hooks, MCP) with this version")
    .option("--local", "Update the project-local install in the current directory instead of the user-global one")
    .option("--dry-run", "Print what would change, per file, without writing anything")
    .option(
      "--force",
      "Replace installed skill, rule and sub-agent files even if you modified them (the old file is saved as <file>.bak)",
      false,
    )
    .option("--quiet", "Suppress informational and success output (warnings and errors still go to stderr)", false)
    .action(async (opts) => {
      const root = opts.local ? process.cwd() : os.homedir();
      const scope = opts.local ? "project" : "user";
      const platforms = detectInstalledPlatforms(root, scope);
      if (platforms.length === 0) {
        if (!opts.quiet) {
          console.log(fmt.info(`No rafter integrations found under ${root}; nothing to update.`));
          console.log(fmt.info(`To install, run: rafter agent init${opts.local ? " --local" : ""} --with-<platform>`));
        }
        return;
      }
      const flags = Object.fromEntries(platforms.map((p) => [INIT_FLAG[p], true]));
      // Loaded here, not at the top: the pretool hook imports this module for
      // detectInstalledPlatforms and must not pay for init's dependencies.
      const { runAgentInit } = await import("./init.js");
      await runAgentInit({
        ...flags,
        local: opts.local,
        dryRun: opts.dryRun,
        force: opts.force,
        quiet: opts.quiet,
        mode: "update",
      });
    });
}
