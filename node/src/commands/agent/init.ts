import { Command } from "commander";
import { ConfigManager } from "../../core/config-manager.js";
import { getRafterDir } from "../../core/config-defaults.js";
import { BinaryManager } from "../../utils/binary-manager.js";
import { SkillScannerInstaller, SKILL_SCANNER_VERSION } from "../../scanners/skill-scanner.js";
import { SkillManager } from "../../utils/skill-manager.js";
import fs from "fs";
import path from "path";
import os from "os";
import { execSync } from "child_process";
import { fileURLToPath } from "url";
import { createRequire } from "module";
import { askYesNo } from "../../utils/prompt.js";
import { fmt } from "../../utils/formatter.js";
import { injectInstructionFile } from "./instruction-block.js";
import yaml from "js-yaml";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Skills installed by `rafter agent init` for Claude Code / Codex.
 *
 * Sourced from `resources/skills/<name>/SKILL.md` in the shipped package.
 * Keep this list in sync with Python's installer and the skills that actually
 * ship in both resources/skills/ trees.
 */
const AGENT_SKILLS: { name: string; description: string }[] = [
  { name: "rafter", description: "Rafter Remote" },
  { name: "rafter-secure-design", description: "Rafter Secure Design" },
  { name: "rafter-code-review", description: "Rafter Code Review" },
];

/**
 * Print every file path the install would touch — without writing anything.
 *
 * Lists are derived from the resolved want* booleans (which already account
 * for --all, --with-*, detection, and --local scope), so the printed plan
 * mirrors exactly what the install path would do. Implements rf-hrtd.
 */
function printDryRunPlan(plan: {
  root: string;
  scope: "user" | "project";
  wantOpenClaw: boolean;
  wantClaudeCode: boolean;
  wantCodex: boolean;
  wantGemini: boolean;
  wantCursor: boolean;
  wantWindsurf: boolean;
  wantContinue: boolean;
  wantAider: boolean;
  wantHermes: boolean;
  wantOpenCode: boolean;
  wantBetterleaks: boolean;
  wantSkillScanner: boolean;
  riskLevel: string;
}): void {
  const home = os.homedir();
  let writeCount = 0;
  let downloadCount = 0;

  const W = (p: string, note?: string) => {
    writeCount++;
    console.log(`  WRITE     ${p}${note ? `   (${note})` : ""}`);
  };
  const D = (p: string, note?: string) => {
    downloadCount++;
    console.log(`  DOWNLOAD  ${p}${note ? `   (${note})` : ""}`);
  };
  const R = (p: string, note?: string) => {
    console.log(`  REMOVE    ${p}${note ? `   (${note})` : ""}`);
  };

  console.log();
  console.log(fmt.info("DRY RUN — no files will be created or modified."));
  console.log(fmt.info(`Scope: ${plan.scope}${plan.scope === "project" ? ` (cwd: ${plan.root})` : ""}`));
  console.log();
  console.log(fmt.divider());
  console.log("Always:");
  W(path.join(home, ".rafter", "config.json"), `riskLevel: ${plan.riskLevel}`);
  W(path.join(home, ".rafter", "bin/"), "directory");
  W(path.join(home, ".rafter", "patterns/"), "directory");

  if (plan.wantBetterleaks) {
    console.log();
    console.log("Betterleaks (--with-betterleaks / --all):");
    D(path.join(home, ".rafter", "bin", "betterleaks"), "binary, ~12MB from GitHub releases");
  }

  if (plan.wantSkillScanner) {
    console.log();
    console.log("skill-scanner deep engine (--with-skill-scanner):");
    D("skill-scanner", "heavy PyPI package, isolated install via uv tool / pip --user");
  }

  if (plan.wantClaudeCode) {
    console.log();
    console.log("Claude Code (--with-claude-code):");
    W(path.join(plan.root, ".claude", "settings.json"), "PreToolUse + PostToolUse hooks merged");
    for (const s of ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"]) {
      W(path.join(plan.root, ".claude", "skills", s, "SKILL.md"));
    }
    W(path.join(plan.root, ".claude", "agents", "rafter.md"), "sub-agent");
    W(path.join(plan.root, ".claude", "CLAUDE.md"), "rafter:start/end marker block");
    W(path.join(plan.root, ".mcp.json"), "project-scope MCP config");
  }

  if (plan.wantCodex) {
    console.log();
    console.log("Codex CLI (--with-codex):");
    W(path.join(plan.root, ".codex", "hooks.json"), "PreToolUse: Bash|apply_patch, PostToolUse: .*");
    for (const s of AGENT_SKILLS) {
      W(path.join(plan.root, ".agents", "skills", s.name, "SKILL.md"));
    }
    const agentsMd = plan.scope === "user" ? path.join(plan.root, ".codex", "AGENTS.md") : path.join(plan.root, "AGENTS.md");
    W(agentsMd, "shared with Windsurf when --with-windsurf");
  }

  if (plan.wantGemini) {
    console.log();
    console.log("Gemini CLI (--with-gemini):");
    W(path.join(plan.root, ".gemini", "settings.json"), "MCP + BeforeTool/AfterTool hooks");
    for (const s of AGENT_SKILLS) {
      W(path.join(plan.root, ".agents", "skills", s.name, "SKILL.md"), "shared with Codex");
    }
    const geminiMd = plan.scope === "user" ? path.join(plan.root, ".gemini", "GEMINI.md") : path.join(plan.root, "GEMINI.md");
    W(geminiMd);
    if (plan.scope === "user") {
      console.log(`  EXEC      gemini skills link ${path.join(plan.root, ".agents", "skills", "rafter")}   (per-skill, runtime registration)`);
    }
  }

  if (plan.wantCursor) {
    console.log();
    console.log("Cursor (--with-cursor):");
    W(path.join(plan.root, ".cursor", "hooks.json"), "preToolUse + postToolUse + beforeShellExecution");
    for (const s of ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"]) {
      W(path.join(plan.root, ".cursor", "rules", `${s}.mdc`));
    }
    W(path.join(plan.root, ".cursor", "agents", "rafter.md"), "sub-agent (Cursor reads .claude/agents/ too)");
    W(path.join(plan.root, ".cursor", "mcp.json"));
  }

  if (plan.wantWindsurf) {
    console.log();
    console.log("Windsurf (--with-windsurf):");
    if (plan.scope === "user") {
      W(path.join(home, ".codeium", "windsurf", "mcp_config.json"), "user-scope MCP only");
    }
    for (const s of ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"]) {
      W(path.join(plan.root, ".windsurf", "rules", `${s}.md`));
    }
    W(path.join(plan.root, "AGENTS.md"), "shared with Codex; idempotent if already written");
  }

  if (plan.wantContinue) {
    console.log();
    console.log("Continue.dev (--with-continue):");
    if (plan.scope === "user") {
      W(path.join(home, ".continue", "config.json"), "MCP entry; preserves existing keys");
    }
    for (const s of ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"]) {
      W(path.join(plan.root, ".continue", "rules", `${s}.md`));
    }
  }

  if (plan.wantAider) {
    console.log();
    console.log("Aider (--with-aider):");
    W(path.join(plan.root, "RAFTER.md"), "rafter:start/end marker block");
    W(path.join(plan.root, ".aider.conf.yml"), "appends RAFTER.md to read: list; strips legacy mcp-server-command line");
  }

  if (plan.wantHermes) {
    console.log();
    console.log("Hermes (--with-hermes):");
    W(path.join(plan.root, ".hermes", "config.yaml"), "mcp_servers.rafter entry merged into existing YAML");
  }

  if (plan.wantOpenCode) {
    console.log();
    console.log("OpenCode (--with-opencode):");
    W(path.join(plan.root, ".config", "opencode", "opencode.json"), "mcp.rafter local/stdio entry merged into existing JSON");
  }

  if (plan.wantOpenClaw) {
    console.log();
    console.log("OpenClaw (--with-openclaw):");
    W(path.join(home, ".openclaw", "workspace", "skills", "rafter-security", "SKILL.md"), "ClawHub-shape");
    R(path.join(home, ".openclaw", "skills", "rafter-security.md"), "legacy file from rafter ≤ 0.7.7, if present");
  }

  console.log();
  console.log(fmt.divider());
  console.log(fmt.info(`Plan: ${writeCount} write${writeCount === 1 ? "" : "s"}, ${downloadCount} download${downloadCount === 1 ? "" : "s"}.`));
  console.log(fmt.info("Re-run without --dry-run to apply."));
  console.log();
}

/**
 * Install instruction files for platforms that support them, at either user
 * or project scope.
 *
 * Path layout:
 *   Claude Code — user: ~/.claude/CLAUDE.md       project: <cwd>/.claude/CLAUDE.md
 *   Codex CLI  — user: ~/.codex/AGENTS.md        project: <cwd>/AGENTS.md
 *   Gemini CLI — user: ~/.gemini/GEMINI.md       project: <cwd>/GEMINI.md
 *   Cursor     — user: ~/.cursor/rules/…mdc       project: <cwd>/.cursor/rules/…mdc
 *
 * Codex (AGENTS.md) and Gemini (GEMINI.md) each have the same filename at
 * user and project scope — only the location differs — which is why scope
 * is passed in explicitly.
 *
 * Windsurf, Continue.dev, and Aider are project-only and handled by
 * `rafter agent init-project`.
 */
function installGlobalInstructions(
  platforms: {
    claudeCode?: boolean;
    codex?: boolean;
    gemini?: boolean;
    windsurf?: boolean;
  },
  root: string,
  scope: "user" | "project",
): void {
  // Claude Code — <root>/.claude/CLAUDE.md
  if (platforms.claudeCode) {
    try {
      const filePath = path.join(root, ".claude", "CLAUDE.md");
      injectInstructionFile(filePath);
      console.log(fmt.success(`Installed Rafter instructions to ${filePath}`));
    } catch (e) {
      console.log(fmt.warning(`Failed to write Claude Code instructions: ${e}`));
    }
  }

  // AGENTS.md — read natively by Codex AND Windsurf. Codex at user scope keeps
  // its own copy at ~/.codex/AGENTS.md; everything else (project scope, or any
  // scope where Windsurf is in play) writes <root>/AGENTS.md once.
  if (platforms.codex || platforms.windsurf) {
    try {
      const codexUser = scope === "user" && platforms.codex && !platforms.windsurf;
      const filePath = codexUser
        ? path.join(root, ".codex", "AGENTS.md")
        : path.join(root, "AGENTS.md");
      injectInstructionFile(filePath);
      const readers = [platforms.codex && "Codex", platforms.windsurf && "Windsurf"]
        .filter(Boolean)
        .join(" + ");
      console.log(fmt.success(`Installed Rafter instructions for ${readers} to ${filePath}`));
    } catch (e) {
      console.log(fmt.warning(`Failed to write AGENTS.md: ${e}`));
    }
  }

  // Gemini — ~/.gemini/GEMINI.md (user) or <cwd>/GEMINI.md (project)
  if (platforms.gemini) {
    try {
      const filePath = scope === "user"
        ? path.join(root, ".gemini", "GEMINI.md")
        : path.join(root, "GEMINI.md");
      injectInstructionFile(filePath);
      console.log(fmt.success(`Installed Rafter instructions to ${filePath}`));
    } catch (e) {
      console.log(fmt.warning(`Failed to write Gemini instructions: ${e}`));
    }
  }

  // Cursor uses per-skill rules at <root>/.cursor/rules/<skill>.mdc and the
  // rafter sub-agent at <root>/.cursor/agents/rafter.md (installed in the
  // Cursor branch above). The consolidated rafter-security.mdc was retired
  // in rf-svn3 in favor of per-skill rules with trigger-first descriptions.
}

function installClaudeCodeHooks(root: string): void {
  const settingsPath = path.join(root, ".claude", "settings.json");
  const claudeDir = path.join(root, ".claude");

  if (!fs.existsSync(claudeDir)) {
    fs.mkdirSync(claudeDir, { recursive: true });
  }

  // Read existing settings or start fresh
  let settings: Record<string, any> = {};
  if (fs.existsSync(settingsPath)) {
    try {
      settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    } catch {
      // Corrupted file — start fresh but warn
      console.log(fmt.warning("Existing settings.json was unreadable, creating new one"));
    }
  }

  // Merge hooks — don't overwrite existing non-Rafter hooks
  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];
  if (!settings.hooks.PostToolUse) settings.hooks.PostToolUse = [];

  const preHook = { type: "command", command: "rafter hook pretool" };
  const postHook = { type: "command", command: "rafter hook posttool" };

  // Remove any existing Rafter hooks to avoid duplicates
  settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter(
    (entry: any) => {
      const hooks = entry.hooks || [];
      return !hooks.some((h: any) => h.command === "rafter hook pretool");
    }
  );
  settings.hooks.PostToolUse = settings.hooks.PostToolUse.filter(
    (entry: any) => {
      const hooks = entry.hooks || [];
      return !hooks.some((h: any) => h.command === "rafter hook posttool");
    }
  );
  // Strip legacy SessionStart entry left over from <=0.7.4 installs.
  if (Array.isArray(settings.hooks.SessionStart)) {
    settings.hooks.SessionStart = settings.hooks.SessionStart.filter(
      (entry: any) => {
        const hooks = entry.hooks || [];
        return !hooks.some((h: any) => h.command === "rafter hook session-start");
      }
    );
    if (settings.hooks.SessionStart.length === 0) delete settings.hooks.SessionStart;
  }

  // Add Rafter hooks
  settings.hooks.PreToolUse.push(
    { matcher: "Bash", hooks: [preHook] },
    { matcher: "Write|Edit", hooks: [preHook] },
  );
  // Narrow to tools that produce scannable output (shell output + file
  // writes). Firing posttool on every tool — including Read and MCP calls —
  // added latency to operations that never produce secrets to redact.
  settings.hooks.PostToolUse.push(
    { matcher: "Bash|Write|Edit|MultiEdit", hooks: [postHook] },
  );

  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), "utf-8");
  console.log(fmt.success(`Installed PreToolUse hooks to ${settingsPath}`));
  console.log(fmt.success(`Installed PostToolUse hooks to ${settingsPath}`));
}

function installCodexHooks(root: string): void {
  const codexDir = path.join(root, ".codex");

  if (!fs.existsSync(codexDir)) {
    fs.mkdirSync(codexDir, { recursive: true });
  }

  const hooksPath = path.join(codexDir, "hooks.json");

  let config: Record<string, any> = {};
  if (fs.existsSync(hooksPath)) {
    try {
      config = JSON.parse(fs.readFileSync(hooksPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Codex hooks.json was unreadable, creating new one"));
    }
  }

  if (!config.hooks) config.hooks = {};
  if (!config.hooks.PreToolUse) config.hooks.PreToolUse = [];
  if (!config.hooks.PostToolUse) config.hooks.PostToolUse = [];

  // Codex uses the same hookSpecificOutput protocol as Claude Code (format=claude)
  const preHook = { type: "command", command: "rafter hook pretool" };
  const postHook = { type: "command", command: "rafter hook posttool" };

  // Remove existing rafter hooks
  config.hooks.PreToolUse = config.hooks.PreToolUse.filter(
    (entry: any) => !(entry.hooks || []).some((h: any) => h.command?.startsWith("rafter hook pretool"))
  );
  config.hooks.PostToolUse = config.hooks.PostToolUse.filter(
    (entry: any) => !(entry.hooks || []).some((h: any) => h.command?.startsWith("rafter hook posttool"))
  );

  // PreToolUse intercepts the tools Codex documents support for: Bash and
  // apply_patch (file edits). Per developers.openai.com/codex/hooks PreToolUse
  // also covers MCP tool calls via patterns like `mcp__<server>__<tool>` —
  // when an MCP server is wired up, install a separate matcher for it.
  // (rf-ovql verification 2026-05-03.)
  config.hooks.PreToolUse.push(
    { matcher: "Bash|apply_patch", hooks: [preHook] },
  );
  // PostToolUse fires for the same tool surface; .* keeps all events in the
  // audit log without filtering.
  config.hooks.PostToolUse.push(
    { matcher: ".*", hooks: [postHook] },
  );

  fs.writeFileSync(hooksPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed hooks to ${hooksPath}`));
}

/**
 * Install Cursor hooks at <root>/.cursor/hooks.json.
 *
 * Covers the full pre/post-tool lifecycle plus shell-specific gating:
 *   - preToolUse           — rafter classifies every tool call
 *   - postToolUse          — rafter post-hook (audit, telemetry)
 *   - beforeShellExecution — narrower complement; some Cursor versions
 *                            fire this without firing preToolUse for shell.
 *
 * Idempotent — repeated installs do not duplicate rafter entries.
 * Non-rafter entries (other tools' hooks, unrelated events) are preserved.
 */
function installCursorHooks(root: string): void {
  const cursorDir = path.join(root, ".cursor");

  if (!fs.existsSync(cursorDir)) {
    fs.mkdirSync(cursorDir, { recursive: true });
  }

  const hooksPath = path.join(cursorDir, "hooks.json");

  let config: Record<string, any> = {};
  if (fs.existsSync(hooksPath)) {
    try {
      config = JSON.parse(fs.readFileSync(hooksPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Cursor hooks.json was unreadable, creating new one"));
    }
  }

  if (!config.version) config.version = 1;
  if (!config.hooks) config.hooks = {};

  const events: { event: string; command: string }[] = [
    { event: "preToolUse", command: "rafter hook pretool --format cursor" },
    { event: "postToolUse", command: "rafter hook posttool --format cursor" },
    { event: "beforeShellExecution", command: "rafter hook pretool --format cursor" },
  ];

  for (const { event, command } of events) {
    if (!Array.isArray(config.hooks[event])) config.hooks[event] = [];
    config.hooks[event] = config.hooks[event].filter(
      (entry: any) => !entry?.command?.includes("rafter hook"),
    );
    config.hooks[event].push({ command, type: "command", timeout: 5000 });
  }

  fs.writeFileSync(hooksPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed hooks to ${hooksPath}`));
}

/** Skills shipped as both Cursor rules and (Claude Code / Codex / Gemini) skills. */
const CURSOR_RULE_SKILLS = [
  "rafter",
  "rafter-secure-design",
  "rafter-code-review",
  "rafter-skill-review",
] as const;

/**
 * Install per-skill Cursor rules at <root>/.cursor/rules/<skill>.mdc.
 *
 * One file per shipped skill. Each rule's frontmatter description is reused
 * verbatim from the skill's SKILL.md frontmatter (trigger-first phrasing per
 * rf-4ei / rf-8po) so Cursor surfaces it on the same triggers as Claude Code.
 *
 * Replaces the legacy consolidated `.cursor/rules/rafter-security.mdc` — that
 * single file is no longer written by the Cursor install path.
 */
function installCursorRules(root: string): void {
  const rulesDir = path.join(root, ".cursor", "rules");
  fs.mkdirSync(rulesDir, { recursive: true });

  // Resolve resources/cursor-rules relative to this module.
  // After build: dist/commands/agent/init.js -> ../../../resources/cursor-rules
  const candidates = [
    path.resolve(__dirname, "..", "..", "..", "resources", "cursor-rules"),
    path.resolve(__dirname, "..", "..", "resources", "cursor-rules"),
  ];
  const sourceDir = candidates.find((p) => fs.existsSync(p));
  if (!sourceDir) {
    console.log(fmt.warning(`Cursor rule templates not found in resources/cursor-rules`));
    return;
  }

  for (const name of CURSOR_RULE_SKILLS) {
    const src = path.join(sourceDir, `${name}.mdc`);
    const dest = path.join(rulesDir, `${name}.mdc`);
    if (!fs.existsSync(src)) {
      console.log(fmt.warning(`Cursor rule template missing: ${src}`));
      continue;
    }
    fs.copyFileSync(src, dest);
    console.log(fmt.success(`Installed Cursor rule to ${dest}`));
  }

  // Remove the legacy consolidated rule if present, so reinstall on top of
  // an old layout migrates cleanly.
  const legacy = path.join(rulesDir, "rafter-security.mdc");
  if (fs.existsSync(legacy)) {
    try {
      fs.unlinkSync(legacy);
      console.log(fmt.info(`Removed legacy ${legacy} (superseded by per-skill rules)`));
    } catch {
      /* best-effort */
    }
  }
}

/**
 * Install Cursor sub-agent at <root>/.cursor/agents/rafter.md.
 *
 * Reuses the Claude-Code sub-agent body (rf-q7j) with one shape difference:
 * Cursor's frontmatter has no `tools:` field — tools inherit from the parent
 * agent. The hard rules in the body (no code modification, no commits) still
 * apply, since Cursor relies on prompt-level constraints rather than
 * structural restriction.
 */
function installCursorSubAgents(root: string): void {
  const agentsDir = path.join(root, ".cursor", "agents");
  fs.mkdirSync(agentsDir, { recursive: true });

  const candidates = [
    path.resolve(__dirname, "..", "..", "..", "resources", "agents", "rafter.md"),
    path.resolve(__dirname, "..", "..", "resources", "agents", "rafter.md"),
  ];
  const src = candidates.find((p) => fs.existsSync(p));
  if (!src) {
    console.log(fmt.warning(`Rafter sub-agent template not found in resources/agents`));
    return;
  }

  const raw = fs.readFileSync(src, "utf-8");
  const cursored = stripToolsFromFrontmatter(raw);

  const dest = path.join(agentsDir, "rafter.md");
  fs.writeFileSync(dest, cursored, "utf-8");
  console.log(fmt.success(`Installed Cursor sub-agent to ${dest}`));
}

/** Strip the Claude-Code `tools:` line from sub-agent frontmatter — Cursor doesn't have it. */
function stripToolsFromFrontmatter(content: string): string {
  if (!content.startsWith("---\n")) return content;
  const fmEnd = content.indexOf("\n---", 4);
  if (fmEnd === -1) return content;
  const frontmatter = content.slice(4, fmEnd);
  const body = content.slice(fmEnd);
  const cleaned = frontmatter
    .split("\n")
    .filter((line) => !/^tools:\s/.test(line))
    .join("\n");
  return `---\n${cleaned}${body}`;
}

function installGeminiHooks(root: string): void {
  const geminiDir = path.join(root, ".gemini");

  if (!fs.existsSync(geminiDir)) {
    fs.mkdirSync(geminiDir, { recursive: true });
  }

  const settingsPath = path.join(geminiDir, "settings.json");

  let settings: Record<string, any> = {};
  if (fs.existsSync(settingsPath)) {
    try {
      settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Gemini settings.json was unreadable, creating new one"));
    }
  }

  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.BeforeTool) settings.hooks.BeforeTool = [];
  if (!settings.hooks.AfterTool) settings.hooks.AfterTool = [];

  // Remove existing rafter hooks
  settings.hooks.BeforeTool = settings.hooks.BeforeTool.filter(
    (entry: any) => !(entry.hooks || []).some((h: any) => h.command?.includes("rafter hook pretool"))
  );
  settings.hooks.AfterTool = settings.hooks.AfterTool.filter(
    (entry: any) => !(entry.hooks || []).some((h: any) => h.command?.includes("rafter hook posttool"))
  );

  // Gemini matchers are regexes against built-in tool names per
  // geminicli.com/docs/hooks/reference. Match the mutating tools by name
  // explicitly: run_shell_command, write_file, replace, edit. (rf-044o
  // verification 2026-05-03 — schema confirmed against current Gemini docs.)
  settings.hooks.BeforeTool.push({
    matcher: "run_shell_command|write_file|replace|edit",
    hooks: [{ type: "command", command: "rafter hook pretool --format gemini", timeout: 5000 }],
  });
  settings.hooks.AfterTool.push({
    matcher: ".*",
    hooks: [{ type: "command", command: "rafter hook posttool --format gemini", timeout: 5000 }],
  });

  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), "utf-8");
  console.log(fmt.success(`Installed hooks to ${settingsPath}`));
}

/** Skills shipped as Windsurf per-workspace rules at .windsurf/rules/<skill>.md (rf-0vr3). */
const WINDSURF_RULE_SKILLS = [
  "rafter",
  "rafter-secure-design",
  "rafter-code-review",
  "rafter-skill-review",
] as const;

/**
 * Install per-skill Windsurf rules at <root>/.windsurf/rules/<skill>.md.
 *
 * Windsurf reads workspace rules from .windsurf/rules/*.md (12KB cap per file
 * per docs). Each file uses Windsurf YAML frontmatter (`trigger: model_decision`
 * + `description:`) so the agent fetches the rule when its description matches
 * the task. Body content mirrors the Cursor pointer-rule pattern.
 *
 * Replaces the prior `~/.windsurf/hooks.json` install, which was a silent
 * no-op — Windsurf has no documented hook surface as of v1.x (research bead
 * rf-s1n3, gap reports rf-p1ri / rf-vayl).
 */
function installWindsurfRules(root: string): void {
  const rulesDir = path.join(root, ".windsurf", "rules");
  fs.mkdirSync(rulesDir, { recursive: true });

  const candidates = [
    path.resolve(__dirname, "..", "..", "..", "resources", "windsurf-rules"),
    path.resolve(__dirname, "..", "..", "resources", "windsurf-rules"),
  ];
  const sourceDir = candidates.find((p) => fs.existsSync(p));
  if (!sourceDir) {
    console.log(fmt.warning(`Windsurf rule templates not found in resources/windsurf-rules`));
    return;
  }

  for (const name of WINDSURF_RULE_SKILLS) {
    const src = path.join(sourceDir, `${name}.md`);
    const dest = path.join(rulesDir, `${name}.md`);
    if (!fs.existsSync(src)) {
      console.log(fmt.warning(`Windsurf rule template missing: ${src}`));
      continue;
    }
    fs.copyFileSync(src, dest);
    console.log(fmt.success(`Installed Windsurf rule to ${dest}`));
  }
}


/** MCP server entry for rafter — shared across MCP-native clients */
const RAFTER_MCP_ENTRY = {
  command: "rafter",
  args: ["mcp", "serve"],
};

/**
 * Install MCP server config for Claude Code (<root>/.mcp.json).
 * Project-scope MCP config that Claude Code auto-loads on startup.
 */
function installClaudeCodeMcp(root: string): boolean {
  const mcpPath = path.join(root, ".mcp.json");

  let config: Record<string, any> = {};
  if (fs.existsSync(mcpPath)) {
    try {
      config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing .mcp.json was unreadable, creating new one"));
    }
  }

  if (!config.mcpServers) config.mcpServers = {};
  config.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };

  fs.writeFileSync(mcpPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${mcpPath}`));
  return true;
}

/**
 * Install MCP server config for Gemini CLI (~/.gemini/settings.json)
 */
function installGeminiMcp(root: string): boolean {
  const geminiDir = path.join(root, ".gemini");
  const settingsPath = path.join(geminiDir, "settings.json");

  if (!fs.existsSync(geminiDir)) {
    fs.mkdirSync(geminiDir, { recursive: true });
  }

  let settings: Record<string, any> = {};
  if (fs.existsSync(settingsPath)) {
    try {
      settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Gemini settings.json was unreadable, creating new one"));
    }
  }

  if (!settings.mcpServers) settings.mcpServers = {};
  settings.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };

  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${settingsPath}`));
  return true;
}

/**
 * Install MCP server config for Cursor (~/.cursor/mcp.json)
 */
function installCursorMcp(root: string): boolean {
  const cursorDir = path.join(root, ".cursor");
  const mcpPath = path.join(cursorDir, "mcp.json");

  if (!fs.existsSync(cursorDir)) {
    fs.mkdirSync(cursorDir, { recursive: true });
  }

  let config: Record<string, any> = {};
  if (fs.existsSync(mcpPath)) {
    try {
      config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Cursor mcp.json was unreadable, creating new one"));
    }
  }

  if (!config.mcpServers) config.mcpServers = {};
  config.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };

  fs.writeFileSync(mcpPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${mcpPath}`));
  return true;
}

/**
 * Install MCP server config for Windsurf (~/.codeium/windsurf/mcp_config.json)
 */
function installWindsurfMcp(root: string): boolean {
  const windsurfDir = path.join(root, ".codeium", "windsurf");
  const mcpPath = path.join(windsurfDir, "mcp_config.json");

  if (!fs.existsSync(windsurfDir)) {
    fs.mkdirSync(windsurfDir, { recursive: true });
  }

  let config: Record<string, any> = {};
  if (fs.existsSync(mcpPath)) {
    try {
      config = JSON.parse(fs.readFileSync(mcpPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Windsurf mcp_config.json was unreadable, creating new one"));
    }
  }

  if (!config.mcpServers) config.mcpServers = {};
  config.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };

  fs.writeFileSync(mcpPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${mcpPath}`));
  return true;
}

/** Skills shipped as Continue.dev rules at .continue/rules/<skill>.md (rf-acz0). */
const CONTINUE_RULE_SKILLS = [
  "rafter",
  "rafter-secure-design",
  "rafter-code-review",
  "rafter-skill-review",
] as const;

/**
 * Install per-skill Continue.dev rules at <root>/.continue/rules/<skill>.md.
 *
 * Continue.dev reads workspace rules from .continue/rules/*.md (per-rule files,
 * lexicographic load order). Frontmatter: `name`, `description`, `alwaysApply`.
 * Each rule body mirrors the Cursor / Windsurf pointer-rule pattern.
 *
 * Continue.dev has no documented hook surface (the prior hooks install was
 * pruned in rf-cia phase b). Rules + MCP are the only intercepts.
 */
function installContinueDevRules(root: string): void {
  const rulesDir = path.join(root, ".continue", "rules");
  fs.mkdirSync(rulesDir, { recursive: true });

  const candidates = [
    path.resolve(__dirname, "..", "..", "..", "resources", "continue-rules"),
    path.resolve(__dirname, "..", "..", "resources", "continue-rules"),
  ];
  const sourceDir = candidates.find((p) => fs.existsSync(p));
  if (!sourceDir) {
    console.log(fmt.warning(`Continue.dev rule templates not found in resources/continue-rules`));
    return;
  }

  for (const name of CONTINUE_RULE_SKILLS) {
    const src = path.join(sourceDir, `${name}.md`);
    const dest = path.join(rulesDir, `${name}.md`);
    if (!fs.existsSync(src)) {
      console.log(fmt.warning(`Continue.dev rule template missing: ${src}`));
      continue;
    }
    fs.copyFileSync(src, dest);
    console.log(fmt.success(`Installed Continue.dev rule to ${dest}`));
  }
}

/**
 * Install MCP server config for Continue.dev (~/.continue/config.json)
 */
function installContinueDevMcp(root: string): boolean {
  const continueDir = path.join(root, ".continue");
  const configPath = path.join(continueDir, "config.json");

  if (!fs.existsSync(continueDir)) {
    fs.mkdirSync(continueDir, { recursive: true });
  }

  let config: Record<string, any> = {};
  if (fs.existsSync(configPath)) {
    try {
      config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    } catch {
      console.log(fmt.warning("Existing Continue.dev config.json was unreadable, creating new one"));
    }
  }

  if (!config.mcpServers) config.mcpServers = [];

  // Remove existing rafter entry if present (array format)
  if (Array.isArray(config.mcpServers)) {
    config.mcpServers = config.mcpServers.filter(
      (s: any) => s.name !== "rafter"
    );
    config.mcpServers.push({
      name: "rafter",
      command: RAFTER_MCP_ENTRY.command,
      args: RAFTER_MCP_ENTRY.args,
    });
  } else {
    // Object format (newer Continue.dev versions)
    config.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };
  }

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${configPath}`));
  return true;
}

/**
 * Install Rafter context for Aider (rf-du2o).
 *
 * Aider has no native MCP support and no plugin/hook surface. Its only
 * intercept-friendly persistent-context primitive is the `read:` flag in
 * `.aider.conf.yml`, which injects read-only files into every session.
 *
 * Behavior:
 *   1. Write `<root>/RAFTER.md` with the rafter instruction block.
 *   2. Update `<root>/.aider.conf.yml` so `read:` includes `RAFTER.md`
 *      (preserves any pre-existing `read:` entries; preserves other YAML keys).
 *   3. Strip the legacy `mcp-server-command: rafter mcp serve` line if present
 *      — it was a silent no-op in earlier rafter versions (Aider has no MCP).
 *
 * Returns true on success.
 */
/**
 * Install MCP server config for Hermes (<root>/.hermes/config.yaml).
 *
 * Hermes uses a YAML config with an `mcp_servers:` block (snake_case, unlike
 * Cursor/Windsurf/Claude Code which use `mcpServers` camelCase). Schema per
 * server is {command, args, env}. We use js-yaml (already a dep, used by
 * installAiderRead and elsewhere) to merge in the rafter entry while
 * preserving any existing servers.
 *
 * Hooks (preToolUse/postToolUse equivalents) deferred to a follow-on bead
 * pending confirmation Hermes exposes a hook surface — landing MCP-only as
 * v0 mirrors how Gemini and Continue.dev were initially shipped.
 */
function installHermesMcp(root: string): boolean {
  const hermesDir = path.join(root, ".hermes");
  const configPath = path.join(hermesDir, "config.yaml");

  if (!fs.existsSync(hermesDir)) {
    fs.mkdirSync(hermesDir, { recursive: true });
  }

  let config: Record<string, any> = {};
  if (fs.existsSync(configPath)) {
    const raw = fs.readFileSync(configPath, "utf-8");
    try {
      const loaded = yaml.load(raw);
      if (loaded && typeof loaded === "object" && !Array.isArray(loaded)) {
        config = loaded as Record<string, any>;
      }
    } catch {
      console.log(fmt.warning(`Existing Hermes config.yaml was not valid YAML, creating new one`));
    }
  }

  if (!config.mcp_servers || typeof config.mcp_servers !== "object" || Array.isArray(config.mcp_servers)) {
    config.mcp_servers = {};
  }
  config.mcp_servers.rafter = { ...RAFTER_MCP_ENTRY };

  fs.writeFileSync(configPath, yaml.dump(config), "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${configPath}`));
  return true;
}

/**
 * OpenCode MCP server entry. OpenCode's schema differs from Cursor/Windsurf:
 * the block is `mcp` (not `mcpServers`), each local server has `type: "local"`,
 * and the command + args are a single `command` array (not split). Verified
 * against https://opencode.ai/docs/mcp-servers/ (rf-opencode).
 */
const RAFTER_OPENCODE_MCP_ENTRY = {
  type: "local" as const,
  command: [RAFTER_MCP_ENTRY.command, ...RAFTER_MCP_ENTRY.args],
  enabled: true,
};

/**
 * Install MCP server config for OpenCode (~/.config/opencode/opencode.json).
 *
 * OpenCode reads a global config at ~/.config/opencode/opencode.json and a
 * project-level opencode.json (project takes precedence). We register the
 * local stdio server `rafter mcp serve` under the `mcp` block. The `$schema`
 * pointer is seeded on first write so editors get completion. Any existing
 * keys / other MCP servers are preserved.
 */
function installOpenCodeMcp(root: string): boolean {
  const openCodeDir = path.join(root, ".config", "opencode");
  const configPath = path.join(openCodeDir, "opencode.json");

  if (!fs.existsSync(openCodeDir)) {
    fs.mkdirSync(openCodeDir, { recursive: true });
  }

  let config: Record<string, any> = {};
  if (fs.existsSync(configPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(configPath, "utf-8"));
      // Guard against valid-but-non-object top-level JSON (array/string/number).
      // Mirrors the Python `isinstance(loaded, dict)` check so a wrong-shaped
      // file is replaced rather than silently mangled by property assignment.
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        config = parsed;
      } else {
        console.log(fmt.warning("Existing OpenCode opencode.json was not a JSON object, creating new one"));
      }
    } catch {
      console.log(fmt.warning("Existing OpenCode opencode.json was unreadable, creating new one"));
    }
  }

  if (!config.$schema) config.$schema = "https://opencode.ai/config.json";
  if (!config.mcp || typeof config.mcp !== "object" || Array.isArray(config.mcp)) {
    config.mcp = {};
  }
  config.mcp.rafter = { ...RAFTER_OPENCODE_MCP_ENTRY };

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), "utf-8");
  console.log(fmt.success(`Installed Rafter MCP server to ${configPath}`));
  return true;
}

function installAiderRead(root: string): boolean {
  const rafterMdPath = path.join(root, "RAFTER.md");
  const configPath = path.join(root, ".aider.conf.yml");
  const RAFTER_READ_ENTRY = "RAFTER.md";

  // 1. Write RAFTER.md (idempotent — the marker block is replaced in place).
  injectInstructionFile(rafterMdPath);

  // 2. Update .aider.conf.yml read: list.
  let raw = "";
  if (fs.existsSync(configPath)) {
    raw = fs.readFileSync(configPath, "utf-8");
  }

  // 2a. Strip the legacy mcp-server-command line(s). Match a contiguous block
  // that may include the preceding `# Rafter security MCP server` comment.
  raw = raw.replace(
    /\n?#\s*Rafter security MCP server\s*\nmcp-server-command:\s*rafter\s+mcp\s+serve\s*\n?/g,
    "\n",
  );
  raw = raw.replace(/^mcp-server-command:\s*rafter\s+mcp\s+serve\s*\n?/gm, "");

  // 2b. Parse remaining YAML, normalize read:.
  let parsed: Record<string, any> = {};
  if (raw.trim().length > 0) {
    try {
      const loaded = yaml.load(raw);
      if (loaded && typeof loaded === "object" && !Array.isArray(loaded)) {
        parsed = loaded as Record<string, any>;
      }
    } catch {
      console.log(fmt.warning(`Existing ${configPath} was not valid YAML — preserving raw content and appending read: entry`));
      // Append the read: line at the bottom rather than rewriting an
      // unparseable file. We still need to make sure RAFTER.md ends up in it.
      if (!new RegExp(`^read:\\s*\\[?[^\\n]*\\b${RAFTER_READ_ENTRY}\\b`, "m").test(raw)) {
        const sep = raw.length > 0 && !raw.endsWith("\n") ? "\n" : "";
        raw = `${raw}${sep}read:\n  - ${RAFTER_READ_ENTRY}\n`;
        fs.writeFileSync(configPath, raw, "utf-8");
      }
      console.log(fmt.success(`Installed Rafter read-only context to ${configPath}`));
      return true;
    }
  }

  // Normalize `read:` to a string array.
  let reads: string[] = [];
  if (Array.isArray(parsed.read)) {
    reads = parsed.read.map(String);
  } else if (typeof parsed.read === "string") {
    reads = [parsed.read];
  }

  if (!reads.includes(RAFTER_READ_ENTRY)) {
    reads.push(RAFTER_READ_ENTRY);
  }
  parsed.read = reads;

  fs.writeFileSync(configPath, yaml.dump(parsed), "utf-8");
  console.log(fmt.success(`Installed Rafter read-only context to ${rafterMdPath} + ${configPath}`));
  return true;
}

// Copies an entire skill source directory (SKILL.md + any subfolders like docs/)
// into the destination. Without this, `docs/` reference material referenced from
// SKILL.md would never reach users — only SKILL.md would.
function installSkillDir(sourceSkillDir: string, destSkillDir: string, label: string): void {
  const sourceSkillFile = path.join(sourceSkillDir, "SKILL.md");
  if (!fs.existsSync(sourceSkillFile)) {
    console.log(fmt.warning(`${label} skill template not found at ${sourceSkillFile}`));
    return;
  }
  fs.mkdirSync(destSkillDir, { recursive: true });
  fs.cpSync(sourceSkillDir, destSkillDir, { recursive: true });
  console.log(fmt.success(`Installed ${label} skill to ${destSkillDir}`));
}

function skillResourceDir(name: string): string {
  return path.join(__dirname, "..", "..", "..", "resources", "skills", name);
}

function installSkillsTo(skillsDir: string): void {
  fs.mkdirSync(skillsDir, { recursive: true });
  for (const skill of AGENT_SKILLS) {
    installSkillDir(skillResourceDir(skill.name), path.join(skillsDir, skill.name), skill.description);
  }
}

async function installClaudeCodeSkills(root: string): Promise<void> {
  installSkillsTo(path.join(root, ".claude", "skills"));
}

/**
 * Sub-agents shipped by `rafter agent init --with-claude-code`.
 *
 * These land in <root>/.claude/agents/<name>.md and become first-class
 * delegation targets (Agent(subagent_type='<name>')) in the calling Claude
 * Code session — distinct from skills, which only surface in the activation
 * prompt. Source files live in `resources/agents/<name>.md`.
 *
 * Keep this list in sync with the Python installer.
 */
const CLAUDE_CODE_SUBAGENTS: { name: string; description: string }[] = [
  { name: "rafter", description: "Rafter Security" },
];

function installClaudeCodeSubAgents(root: string): void {
  const agentsDir = path.join(root, ".claude", "agents");
  if (!fs.existsSync(agentsDir)) {
    fs.mkdirSync(agentsDir, { recursive: true });
  }
  for (const sub of CLAUDE_CODE_SUBAGENTS) {
    const destPath = path.join(agentsDir, `${sub.name}.md`);
    const srcPath = path.join(
      __dirname, "..", "..", "..", "resources", "agents", `${sub.name}.md`,
    );
    if (fs.existsSync(srcPath)) {
      fs.copyFileSync(srcPath, destPath);
      console.log(fmt.success(`Installed ${sub.description} sub-agent to ${destPath}`));
    } else {
      console.log(fmt.warning(`${sub.description} sub-agent template not found at ${srcPath}`));
    }
  }
}

function installCodexSkills(root: string): void {
  installSkillsTo(path.join(root, ".agents", "skills"));
}

function installGeminiSkills(root: string): void {
  installSkillsTo(path.join(root, ".agents", "skills"));
}

/**
 * Register installed skills with Gemini CLI via `gemini skills link <abs-path>`.
 *
 * Requires gemini CLI >= 0.35 (the version that added `gemini skills`).
 * Missing CLI, missing subcommand, and per-skill registration failures are
 * non-fatal: we warn and continue so the on-disk install still succeeds.
 */
function registerGeminiSkills(skillsDir: string): void {
  // Probe for the `gemini` binary. Absence is expected on CI / fresh machines.
  try {
    execSync("gemini --version", { stdio: ["ignore", "pipe", "ignore"], timeout: 5000 });
  } catch {
    console.log(fmt.warning(
      "gemini CLI not found on PATH — skipping skill registration. " +
      "Skills are installed to disk; re-run after installing gemini ≥ 0.35.",
    ));
    return;
  }

  // Probe `gemini skills` subcommand (added in 0.35).
  try {
    execSync("gemini skills --help", { stdio: ["ignore", "pipe", "ignore"], timeout: 5000 });
  } catch {
    console.log(fmt.warning(
      "gemini CLI does not support `skills` subcommand (needs ≥ 0.35). " +
      "Skipping registration — skills are still installed to disk.",
    ));
    return;
  }

  for (const skill of AGENT_SKILLS) {
    const absPath = path.resolve(skillsDir, skill.name);
    if (!fs.existsSync(absPath)) continue;
    try {
      execSync(`gemini skills link ${JSON.stringify(absPath)}`, {
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 10000,
      });
      console.log(fmt.success(`Registered ${skill.name} with Gemini CLI`));
    } catch (e: any) {
      const msg = (e?.stderr?.toString?.() || e?.message || "").trim();
      console.log(fmt.warning(
        `Failed to register ${skill.name} with Gemini CLI: ${msg.split("\n")[0] || "unknown error"}`,
      ));
    }
  }
}

export function createInitCommand(): Command {
  return new Command("init")
    .description("Initialize agent security system")
    .option("--risk-level <level>", "Set risk level (minimal, moderate, aggressive)", "moderate")
    .option("--with-openclaw", "Install OpenClaw integration")
    .option("--with-claude-code", "Install Claude Code integration")
    .option("--with-codex", "Install Codex CLI integration")
    .option("--with-gemini", "Install Gemini CLI integration")
    .option("--with-aider", "Install Aider integration")
    .option("--with-cursor", "Install Cursor integration")
    .option("--with-windsurf", "Install Windsurf integration")
    .option("--with-continue", "Install Continue.dev integration")
    .option("--with-hermes", "Install Hermes integration")
    .option("--with-opencode", "Install OpenCode integration")
    .option("--with-betterleaks", "Download and install Betterleaks binary")
    .option("--with-skill-scanner", "Install the optional skill-scanner deep engine (heavy; audit-skill --deep)")
    .option("--all", "Install all detected integrations and download Betterleaks")
    .option("-i, --interactive", "Guided setup — prompts for each detected integration")
    .option("--update", "Re-download betterleaks and reinstall integrations without resetting config")
    .option(
      "--local",
      "Install integration configs project-locally (in CWD) instead of user-globally. " +
      "Supported for Claude Code, Codex, Gemini, Cursor. Other platforms are skipped in local mode.",
    )
    .option(
      "--dry-run",
      "Print every file path that would be created, modified, or downloaded — without making any changes (rf-hrtd).",
    )
    .action(async (opts) => {
      console.log(fmt.header("Rafter Agent Security Setup"));
      console.log(fmt.divider());
      console.log();

      const manager = new ConfigManager();
      const root = opts.local ? process.cwd() : os.homedir();
      const scope: "project" | "user" = opts.local ? "project" : "user";
      if (opts.local) {
        console.log(fmt.info(`Project-local install — writing configs under ${root}`));
      }

      // Platforms supported in --local scope: Claude Code, Codex, Gemini, Cursor.
      // Windsurf, Continue.dev, Aider are skipped in --local because their
      // project-local config story is not established in their CLIs today.

      // Detect environments. In local scope, don't probe user-global paths —
      // the user must opt in explicitly via --with-<platform>.
      const hasOpenClaw = scope === "user" && fs.existsSync(path.join(os.homedir(), ".openclaw"));
      const hasClaudeCode = scope === "user" && fs.existsSync(path.join(os.homedir(), ".claude"));
      const hasCodex = scope === "user" && fs.existsSync(path.join(os.homedir(), ".codex"));
      const hasGemini = scope === "user" && fs.existsSync(path.join(os.homedir(), ".gemini"));
      const hasCursor = scope === "user" && fs.existsSync(path.join(os.homedir(), ".cursor"));
      const hasWindsurf = scope === "user" && fs.existsSync(path.join(os.homedir(), ".codeium", "windsurf"));
      const hasContinueDev = scope === "user" && fs.existsSync(path.join(os.homedir(), ".continue"));
      const hasAider = scope === "user" && fs.existsSync(path.join(os.homedir(), ".aider.conf.yml"));
      const hasHermes = scope === "user" && fs.existsSync(path.join(os.homedir(), ".hermes"));
      const hasOpenCode = scope === "user" && fs.existsSync(path.join(os.homedir(), ".config", "opencode"));

      // Resolve opt-in flags (--all enables all detected, --interactive prompts).
      // In --local scope, --all is restricted to platforms that have a project-local
      // config story (claudeCode, codex, gemini, cursor). The rest require user scope.
      // OpenClaw returns to --all in rf-zgwj — the integration was rebuilt
      // to ship a ClawHub-shaped skill at the canonical workspace path
      // (~/.openclaw/workspace/skills/rafter-security/SKILL.md), so OpenClaw
      // actually auto-discovers it now. (User-scope only; --local doesn't
      // apply since the platform is user-config-driven.)
      let wantOpenClaw = opts.withOpenclaw || (opts.all && !opts.local);
      let wantClaudeCode = opts.withClaudeCode || opts.all;
      let wantCodex = opts.withCodex || opts.all;
      let wantGemini = opts.withGemini || opts.all;
      let wantCursor = opts.withCursor || opts.all;
      // Windsurf can install at --local scope (project rules + AGENTS.md)
      // since rf-0vr3. User scope still also installs the MCP entry.
      let wantWindsurf = opts.withWindsurf || opts.all;
      // Continue.dev can install at --local scope (project rules) since rf-acz0.
      // User scope additionally registers the MCP entry.
      let wantContinue = opts.withContinue || opts.all;
      // Aider can install at --local scope (writes RAFTER.md + .aider.conf.yml
      // in cwd) since rf-du2o.
      let wantAider = opts.withAider || opts.all;
      // Hermes: MCP-only v0 (no hooks confirmed yet). User scope only — Hermes
      // reads ~/.hermes/config.yaml; the project-local install story isn't
      // established. Excluded from --all in --local for the same reason.
      let wantHermes = opts.withHermes || (opts.all && !opts.local);
      // OpenCode: MCP-based, user scope only. OpenCode reads a global config at
      // ~/.config/opencode/opencode.json; a project-local install story via
      // --local isn't wired here, so (like Hermes) it's excluded from --all in
      // --local scope. It supports MCP local/stdio servers and AGENTS.md
      // natively (https://opencode.ai/docs/mcp-servers/, sable-l8e5).
      let wantOpenCode = opts.withOpencode || (opts.all && !opts.local);
      let wantBetterleaks = opts.withBetterleaks || (opts.all && !opts.local);
      // skill-scanner is heavy and opt-in only — deliberately NOT folded into --all.
      const wantSkillScanner = !!opts.withSkillScanner;

      // Interactive mode: prompt for each detected integration
      if (opts.interactive && !opts.all) {
        console.log();
        console.log(fmt.info("Select integrations to install:"));
        console.log();
        if (hasClaudeCode && !wantClaudeCode) wantClaudeCode = await askYesNo("Install Claude Code hooks + skills?");
        if (hasCodex && !wantCodex) wantCodex = await askYesNo("Install Codex CLI skills + hooks?");
        if (hasOpenClaw && !wantOpenClaw) wantOpenClaw = await askYesNo("Install OpenClaw skill?");
        if (hasGemini && !wantGemini) wantGemini = await askYesNo("Install Gemini CLI MCP + hooks?");
        if (hasCursor && !wantCursor) wantCursor = await askYesNo("Install Cursor MCP + hooks?");
        if (hasWindsurf && !wantWindsurf) wantWindsurf = await askYesNo("Install Windsurf MCP + hooks?");
        if (hasContinueDev && !wantContinue) wantContinue = await askYesNo("Install Continue.dev MCP server?");
        if (hasAider && !wantAider) wantAider = await askYesNo("Install Aider MCP server?");
        if (hasHermes && !wantHermes) wantHermes = await askYesNo("Install Hermes MCP server?");
        if (hasOpenCode && !wantOpenCode) wantOpenCode = await askYesNo("Install OpenCode MCP server?");
        if (!wantBetterleaks) wantBetterleaks = await askYesNo("Download Betterleaks binary (enhanced scanning)?");
        console.log();
      }

      // Show detected environments with opt-in hints
      const detected: string[] = [];
      if (hasOpenClaw) detected.push("OpenClaw");
      if (hasClaudeCode) detected.push("Claude Code");
      if (hasCodex) detected.push("Codex CLI");
      if (hasGemini) detected.push("Gemini CLI");
      if (hasCursor) detected.push("Cursor");
      if (hasWindsurf) detected.push("Windsurf");
      if (hasContinueDev) detected.push("Continue.dev");
      if (hasAider) detected.push("Aider");
      if (hasHermes) detected.push("Hermes");
      if (hasOpenCode) detected.push("OpenCode");

      if (detected.length > 0) {
        console.log(fmt.info(`Detected environments: ${detected.join(", ")}`));
      } else {
        console.log(fmt.info("No agent environments detected"));
      }

      // Warn about requested but undetected environments (user scope only —
      // in --local scope we create the directories in CWD as needed).
      if (scope === "user") {
        if (wantOpenClaw && !hasOpenClaw) console.log(fmt.warning("OpenClaw requested but not detected (~/.openclaw not found)"));
        if (wantClaudeCode && !hasClaudeCode) console.log(fmt.warning("Claude Code requested but not detected (~/.claude not found)"));
        if (wantCodex && !hasCodex) console.log(fmt.warning("Codex CLI requested but not detected (~/.codex not found)"));
        if (wantGemini && !hasGemini) console.log(fmt.warning("Gemini CLI requested but not detected (~/.gemini not found)"));
        if (wantCursor && !hasCursor) console.log(fmt.warning("Cursor requested but not detected (~/.cursor not found)"));
        if (wantWindsurf && !hasWindsurf) console.log(fmt.warning("Windsurf requested but not detected (~/.codeium/windsurf not found)"));
        if (wantContinue && !hasContinueDev) console.log(fmt.warning("Continue.dev requested but not detected (~/.continue not found)"));
        if (wantAider && !hasAider) console.log(fmt.warning("Aider requested but not detected (~/.aider.conf.yml not found)"));
        if (wantHermes && !hasHermes) console.log(fmt.warning("Hermes requested but not detected (~/.hermes not found)"));
        if (wantOpenCode && !hasOpenCode) console.log(fmt.warning("OpenCode requested but not detected (~/.config/opencode not found)"));
      }

      // --dry-run: print every file path the command would touch, then
      // exit before any filesystem write happens (rf-hrtd). The plan is
      // built from the SAME resolved want* / has* booleans the install
      // path uses, so the listing mirrors what would actually run.
      if (opts.dryRun) {
        printDryRunPlan({
          root,
          scope,
          wantOpenClaw: wantOpenClaw && (hasOpenClaw),
          wantClaudeCode: wantClaudeCode && (hasClaudeCode || opts.local),
          wantCodex: wantCodex && (hasCodex || opts.local),
          wantGemini: wantGemini && (hasGemini || opts.local),
          wantCursor: wantCursor && (hasCursor || opts.local),
          wantWindsurf: wantWindsurf && (hasWindsurf || opts.local),
          wantContinue: wantContinue && (hasContinueDev || opts.local),
          wantAider: wantAider && (hasAider || opts.local),
          wantHermes: wantHermes && hasHermes,
          wantOpenCode: wantOpenCode && hasOpenCode,
          wantBetterleaks,
          wantSkillScanner,
          riskLevel: opts.riskLevel,
        });
        return;
      }

      // Initialize directory structure
      try {
        await manager.initialize();
        console.log(fmt.success("Created config at ~/.rafter/config.json"));
      } catch (e) {
        console.error(fmt.error(`Failed to initialize: ${e}`));
        process.exit(1);
      }

      // Set risk level
      const validRiskLevels = ["minimal", "moderate", "aggressive"];
      if (!validRiskLevels.includes(opts.riskLevel)) {
        console.error(fmt.error(`Invalid risk level: ${opts.riskLevel}`));
        console.error(`Valid options: ${validRiskLevels.join(", ")}`);
        process.exit(1);
      }

      manager.set("agent.riskLevel", opts.riskLevel);
      console.log(fmt.success(`Set risk level: ${opts.riskLevel}`));

      // Check / download Betterleaks binary (opt-in via --with-betterleaks or --all)
      if (wantBetterleaks) {
        const binaryManager = new BinaryManager();
        const platformInfo = binaryManager.getPlatformInfo();

        // Helper: show diagnostics for a failing binary (mirrors Python's agent init)
        const showDiagnostics = async (binaryPath: string, verResult: { ok: boolean; stdout: string; stderr: string }) => {
          if (verResult.stderr) {
            console.log(fmt.info(`  stderr: ${verResult.stderr}`));
          }
          const diag = await binaryManager.collectBinaryDiagnostics(binaryPath);
          if (diag) {
            console.log(fmt.info("Diagnostics:"));
            console.log(diag);
          }
          console.log(fmt.info("To fix: install betterleaks (https://github.com/betterleaks/betterleaks/releases) and ensure it is on PATH, then re-run 'rafter agent init'."));
          console.log();
        };

        if (!opts.update && binaryManager.isBetterleaksInstalled()) {
          // Local binary exists — verify it actually works
          const verResult = await binaryManager.verifyBetterleaksVerbose();
          if (verResult.ok) {
            console.log(fmt.success(`Betterleaks already installed (${verResult.stdout})`));
          } else {
            console.log(fmt.warning("Betterleaks binary found locally but failed to execute."));
            console.log(fmt.info(`  Binary: ${binaryManager.getBetterleaksPath()}`));
            await showDiagnostics(binaryManager.getBetterleaksPath(), verResult);
          }
        } else {
          // Not installed locally (or --update forcing re-download) — check PATH first
          // unless --update was passed (in that case force a fresh managed install)
          const pathBinary = opts.update ? null : binaryManager.findBetterleaksOnPath();
          if (pathBinary) {
            const verResult = await binaryManager.verifyBetterleaksVerbose(pathBinary);
            if (verResult.ok) {
              console.log(fmt.success(`Betterleaks available on PATH (${verResult.stdout})`));
            } else {
              console.log(fmt.warning("Betterleaks found on PATH but failed to execute."));
              console.log(fmt.info(`  Binary: ${pathBinary}`));
              await showDiagnostics(pathBinary, verResult);
            }
          } else if (!platformInfo.supported) {
            console.log(fmt.info(`Betterleaks not available for ${platformInfo.platform}/${platformInfo.arch}`));
            console.log(fmt.success("Using pattern-based scanning (21 patterns)"));
          } else {
            // Not on PATH, not installed locally — download
            console.log();
            console.log(fmt.info("Downloading Betterleaks (enhanced secret detection)..."));
            try {
              await binaryManager.downloadBetterleaks((msg) => {
                console.log(`   ${msg}`);
              });
              console.log();
            } catch (e) {
              console.log();
              console.log(fmt.error(`Betterleaks setup failed — pattern-based scanning will be used instead.`));
              console.log(fmt.warning(String(e)));
              console.log();
              console.log(fmt.info("To fix: install betterleaks manually (https://github.com/betterleaks/betterleaks/releases) and ensure it is on PATH, then re-run 'rafter agent init'."));
              console.log();
            }
          }
        }
      }

      // Install the optional skill-scanner deep engine (opt-in via
      // --with-skill-scanner only — never via --all, as it's heavy).
      if (wantSkillScanner) {
        const onPath = opts.update ? null : (() => {
          try {
            const cmd = process.platform === "win32" ? "where skill-scanner" : "which skill-scanner";
            return execSync(cmd, { timeout: 5000, encoding: "utf-8" }).trim().split("\n")[0].trim() || null;
          } catch {
            return null;
          }
        })();
        if (onPath) {
          console.log(fmt.success(`skill-scanner available on PATH (${onPath})`));
        } else {
          console.log();
          console.log(fmt.info(
            "Installing optional skill-scanner deep engine (heavy third-party package; isolated install)...",
          ));
          const result = await new SkillScannerInstaller().install(
            SKILL_SCANNER_VERSION,
            (msg) => console.log(`   ${msg}`),
          );
          if (result.ok) {
            console.log(fmt.success(`skill-scanner installed (via ${result.via}): ${result.message}`));
          } else {
            console.log(fmt.warning(`skill-scanner install failed: ${result.message}`));
            console.log(fmt.info(
              "To fix: run 'rafter agent update-skill-scanner' or install manually with 'uv tool install cisco-ai-skill-scanner'.",
            ));
          }
        }
      }

      // Install OpenClaw skill if opted in
      let openclawOk = false;
      if (hasOpenClaw && wantOpenClaw) {
        const skillManager = new SkillManager();
        const result = await skillManager.installRafterSkillVerbose();
        openclawOk = result.ok;
        if (result.ok) {
          console.log(fmt.success(`Installed Rafter Security skill to ${result.destPath}`));
          manager.set("agent.environments.openclaw.enabled", true);
        } else {
          console.log(fmt.error("Failed to install Rafter Security skill"));
          console.log(fmt.warning(`  Source: ${result.sourcePath}`));
          console.log(fmt.warning(`  Destination: ${result.destPath}`));
          if (result.error) {
            console.log(fmt.warning(`  Error: ${result.error}`));
          }
        }
      }

      // Helper: warn that a platform is not supported in --local mode.
      const localUnsupported = (label: string): void => {
        console.log(fmt.warning(
          `${label} is not supported in --local mode yet. Skipping. ` +
          `Re-run without --local to install for this platform user-globally.`,
        ));
      };

      // Install Claude Code skills + hooks if opted in
      // When --with-claude-code is explicitly passed (or --local), install even if <root>/.claude doesn't exist yet
      let claudeCodeOk = false;
      if ((hasClaudeCode || opts.withClaudeCode || (opts.local && wantClaudeCode)) && wantClaudeCode) {
        try {
          await installClaudeCodeSkills(root);
          installClaudeCodeSubAgents(root);
          installClaudeCodeHooks(root);
          if (scope === "project") {
            const components = (manager.get("agent.components") ?? {}) as Record<string, any>;
            if (components["claude-code.mcp"]?.enabled === false) {
              console.log(fmt.info("Skipped .mcp.json (claude-code.mcp disabled; re-enable with `rafter agent enable claude-code.mcp`)"));
            } else {
              installClaudeCodeMcp(root);
              components["claude-code.mcp"] = { enabled: true, updatedAt: new Date().toISOString() };
              manager.set("agent.components", components);
            }
          }
          if (scope === "user") manager.set("agent.environments.claudeCode.enabled", true);
          claudeCodeOk = true;
        } catch (e) {
          console.error(fmt.error(`Failed to install Claude Code integration: ${e}`));
        }
      }

      // Install Codex CLI skills + hooks if opted in
      let codexOk = false;
      if ((hasCodex || (opts.local && wantCodex)) && wantCodex) {
        try {
          installCodexSkills(root);
          installCodexHooks(root);
          if (scope === "user") manager.set("agent.environments.codex.enabled", true);
          codexOk = true;
        } catch (e) {
          console.error(fmt.error(`Failed to install Codex CLI integration: ${e}`));
        }
      }

      // Install Gemini CLI MCP + skills + hooks if opted in
      let geminiOk = false;
      if ((hasGemini || (opts.local && wantGemini)) && wantGemini) {
        try {
          geminiOk = installGeminiMcp(root);
          installGeminiSkills(root);
          registerGeminiSkills(path.join(root, ".agents", "skills"));
          installGeminiHooks(root);
          if (geminiOk && scope === "user") manager.set("agent.environments.gemini.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Gemini CLI integration: ${e}`));
        }
      }

      // Install Cursor MCP + hooks + per-skill rules + sub-agent if opted in
      let cursorOk = false;
      if ((hasCursor || (opts.local && wantCursor)) && wantCursor) {
        try {
          cursorOk = installCursorMcp(root);
          installCursorHooks(root);
          installCursorRules(root);
          installCursorSubAgents(root);
          if (cursorOk && scope === "user") manager.set("agent.environments.cursor.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Cursor integration: ${e}`));
        }
      }

      // Install Windsurf integration if opted in.
      // - User scope: MCP entry under ~/.codeium/windsurf/ + per-skill rules
      //   at .windsurf/rules/ (workspace) + AGENTS.md (workspace, written by
      //   installGlobalInstructions below).
      // - Project scope (--local): per-skill rules + AGENTS.md only (no
      //   user-scope MCP entry written from a project init).
      // The previous ~/.windsurf/hooks.json install was pruned: Windsurf has
      // no documented hook surface (rf-0vr3).
      let windsurfOk = false;
      if (wantWindsurf && (hasWindsurf || opts.local)) {
        try {
          if (hasWindsurf) {
            windsurfOk = installWindsurfMcp(root);
            if (windsurfOk) manager.set("agent.environments.windsurf.enabled", true);
          }
          installWindsurfRules(root);
          // AGENTS.md is written below in installGlobalInstructions when
          // platforms.windsurf is true.
          if (!hasWindsurf) windsurfOk = true; // local-scope success: rules + AGENTS.md
        } catch (e) {
          console.error(fmt.error(`Failed to install Windsurf integration: ${e}`));
        }
      }

      // Install Continue.dev integration if opted in (rf-acz0).
      // - User scope: per-skill rules (.continue/rules/) + MCP entry under
      //   ~/.continue/config.json.
      // - Project scope (--local): rules only.
      // Continue.dev has no hook surface — the prior hooks install was pruned
      // in rf-cia phase b.
      let continueOk = false;
      if (wantContinue && (hasContinueDev || opts.local)) {
        try {
          if (hasContinueDev) {
            continueOk = installContinueDevMcp(root);
            if (continueOk) manager.set("agent.environments.continueDev.enabled", true);
          }
          installContinueDevRules(root);
          if (!hasContinueDev) continueOk = true; // local-scope success: rules only
        } catch (e) {
          console.error(fmt.error(`Failed to install Continue.dev integration: ${e}`));
        }
      }

      // Install Aider integration if opted in (rf-du2o).
      // Aider has no MCP and no hook surface — its only intercept is the
      // `read:` flag in .aider.conf.yml. We write RAFTER.md and ensure
      // `read:` includes it. The legacy mcp-server-command YAML line (a
      // silent no-op) is stripped on reinstall.
      let aiderOk = false;
      if (wantAider && (hasAider || opts.local)) {
        try {
          aiderOk = installAiderRead(root);
          if (aiderOk && hasAider) manager.set("agent.environments.aider.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Aider integration: ${e}`));
        }
      }

      // Install Hermes integration if opted in (sable-gyw).
      // User scope only — Hermes reads ~/.hermes/config.yaml. MCP-only v0;
      // hooks deferred pending confirmation Hermes exposes a hook surface.
      let hermesOk = false;
      if (wantHermes && hasHermes) {
        try {
          hermesOk = installHermesMcp(root);
          if (hermesOk) manager.set("agent.environments.hermes.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install Hermes integration: ${e}`));
        }
      }

      // Install OpenCode integration if opted in (sable-l8e5).
      // User scope only — OpenCode reads a global config at
      // ~/.config/opencode/opencode.json. MCP-based: we register the local
      // stdio server `rafter mcp serve` under the `mcp` block.
      let openCodeOk = false;
      if (wantOpenCode && hasOpenCode) {
        try {
          openCodeOk = installOpenCodeMcp(root);
          if (openCodeOk) manager.set("agent.environments.opencode.enabled", true);
        } catch (e) {
          console.error(fmt.error(`Failed to install OpenCode integration: ${e}`));
        }
      }

      // Install global instruction files for platforms that support them.
      // Cursor is intentionally absent — Cursor uses per-skill rules + the
      // rafter sub-agent installed in the Cursor branch above (rf-svn3).
      installGlobalInstructions({
        claudeCode: claudeCodeOk,
        codex: codexOk,
        gemini: geminiOk,
        windsurf: windsurfOk,
      }, root, scope);

      console.log();
      console.log(fmt.success("Agent security initialized!"));
      console.log();

      const anyIntegration = openclawOk || claudeCodeOk || codexOk || geminiOk || cursorOk || windsurfOk || continueOk || aiderOk || hermesOk || openCodeOk;

      if (anyIntegration) {
        console.log("Next steps:");
        if (openclawOk) console.log("  - Restart OpenClaw to load skill");
        if (claudeCodeOk) console.log("  - Restart Claude Code to load skills");
        if (codexOk) console.log("  - Restart Codex CLI to load skills");
        if (geminiOk) console.log("  - Restart Gemini CLI to load MCP server");
        if (cursorOk) console.log("  - Restart Cursor to load MCP server");
        if (windsurfOk) console.log("  - Restart Windsurf to load MCP server");
        if (continueOk) console.log("  - Restart Continue.dev to load MCP server");
        if (aiderOk) console.log("  - Restart Aider to load RAFTER.md from .aider.conf.yml read:");
        if (hermesOk) console.log("  - Restart Hermes to load MCP server");
        if (openCodeOk) console.log("  - Restart OpenCode to load MCP server");
      } else if (scope === "project") {
        console.log("No integrations were installed. In --local mode, pass one or more opt-in flags:");
        console.log("  rafter agent init --local --with-claude-code");
        console.log("  rafter agent init --local --with-codex");
        console.log("  rafter agent init --local --with-gemini");
        console.log("  rafter agent init --local --with-cursor");
      } else if (detected.length > 0) {
        console.log("No integrations were installed. To install, re-run with opt-in flags:");
        console.log("  rafter agent init --all                  # Install all detected");
        if (hasClaudeCode) console.log("  rafter agent init --with-claude-code     # Claude Code only");
        if (hasOpenClaw) console.log("  rafter agent init --with-openclaw        # OpenClaw only");
        if (hasCodex) console.log("  rafter agent init --with-codex           # Codex CLI only");
        if (hasGemini) console.log("  rafter agent init --with-gemini          # Gemini CLI only");
        if (hasCursor) console.log("  rafter agent init --with-cursor          # Cursor only");
        if (hasWindsurf) console.log("  rafter agent init --with-windsurf        # Windsurf only");
        if (hasContinueDev) console.log("  rafter agent init --with-continue        # Continue.dev only");
        if (hasAider) console.log("  rafter agent init --with-aider           # Aider only");
        if (hasHermes) console.log("  rafter agent init --with-hermes          # Hermes only");
        if (hasOpenCode) console.log("  rafter agent init --with-opencode        # OpenCode only");
      } else {
        console.log("No agent environments detected. Install an agent tool and re-run with --with-<tool>.");
      }
      console.log();
      console.log("  - Run: rafter secrets . (test secret scanning)");
      console.log("  - Configure: rafter agent config show");
      console.log();

      // Warn if a different rafter version shadows this one on PATH
      try {
        const _require = createRequire(import.meta.url);
        const { version: thisVersion } = _require("../../../package.json");
        const pathVersion = execSync("rafter --version", {
          encoding: "utf-8",
          timeout: 5000,
          stdio: ["pipe", "pipe", "ignore"],
        }).trim();
        if (pathVersion && pathVersion !== thisVersion && !pathVersion.includes(thisVersion)) {
          console.log(fmt.warning(`PATH version mismatch: 'rafter --version' reports ${pathVersion}, but this install is ${thisVersion}.`));
          console.log(fmt.info("Another rafter binary may be shadowing this one. Check: which rafter"));
          console.log();
        }
      } catch {
        // Ignore — rafter may not be on PATH yet
      }
    });
}
