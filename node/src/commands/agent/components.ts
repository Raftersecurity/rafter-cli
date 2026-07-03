import fs from "fs";
import path from "path";
import os from "os";
import yaml from "js-yaml";
import {
  RAFTER_MARKER_START,
  RAFTER_MARKER_END,
  injectInstructionFile,
} from "./instruction-block.js";
import { ConfigManager } from "../../core/config-manager.js";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Component granularity for `rafter agent enable/disable/list`.
 *
 * Each AI platform Rafter integrates with exposes up to four "slots" — hooks,
 * MCP entries, instruction blocks, and skills. A component is one (platform, kind)
 * pair. Users can install/uninstall components individually instead of all-or-nothing
 * per platform.
 */

export type ComponentKind = "hooks" | "mcp" | "instructions" | "skills";

export type ComponentState = "installed" | "not-installed" | "not-detected";

export interface ComponentSpec {
  id: string;
  platform: string;
  kind: ComponentKind;
  description: string;
  /** Directory whose existence indicates the platform is present on this machine. */
  detectDir: string;
  /** Primary file this component reads/writes (for reporting). */
  path: string;
  install: () => void;
  uninstall: () => void;
  /** True when this component's rafter entries are currently present. */
  isInstalled: () => boolean;
}

export interface ComponentStatus {
  id: string;
  platform: string;
  kind: ComponentKind;
  description: string;
  path: string;
  state: ComponentState;
  /** True when rafter entries are present in the relevant config/files. */
  installed: boolean;
  /** True when platform is detected on this machine. */
  detected: boolean;
  /** True when config records this component as enabled (last install succeeded and user hasn't disabled). */
  configEnabled: boolean;
}

const RAFTER_MCP_ENTRY = {
  command: "rafter",
  args: ["mcp", "serve"],
};

// ── helpers ────────────────────────────────────────────────────────────

function readJson(p: string): Record<string, any> {
  try {
    return JSON.parse(fs.readFileSync(p, "utf-8"));
  } catch {
    return {};
  }
}

function writeJson(p: string, obj: any): void {
  const dir = path.dirname(p);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj, null, 2), "utf-8");
}

function filterOutRafter<T>(arr: T[] | undefined, pred: (entry: any) => boolean): T[] {
  if (!Array.isArray(arr)) return [];
  return arr.filter((entry) => !pred(entry));
}

/** Remove a key from an object and return whether it existed. */
function removeKey(obj: Record<string, any> | undefined, key: string): boolean {
  if (!obj || !(key in obj)) return false;
  delete obj[key];
  return true;
}

/** True when a hook entry (matcher + hooks array) contains a rafter command matching a prefix. */
function hookEntryMatchesRafter(entry: any, prefix: string): boolean {
  const hooks = entry?.hooks;
  if (!Array.isArray(hooks)) return false;
  return hooks.some((h) => String(h?.command ?? "").startsWith(prefix));
}

/** Strip the rafter marker block from a text file, writing only if the file actually changed. */
function stripMarkerBlock(filePath: string): boolean {
  if (!fs.existsSync(filePath)) return false;
  const content = fs.readFileSync(filePath, "utf-8");
  const startIdx = content.indexOf(RAFTER_MARKER_START);
  const endIdx = content.indexOf(RAFTER_MARKER_END);
  if (startIdx === -1 || endIdx === -1) return false;
  const before = content.slice(0, startIdx).trimEnd();
  const after = content.slice(endIdx + RAFTER_MARKER_END.length);
  const trailing = after.replace(/^\s*\n+/, "");
  const next = (before ? before + "\n" : "") + trailing;
  fs.writeFileSync(filePath, next, "utf-8");
  return true;
}

/** True when a file exists and contains the rafter marker block. */
function hasMarkerBlock(filePath: string): boolean {
  if (!fs.existsSync(filePath)) return false;
  const content = fs.readFileSync(filePath, "utf-8");
  return content.includes(RAFTER_MARKER_START) && content.includes(RAFTER_MARKER_END);
}

// ── per-component implementations ──────────────────────────────────────

function claudeCodeHooks(): ComponentSpec {
  const home = os.homedir();
  const settingsPath = path.join(home, ".claude", "settings.json");
  return {
    id: "claude-code.hooks",
    platform: "claude-code",
    kind: "hooks",
    description: "Claude Code PreToolUse + PostToolUse hooks",
    detectDir: path.join(home, ".claude"),
    path: settingsPath,
    isInstalled: () => {
      if (!fs.existsSync(settingsPath)) return false;
      const s = readJson(settingsPath);
      const pre = s.hooks?.PreToolUse ?? [];
      for (const entry of pre) {
        if (hookEntryMatchesRafter(entry, "rafter hook pretool")) return true;
      }
      return false;
    },
    install: () => {
      if (!fs.existsSync(path.join(home, ".claude"))) {
        fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
      }
      const settings: Record<string, any> = fs.existsSync(settingsPath)
        ? readJson(settingsPath)
        : {};
      settings.hooks ??= {};
      settings.hooks.PreToolUse ??= [];
      settings.hooks.PostToolUse ??= [];

      const pre = { type: "command", command: "rafter hook pretool" };
      const post = { type: "command", command: "rafter hook posttool" };

      settings.hooks.PreToolUse = filterOutRafter(
        settings.hooks.PreToolUse,
        (e) => hookEntryMatchesRafter(e, "rafter hook pretool"),
      );
      settings.hooks.PostToolUse = filterOutRafter(
        settings.hooks.PostToolUse,
        (e) => hookEntryMatchesRafter(e, "rafter hook posttool"),
      );
      // Strip legacy SessionStart entry from <=0.7.4 installs.
      if (Array.isArray(settings.hooks.SessionStart)) {
        settings.hooks.SessionStart = filterOutRafter(
          settings.hooks.SessionStart,
          (e) => hookEntryMatchesRafter(e, "rafter hook session-start"),
        );
        if (settings.hooks.SessionStart.length === 0) delete settings.hooks.SessionStart;
      }

      settings.hooks.PreToolUse.push(
        { matcher: "Bash", hooks: [pre] },
        { matcher: "Write|Edit", hooks: [pre] },
      );
      // Narrow to tools that produce scannable output (shell output + file
      // writes); avoids firing posttool on every Read/MCP call (latency).
      settings.hooks.PostToolUse.push({ matcher: "Bash|Write|Edit|MultiEdit", hooks: [post] });

      writeJson(settingsPath, settings);
    },
    uninstall: () => {
      if (!fs.existsSync(settingsPath)) return;
      const settings = readJson(settingsPath);
      if (settings.hooks?.PreToolUse) {
        settings.hooks.PreToolUse = filterOutRafter(
          settings.hooks.PreToolUse,
          (e) => hookEntryMatchesRafter(e, "rafter hook pretool"),
        );
      }
      if (settings.hooks?.PostToolUse) {
        settings.hooks.PostToolUse = filterOutRafter(
          settings.hooks.PostToolUse,
          (e) => hookEntryMatchesRafter(e, "rafter hook posttool"),
        );
      }
      if (Array.isArray(settings.hooks?.SessionStart)) {
        settings.hooks.SessionStart = filterOutRafter(
          settings.hooks.SessionStart,
          (e) => hookEntryMatchesRafter(e, "rafter hook session-start"),
        );
        if (settings.hooks.SessionStart.length === 0) delete settings.hooks.SessionStart;
      }
      writeJson(settingsPath, settings);
    },
  };
}

function claudeCodeInstructions(): ComponentSpec {
  const home = os.homedir();
  const filePath = path.join(home, ".claude", "CLAUDE.md");
  return {
    id: "claude-code.instructions",
    platform: "claude-code",
    kind: "instructions",
    description: "Claude Code global instruction block (~/.claude/CLAUDE.md)",
    detectDir: path.join(home, ".claude"),
    path: filePath,
    isInstalled: () => hasMarkerBlock(filePath),
    install: () => {
      injectInstructionFile(filePath);
    },
    uninstall: () => {
      stripMarkerBlock(filePath);
    },
  };
}

function skillTemplatePath(name: string): string {
  return path.join(__dirname, "..", "..", "..", "resources", "skills", name, "SKILL.md");
}

/**
 * Canonical rafter-authored skills that a per-platform "skills" component
 * installs. Mirrors `python/rafter_cli/commands/agent_components.py`. Keep in
 * sync with the SKILL.md files shipped under `node/resources/skills/`.
 */
const COMPONENT_SKILL_NAMES = [
  "rafter",
  "rafter-secure-design",
  "rafter-code-review",
  "rafter-skill-review",
] as const;

function skillsDirComponent(opts: {
  id: string;
  platform: string;
  description: string;
  detectDir: string;
  skillsBaseDir: string;
}): ComponentSpec {
  const destPaths = COMPONENT_SKILL_NAMES.map((name) =>
    path.join(opts.skillsBaseDir, name, "SKILL.md"),
  );
  return {
    id: opts.id,
    platform: opts.platform,
    kind: "skills",
    description: opts.description,
    detectDir: opts.detectDir,
    path: opts.skillsBaseDir,
    isInstalled: () => destPaths.some((p) => fs.existsSync(p)),
    install: () => {
      for (const name of COMPONENT_SKILL_NAMES) {
        const src = skillTemplatePath(name);
        const dst = path.join(opts.skillsBaseDir, name, "SKILL.md");
        if (!fs.existsSync(src)) continue;
        const dir = path.dirname(dst);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.copyFileSync(src, dst);
      }
    },
    uninstall: () => {
      for (const p of destPaths) {
        if (fs.existsSync(p)) {
          fs.rmSync(p, { force: true });
          const dir = path.dirname(p);
          try {
            if (fs.existsSync(dir) && fs.readdirSync(dir).length === 0) {
              fs.rmdirSync(dir);
            }
          } catch {
            // non-empty or races — leave it
          }
        }
      }
    },
  };
}

function claudeCodeSkills(): ComponentSpec {
  const home = os.homedir();
  return skillsDirComponent({
    id: "claude-code.skills",
    platform: "claude-code",
    description: "Claude Code skills (rafter + rafter-secure-design + rafter-code-review + rafter-skill-review)",
    detectDir: path.join(home, ".claude"),
    skillsBaseDir: path.join(home, ".claude", "skills"),
  });
}

function codexSkills(): ComponentSpec {
  const home = os.homedir();
  return skillsDirComponent({
    id: "codex.skills",
    platform: "codex",
    description: "Codex CLI skills (~/.agents/skills/rafter*)",
    detectDir: path.join(home, ".codex"),
    skillsBaseDir: path.join(home, ".agents", "skills"),
  });
}

function codexHooks(): ComponentSpec {
  const home = os.homedir();
  const hooksPath = path.join(home, ".codex", "hooks.json");
  return {
    id: "codex.hooks",
    platform: "codex",
    kind: "hooks",
    description: "Codex CLI hooks (~/.codex/hooks.json)",
    detectDir: path.join(home, ".codex"),
    path: hooksPath,
    isInstalled: () => {
      if (!fs.existsSync(hooksPath)) return false;
      const cfg = readJson(hooksPath);
      for (const entry of cfg.hooks?.PreToolUse ?? []) {
        if (hookEntryMatchesRafter(entry, "rafter hook pretool")) return true;
      }
      return false;
    },
    install: () => {
      const dir = path.join(home, ".codex");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const cfg: Record<string, any> = fs.existsSync(hooksPath) ? readJson(hooksPath) : {};
      cfg.hooks ??= {};
      cfg.hooks.PreToolUse ??= [];
      cfg.hooks.PostToolUse ??= [];
      const pre = { type: "command", command: "rafter hook pretool" };
      const post = { type: "command", command: "rafter hook posttool" };
      cfg.hooks.PreToolUse = filterOutRafter(
        cfg.hooks.PreToolUse,
        (e) => hookEntryMatchesRafter(e, "rafter hook pretool"),
      );
      cfg.hooks.PostToolUse = filterOutRafter(
        cfg.hooks.PostToolUse,
        (e) => hookEntryMatchesRafter(e, "rafter hook posttool"),
      );
      // Bash + apply_patch per Codex hook docs (rf-ovql verification).
      cfg.hooks.PreToolUse.push({ matcher: "Bash|apply_patch", hooks: [pre] });
      cfg.hooks.PostToolUse.push({ matcher: ".*", hooks: [post] });
      writeJson(hooksPath, cfg);
    },
    uninstall: () => {
      if (!fs.existsSync(hooksPath)) return;
      const cfg = readJson(hooksPath);
      if (cfg.hooks?.PreToolUse) {
        cfg.hooks.PreToolUse = filterOutRafter(
          cfg.hooks.PreToolUse,
          (e) => hookEntryMatchesRafter(e, "rafter hook pretool"),
        );
      }
      if (cfg.hooks?.PostToolUse) {
        cfg.hooks.PostToolUse = filterOutRafter(
          cfg.hooks.PostToolUse,
          (e) => hookEntryMatchesRafter(e, "rafter hook posttool"),
        );
      }
      writeJson(hooksPath, cfg);
    },
  };
}

/**
 * Project-scope Claude Code MCP config (<cwd>/.mcp.json). Unlike other
 * claude-code components which touch ~/.claude, this one writes at the
 * project root — Claude Code auto-loads it on startup and exposes
 * `mcp__rafter__*` tools to the agent.
 */
function claudeCodeMcp(): ComponentSpec {
  const home = os.homedir();
  const mcpPath = path.join(process.cwd(), ".mcp.json");
  return {
    id: "claude-code.mcp",
    platform: "claude-code",
    kind: "mcp",
    description: "Claude Code project-scope MCP server (<project>/.mcp.json)",
    detectDir: path.join(home, ".claude"),
    path: mcpPath,
    isInstalled: () => {
      if (!fs.existsSync(mcpPath)) return false;
      const cfg = readJson(mcpPath);
      return !!cfg.mcpServers?.rafter;
    },
    install: () => {
      const cfg: Record<string, any> = fs.existsSync(mcpPath) ? readJson(mcpPath) : {};
      cfg.mcpServers ??= {};
      cfg.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };
      writeJson(mcpPath, cfg);
    },
    uninstall: () => {
      if (!fs.existsSync(mcpPath)) return;
      const cfg = readJson(mcpPath);
      if (!removeKey(cfg.mcpServers, "rafter")) return;
      if (cfg.mcpServers && Object.keys(cfg.mcpServers).length === 0) {
        delete cfg.mcpServers;
      }
      if (Object.keys(cfg).length === 0) {
        fs.unlinkSync(mcpPath);
      } else {
        writeJson(mcpPath, cfg);
      }
    },
  };
}

/** Cursor hook events covered by rafter (rf-svn3). */
const CURSOR_HOOK_EVENTS: { event: string; command: string }[] = [
  { event: "preToolUse", command: "rafter hook pretool --format cursor" },
  { event: "postToolUse", command: "rafter hook posttool --format cursor" },
  { event: "beforeShellExecution", command: "rafter hook pretool --format cursor" },
];

function cursorHooks(): ComponentSpec {
  const home = os.homedir();
  const hooksPath = path.join(home, ".cursor", "hooks.json");
  return {
    id: "cursor.hooks",
    platform: "cursor",
    kind: "hooks",
    description: "Cursor hooks: preToolUse + postToolUse + beforeShellExecution (~/.cursor/hooks.json)",
    detectDir: path.join(home, ".cursor"),
    path: hooksPath,
    isInstalled: () => {
      if (!fs.existsSync(hooksPath)) return false;
      const cfg = readJson(hooksPath);
      for (const { event } of CURSOR_HOOK_EVENTS) {
        for (const entry of cfg.hooks?.[event] ?? []) {
          if (String(entry?.command ?? "").includes("rafter hook")) return true;
        }
      }
      return false;
    },
    install: () => {
      const dir = path.join(home, ".cursor");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const cfg: Record<string, any> = fs.existsSync(hooksPath) ? readJson(hooksPath) : {};
      cfg.version ??= 1;
      cfg.hooks ??= {};
      for (const { event, command } of CURSOR_HOOK_EVENTS) {
        cfg.hooks[event] ??= [];
        cfg.hooks[event] = filterOutRafter(
          cfg.hooks[event],
          (e) => String(e?.command ?? "").includes("rafter hook"),
        );
        cfg.hooks[event].push({ command, type: "command", timeout: 5000 });
      }
      writeJson(hooksPath, cfg);
    },
    uninstall: () => {
      if (!fs.existsSync(hooksPath)) return;
      const cfg = readJson(hooksPath);
      for (const { event } of CURSOR_HOOK_EVENTS) {
        if (cfg.hooks?.[event]) {
          cfg.hooks[event] = filterOutRafter(
            cfg.hooks[event],
            (e) => String(e?.command ?? "").includes("rafter hook"),
          );
        }
      }
      writeJson(hooksPath, cfg);
    },
  };
}

const CURSOR_RULE_SKILLS = [
  "rafter",
  "rafter-secure-design",
  "rafter-code-review",
  "rafter-skill-review",
] as const;

function cursorRuleSourceDir(): string | null {
  // After build: dist/commands/agent/components.js -> ../../../resources/cursor-rules
  const candidates = [
    path.resolve(__dirname, "..", "..", "..", "resources", "cursor-rules"),
    path.resolve(__dirname, "..", "..", "resources", "cursor-rules"),
  ];
  return candidates.find((p) => fs.existsSync(p)) ?? null;
}

function cursorAgentSourceFile(): string | null {
  const candidates = [
    path.resolve(__dirname, "..", "..", "..", "resources", "agents", "rafter.md"),
    path.resolve(__dirname, "..", "..", "resources", "agents", "rafter.md"),
  ];
  return candidates.find((p) => fs.existsSync(p)) ?? null;
}

/**
 * Cursor instructions = per-skill rules under .cursor/rules/ + the rafter
 * sub-agent at .cursor/agents/rafter.md (rf-svn3). The legacy consolidated
 * rafter-security.mdc was retired.
 *
 * `path` reports the rules dir for diagnostics; install/uninstall manage
 * both rules and the sub-agent file together.
 */
function cursorInstructions(): ComponentSpec {
  const home = os.homedir();
  const rulesDir = path.join(home, ".cursor", "rules");
  const agentPath = path.join(home, ".cursor", "agents", "rafter.md");
  const legacyPath = path.join(rulesDir, "rafter-security.mdc");
  return {
    id: "cursor.instructions",
    platform: "cursor",
    kind: "instructions",
    description: "Cursor per-skill rules + rafter sub-agent (~/.cursor/rules/, ~/.cursor/agents/rafter.md)",
    detectDir: path.join(home, ".cursor"),
    path: rulesDir,
    isInstalled: () => {
      const rulesPresent = CURSOR_RULE_SKILLS.every((n) =>
        fs.existsSync(path.join(rulesDir, `${n}.mdc`)),
      );
      return rulesPresent && fs.existsSync(agentPath);
    },
    install: () => {
      fs.mkdirSync(rulesDir, { recursive: true });
      const ruleSrc = cursorRuleSourceDir();
      if (ruleSrc) {
        for (const name of CURSOR_RULE_SKILLS) {
          const src = path.join(ruleSrc, `${name}.mdc`);
          if (fs.existsSync(src)) {
            fs.copyFileSync(src, path.join(rulesDir, `${name}.mdc`));
          }
        }
      }
      // Migrate away from the legacy consolidated rule.
      if (fs.existsSync(legacyPath)) {
        try { fs.unlinkSync(legacyPath); } catch { /* best-effort */ }
      }

      const agentSrc = cursorAgentSourceFile();
      if (agentSrc) {
        fs.mkdirSync(path.dirname(agentPath), { recursive: true });
        const raw = fs.readFileSync(agentSrc, "utf-8");
        const cursored = stripFrontmatterField(raw, "tools");
        fs.writeFileSync(agentPath, cursored, "utf-8");
      }
    },
    uninstall: () => {
      for (const name of CURSOR_RULE_SKILLS) {
        const p = path.join(rulesDir, `${name}.mdc`);
        if (fs.existsSync(p)) fs.rmSync(p, { force: true });
      }
      if (fs.existsSync(legacyPath)) fs.rmSync(legacyPath, { force: true });
      if (fs.existsSync(agentPath)) fs.rmSync(agentPath, { force: true });
    },
  };
}

/** Strip a single-line frontmatter field from a markdown file's frontmatter. */
function stripFrontmatterField(content: string, field: string): string {
  if (!content.startsWith("---\n")) return content;
  const fmEnd = content.indexOf("\n---", 4);
  if (fmEnd === -1) return content;
  const frontmatter = content.slice(4, fmEnd);
  const body = content.slice(fmEnd);
  const re = new RegExp(`^${field}:\\s.*$`, "m");
  const cleaned = frontmatter.replace(re, "").replace(/\n\n+/g, "\n").replace(/^\n/, "");
  return `---\n${cleaned}${body}`;
}

function cursorMcp(): ComponentSpec {
  const home = os.homedir();
  const mcpPath = path.join(home, ".cursor", "mcp.json");
  return {
    id: "cursor.mcp",
    platform: "cursor",
    kind: "mcp",
    description: "Cursor MCP server entry (~/.cursor/mcp.json)",
    detectDir: path.join(home, ".cursor"),
    path: mcpPath,
    isInstalled: () => {
      if (!fs.existsSync(mcpPath)) return false;
      const cfg = readJson(mcpPath);
      return !!cfg.mcpServers?.rafter;
    },
    install: () => {
      const dir = path.join(home, ".cursor");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const cfg: Record<string, any> = fs.existsSync(mcpPath) ? readJson(mcpPath) : {};
      cfg.mcpServers ??= {};
      cfg.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };
      writeJson(mcpPath, cfg);
    },
    uninstall: () => {
      if (!fs.existsSync(mcpPath)) return;
      const cfg = readJson(mcpPath);
      if (removeKey(cfg.mcpServers, "rafter")) writeJson(mcpPath, cfg);
    },
  };
}

function geminiHooks(): ComponentSpec {
  const home = os.homedir();
  const settingsPath = path.join(home, ".gemini", "settings.json");
  return {
    id: "gemini.hooks",
    platform: "gemini",
    kind: "hooks",
    description: "Gemini CLI BeforeTool + AfterTool hooks",
    detectDir: path.join(home, ".gemini"),
    path: settingsPath,
    isInstalled: () => {
      if (!fs.existsSync(settingsPath)) return false;
      const s = readJson(settingsPath);
      for (const entry of s.hooks?.BeforeTool ?? []) {
        if (hookEntryMatchesRafter(entry, "rafter hook pretool")) return true;
      }
      return false;
    },
    install: () => {
      const dir = path.join(home, ".gemini");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const s: Record<string, any> = fs.existsSync(settingsPath) ? readJson(settingsPath) : {};
      s.hooks ??= {};
      s.hooks.BeforeTool ??= [];
      s.hooks.AfterTool ??= [];
      s.hooks.BeforeTool = filterOutRafter(
        s.hooks.BeforeTool,
        (e) => hookEntryMatchesRafter(e, "rafter hook pretool"),
      );
      s.hooks.AfterTool = filterOutRafter(
        s.hooks.AfterTool,
        (e) => hookEntryMatchesRafter(e, "rafter hook posttool"),
      );
      // Explicit Gemini built-in tool names per geminicli.com/docs/hooks/reference
      // (rf-044o verification).
      s.hooks.BeforeTool.push({
        matcher: "run_shell_command|write_file|replace|edit",
        hooks: [{ type: "command", command: "rafter hook pretool --format gemini", timeout: 5000 }],
      });
      s.hooks.AfterTool.push({
        matcher: ".*",
        hooks: [{ type: "command", command: "rafter hook posttool --format gemini", timeout: 5000 }],
      });
      writeJson(settingsPath, s);
    },
    uninstall: () => {
      if (!fs.existsSync(settingsPath)) return;
      const s = readJson(settingsPath);
      if (s.hooks?.BeforeTool) {
        s.hooks.BeforeTool = filterOutRafter(
          s.hooks.BeforeTool,
          (e) => hookEntryMatchesRafter(e, "rafter hook pretool"),
        );
      }
      if (s.hooks?.AfterTool) {
        s.hooks.AfterTool = filterOutRafter(
          s.hooks.AfterTool,
          (e) => hookEntryMatchesRafter(e, "rafter hook posttool"),
        );
      }
      writeJson(settingsPath, s);
    },
  };
}

function geminiMcp(): ComponentSpec {
  const home = os.homedir();
  const settingsPath = path.join(home, ".gemini", "settings.json");
  return {
    id: "gemini.mcp",
    platform: "gemini",
    kind: "mcp",
    description: "Gemini CLI MCP server entry (~/.gemini/settings.json)",
    detectDir: path.join(home, ".gemini"),
    path: settingsPath,
    isInstalled: () => {
      if (!fs.existsSync(settingsPath)) return false;
      const s = readJson(settingsPath);
      return !!s.mcpServers?.rafter;
    },
    install: () => {
      const dir = path.join(home, ".gemini");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const s: Record<string, any> = fs.existsSync(settingsPath) ? readJson(settingsPath) : {};
      s.mcpServers ??= {};
      s.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };
      writeJson(settingsPath, s);
    },
    uninstall: () => {
      if (!fs.existsSync(settingsPath)) return;
      const s = readJson(settingsPath);
      if (removeKey(s.mcpServers, "rafter")) writeJson(settingsPath, s);
    },
  };
}

/** Skills shipped as Windsurf rules at .windsurf/rules/<skill>.md (rf-0vr3). */
const WINDSURF_RULE_SKILLS = [
  "rafter",
  "rafter-secure-design",
  "rafter-code-review",
  "rafter-skill-review",
] as const;

function windsurfRuleSourceDir(): string | null {
  const candidates = [
    path.resolve(__dirname, "..", "..", "..", "resources", "windsurf-rules"),
    path.resolve(__dirname, "..", "..", "resources", "windsurf-rules"),
  ];
  return candidates.find((p) => fs.existsSync(p)) ?? null;
}

/**
 * Windsurf rules component: per-skill files at .windsurf/rules/<skill>.md.
 *
 * Project/workspace-scope by design — Windsurf reads workspace rules from
 * .windsurf/rules/ (12KB cap per file). The cwd at the time install runs is
 * what gets the rules. Shown in the registry as resolved to the current
 * working directory.
 *
 * Replaces the prior `windsurf.hooks` component, pruned in rf-0vr3 because
 * Windsurf has no documented hook surface.
 */
function windsurfRules(): ComponentSpec {
  const home = os.homedir();
  const rulesDir = path.join(process.cwd(), ".windsurf", "rules");
  return {
    id: "windsurf.rules",
    platform: "windsurf",
    kind: "instructions",
    description: "Windsurf per-skill rules (.windsurf/rules/*.md, workspace-scope)",
    detectDir: path.join(home, ".codeium", "windsurf"),
    path: rulesDir,
    isInstalled: () =>
      WINDSURF_RULE_SKILLS.every((n) => fs.existsSync(path.join(rulesDir, `${n}.md`))),
    install: () => {
      fs.mkdirSync(rulesDir, { recursive: true });
      const src = windsurfRuleSourceDir();
      if (!src) return;
      for (const name of WINDSURF_RULE_SKILLS) {
        const from = path.join(src, `${name}.md`);
        if (fs.existsSync(from)) {
          fs.copyFileSync(from, path.join(rulesDir, `${name}.md`));
        }
      }
    },
    uninstall: () => {
      for (const name of WINDSURF_RULE_SKILLS) {
        const p = path.join(rulesDir, `${name}.md`);
        if (fs.existsSync(p)) fs.rmSync(p, { force: true });
      }
    },
  };
}

function windsurfMcp(): ComponentSpec {
  const home = os.homedir();
  const mcpPath = path.join(home, ".codeium", "windsurf", "mcp_config.json");
  return {
    id: "windsurf.mcp",
    platform: "windsurf",
    kind: "mcp",
    description: "Windsurf MCP server entry",
    detectDir: path.join(home, ".codeium", "windsurf"),
    path: mcpPath,
    isInstalled: () => {
      if (!fs.existsSync(mcpPath)) return false;
      const cfg = readJson(mcpPath);
      return !!cfg.mcpServers?.rafter;
    },
    install: () => {
      const dir = path.join(home, ".codeium", "windsurf");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const cfg: Record<string, any> = fs.existsSync(mcpPath) ? readJson(mcpPath) : {};
      cfg.mcpServers ??= {};
      cfg.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };
      writeJson(mcpPath, cfg);
    },
    uninstall: () => {
      if (!fs.existsSync(mcpPath)) return;
      const cfg = readJson(mcpPath);
      if (removeKey(cfg.mcpServers, "rafter")) writeJson(mcpPath, cfg);
    },
  };
}

/** Skills shipped as Continue.dev rules at .continue/rules/<skill>.md (rf-acz0). */
const CONTINUE_RULE_SKILLS = [
  "rafter",
  "rafter-secure-design",
  "rafter-code-review",
  "rafter-skill-review",
] as const;

function continueRuleSourceDir(): string | null {
  const candidates = [
    path.resolve(__dirname, "..", "..", "..", "resources", "continue-rules"),
    path.resolve(__dirname, "..", "..", "resources", "continue-rules"),
  ];
  return candidates.find((p) => fs.existsSync(p)) ?? null;
}

/** Continue.dev rules component: .continue/rules/<skill>.md, workspace-scope (rf-acz0). */
function continueRules(): ComponentSpec {
  const home = os.homedir();
  const rulesDir = path.join(process.cwd(), ".continue", "rules");
  return {
    id: "continue.rules",
    platform: "continue",
    kind: "instructions",
    description: "Continue.dev per-skill rules (.continue/rules/*.md, workspace-scope)",
    detectDir: path.join(home, ".continue"),
    path: rulesDir,
    isInstalled: () =>
      CONTINUE_RULE_SKILLS.every((n) => fs.existsSync(path.join(rulesDir, `${n}.md`))),
    install: () => {
      fs.mkdirSync(rulesDir, { recursive: true });
      const src = continueRuleSourceDir();
      if (!src) return;
      for (const name of CONTINUE_RULE_SKILLS) {
        const from = path.join(src, `${name}.md`);
        if (fs.existsSync(from)) {
          fs.copyFileSync(from, path.join(rulesDir, `${name}.md`));
        }
      }
    },
    uninstall: () => {
      for (const name of CONTINUE_RULE_SKILLS) {
        const p = path.join(rulesDir, `${name}.md`);
        if (fs.existsSync(p)) fs.rmSync(p, { force: true });
      }
    },
  };
}

function continueMcp(): ComponentSpec {
  const home = os.homedir();
  const configPath = path.join(home, ".continue", "config.json");
  return {
    id: "continue.mcp",
    platform: "continue",
    kind: "mcp",
    description: "Continue.dev MCP server entry (~/.continue/config.json)",
    detectDir: path.join(home, ".continue"),
    path: configPath,
    isInstalled: () => {
      if (!fs.existsSync(configPath)) return false;
      const cfg = readJson(configPath);
      const servers = cfg.mcpServers;
      if (Array.isArray(servers)) return servers.some((s: any) => s?.name === "rafter");
      if (servers && typeof servers === "object") return !!servers.rafter;
      return false;
    },
    install: () => {
      const dir = path.join(home, ".continue");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const cfg: Record<string, any> = fs.existsSync(configPath) ? readJson(configPath) : {};
      if (Array.isArray(cfg.mcpServers)) {
        cfg.mcpServers = cfg.mcpServers.filter((s: any) => s?.name !== "rafter");
        cfg.mcpServers.push({ name: "rafter", ...RAFTER_MCP_ENTRY });
      } else {
        cfg.mcpServers ??= {};
        cfg.mcpServers.rafter = { ...RAFTER_MCP_ENTRY };
      }
      writeJson(configPath, cfg);
    },
    uninstall: () => {
      if (!fs.existsSync(configPath)) return;
      const cfg = readJson(configPath);
      let changed = false;
      if (Array.isArray(cfg.mcpServers)) {
        const before = cfg.mcpServers.length;
        cfg.mcpServers = cfg.mcpServers.filter((s: any) => s?.name !== "rafter");
        changed = cfg.mcpServers.length !== before;
      } else if (cfg.mcpServers && typeof cfg.mcpServers === "object") {
        changed = removeKey(cfg.mcpServers, "rafter");
      }
      if (changed) writeJson(configPath, cfg);
    },
  };
}

/**
 * Hermes MCP server entry (~/.hermes/config.yaml).
 *
 * Hermes uses a YAML config with a snake_case `mcp_servers:` block (unlike the
 * camelCase `mcpServers` of Cursor/Windsurf/Claude Code). Per-server schema is
 * {command, args, env}. MCP-only v0 — hooks deferred pending confirmation
 * Hermes exposes a hook surface (sable-gyw).
 */
function hermesMcp(): ComponentSpec {
  const home = os.homedir();
  const configPath = path.join(home, ".hermes", "config.yaml");

  const readYaml = (): Record<string, any> => {
    if (!fs.existsSync(configPath)) return {};
    try {
      const loaded = yaml.load(fs.readFileSync(configPath, "utf-8"));
      if (loaded && typeof loaded === "object" && !Array.isArray(loaded)) {
        return loaded as Record<string, any>;
      }
    } catch { /* unparseable — treat as empty */ }
    return {};
  };

  return {
    id: "hermes.mcp",
    platform: "hermes",
    kind: "mcp",
    description: "Hermes MCP server entry (~/.hermes/config.yaml)",
    detectDir: path.join(home, ".hermes"),
    path: configPath,
    isInstalled: () => {
      const servers = readYaml().mcp_servers;
      return !!(servers && typeof servers === "object" && !Array.isArray(servers) && servers.rafter);
    },
    install: () => {
      const dir = path.join(home, ".hermes");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const cfg = readYaml();
      if (!cfg.mcp_servers || typeof cfg.mcp_servers !== "object" || Array.isArray(cfg.mcp_servers)) {
        cfg.mcp_servers = {};
      }
      cfg.mcp_servers.rafter = { ...RAFTER_MCP_ENTRY };
      fs.writeFileSync(configPath, yaml.dump(cfg), "utf-8");
    },
    uninstall: () => {
      if (!fs.existsSync(configPath)) return;
      const cfg = readYaml();
      const servers = cfg.mcp_servers;
      if (servers && typeof servers === "object" && !Array.isArray(servers) && removeKey(servers, "rafter")) {
        fs.writeFileSync(configPath, yaml.dump(cfg), "utf-8");
      }
    },
  };
}

/**
 * OpenCode MCP server entry (~/.config/opencode/opencode.json).
 *
 * OpenCode's schema differs from Cursor/Windsurf: the block is `mcp` (not
 * `mcpServers`), each local server carries `type: "local"`, and command + args
 * are a single `command` array. Verified against
 * https://opencode.ai/docs/mcp-servers/ (sable-l8e5).
 */
function openCodeMcp(): ComponentSpec {
  const home = os.homedir();
  const configPath = path.join(home, ".config", "opencode", "opencode.json");
  const entry = {
    type: "local" as const,
    command: [RAFTER_MCP_ENTRY.command, ...RAFTER_MCP_ENTRY.args],
    enabled: true,
  };
  return {
    id: "opencode.mcp",
    platform: "opencode",
    kind: "mcp",
    description: "OpenCode MCP server entry (~/.config/opencode/opencode.json)",
    detectDir: path.join(home, ".config", "opencode"),
    path: configPath,
    isInstalled: () => {
      if (!fs.existsSync(configPath)) return false;
      const cfg = readJson(configPath);
      return !!cfg.mcp?.rafter;
    },
    install: () => {
      const dir = path.join(home, ".config", "opencode");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const cfg: Record<string, any> = fs.existsSync(configPath) ? readJson(configPath) : {};
      if (!cfg.$schema) cfg.$schema = "https://opencode.ai/config.json";
      if (!cfg.mcp || typeof cfg.mcp !== "object" || Array.isArray(cfg.mcp)) cfg.mcp = {};
      cfg.mcp.rafter = { ...entry };
      writeJson(configPath, cfg);
    },
    uninstall: () => {
      if (!fs.existsSync(configPath)) return;
      const cfg = readJson(configPath);
      if (removeKey(cfg.mcp, "rafter")) writeJson(configPath, cfg);
    },
  };
}

/**
 * Aider read-only context: writes RAFTER.md and adds it to .aider.conf.yml `read:`.
 *
 * Replaces the prior `aider.mcp` component, pruned in rf-du2o because Aider
 * has no native MCP support — the legacy `mcp-server-command: rafter mcp serve`
 * line was a silent no-op (Aider ignores unknown YAML keys per its docs).
 *
 * Project-scope by design — RAFTER.md and the read entry land in cwd.
 */
function aiderRead(): ComponentSpec {
  const home = os.homedir();
  const cwd = process.cwd();
  const configPath = path.join(cwd, ".aider.conf.yml");
  const rafterMdPath = path.join(cwd, "RAFTER.md");
  const READ_ENTRY = "RAFTER.md";

  return {
    id: "aider.read",
    platform: "aider",
    kind: "instructions",
    description: "Aider read-only context (RAFTER.md + .aider.conf.yml read:)",
    detectDir: home,
    path: rafterMdPath,
    isInstalled: () => {
      if (!fs.existsSync(rafterMdPath)) return false;
      if (!fs.existsSync(configPath)) return false;
      const raw = fs.readFileSync(configPath, "utf-8");
      try {
        const parsed = yaml.load(raw) as any;
        const reads = Array.isArray(parsed?.read)
          ? parsed.read.map(String)
          : typeof parsed?.read === "string" ? [parsed.read] : [];
        return reads.includes(READ_ENTRY);
      } catch {
        return raw.includes(READ_ENTRY);
      }
    },
    install: () => {
      injectInstructionFile(rafterMdPath);
      let raw = fs.existsSync(configPath) ? fs.readFileSync(configPath, "utf-8") : "";
      // Strip legacy mcp-server-command silent-no-op (rf-du2o migration).
      raw = raw.replace(
        /\n?#\s*Rafter security MCP server\s*\nmcp-server-command:\s*rafter\s+mcp\s+serve\s*\n?/g,
        "\n",
      );
      raw = raw.replace(/^mcp-server-command:\s*rafter\s+mcp\s+serve\s*\n?/gm, "");

      let parsed: Record<string, any> = {};
      if (raw.trim().length > 0) {
        try {
          const loaded = yaml.load(raw);
          if (loaded && typeof loaded === "object" && !Array.isArray(loaded)) {
            parsed = loaded as Record<string, any>;
          }
        } catch {
          // Unparseable YAML — append safely without touching existing content.
          if (!new RegExp(`\\b${READ_ENTRY}\\b`).test(raw)) {
            const sep = raw.length > 0 && !raw.endsWith("\n") ? "\n" : "";
            fs.writeFileSync(configPath, `${raw}${sep}read:\n  - ${READ_ENTRY}\n`, "utf-8");
          }
          return;
        }
      }
      let reads: string[] = [];
      if (Array.isArray(parsed.read)) reads = parsed.read.map(String);
      else if (typeof parsed.read === "string") reads = [parsed.read];
      if (!reads.includes(READ_ENTRY)) reads.push(READ_ENTRY);
      parsed.read = reads;
      fs.writeFileSync(configPath, yaml.dump(parsed), "utf-8");
    },
    uninstall: () => {
      if (fs.existsSync(rafterMdPath)) {
        try { fs.rmSync(rafterMdPath, { force: true }); } catch { /* best-effort */ }
      }
      if (!fs.existsSync(configPath)) return;
      const raw = fs.readFileSync(configPath, "utf-8");
      try {
        const parsed = yaml.load(raw) as any;
        if (parsed && Array.isArray(parsed.read)) {
          parsed.read = parsed.read.filter((p: any) => String(p) !== READ_ENTRY);
          if (parsed.read.length === 0) delete parsed.read;
        } else if (parsed && parsed.read === READ_ENTRY) {
          delete parsed.read;
        }
        fs.writeFileSync(configPath, yaml.dump(parsed ?? {}), "utf-8");
      } catch {
        /* preserve unparseable file */
      }
    },
  };
}

function openclawSkill(): ComponentSpec {
  const home = os.homedir();
  const skillPath = path.join(home, ".openclaw", "skills", "rafter-security.md");
  return {
    id: "openclaw.skills",
    platform: "openclaw",
    kind: "skills",
    description: "OpenClaw rafter-security skill",
    detectDir: path.join(home, ".openclaw"),
    path: skillPath,
    isInstalled: () => fs.existsSync(skillPath),
    install: () => {
      const dir = path.dirname(skillPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const template = skillTemplatePath("rafter");
      if (fs.existsSync(template)) {
        fs.copyFileSync(template, skillPath);
      }
    },
    uninstall: () => {
      if (fs.existsSync(skillPath)) fs.rmSync(skillPath, { force: true });
    },
  };
}

// ── registry ───────────────────────────────────────────────────────────

let _registry: ComponentSpec[] | null = null;

export function getComponentRegistry(): ComponentSpec[] {
  if (!_registry) {
    _registry = [
      claudeCodeHooks(),
      claudeCodeInstructions(),
      claudeCodeSkills(),
      claudeCodeMcp(),
      codexHooks(),
      codexSkills(),
      cursorHooks(),
      cursorInstructions(),
      cursorMcp(),
      geminiHooks(),
      geminiMcp(),
      windsurfRules(),
      windsurfMcp(),
      continueRules(),
      continueMcp(),
      aiderRead(),
      hermesMcp(),
      openCodeMcp(),
      openclawSkill(),
    ];
  }
  return _registry;
}

/** Reset cached registry — tests use this when HOME changes. */
export function resetComponentRegistryCache(): void {
  _registry = null;
}

export function resolveComponent(id: string): ComponentSpec | undefined {
  const normalized = id.trim().toLowerCase();
  // Allow short aliases: "claude" for "claude-code", "continuedev" for "continue".
  const aliased = normalized
    .replace(/^claude\./, "claude-code.")
    .replace(/^continuedev\./, "continue.");
  return getComponentRegistry().find((c) => c.id === aliased);
}

/** Produce a structured status snapshot for every registered component. */
export function snapshotComponents(): ComponentStatus[] {
  const registry = getComponentRegistry();
  const cm = new ConfigManager();
  let cfg: any = {};
  try {
    cfg = cm.load();
  } catch {
    cfg = {};
  }
  const components = cfg.agent?.components ?? {};
  return registry.map((c) => {
    const detected = fs.existsSync(c.detectDir);
    const installed = c.isInstalled();
    const configEntry = components[c.id];
    const configEnabled = configEntry?.enabled ?? installed;
    const state: ComponentState = installed
      ? "installed"
      : detected
        ? "not-installed"
        : "not-detected";
    return {
      id: c.id,
      platform: c.platform,
      kind: c.kind,
      description: c.description,
      path: c.path,
      state,
      installed,
      detected,
      configEnabled,
    };
  });
}

/**
 * Update ~/.rafter/config.json to record that `id` was just installed (enabled=true)
 * or uninstalled (enabled=false). Safe to call multiple times; idempotent.
 *
 * Writes the full `agent.components` map in one shot rather than using dot-notation
 * `set("agent.components.<id>", ...)` — component IDs contain dots which the
 * dot-path setter would otherwise split into nested keys.
 */
export function recordComponentState(id: string, enabled: boolean): void {
  const cm = new ConfigManager();
  const existing = (cm.get("agent.components") ?? {}) as Record<string, any>;
  existing[id] = { enabled, updatedAt: new Date().toISOString() };
  cm.set("agent.components", existing);
}
