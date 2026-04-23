import fs from "fs";
import path from "path";
import os from "os";
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
      settings.hooks.PostToolUse.push({ matcher: ".*", hooks: [post] });

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
      cfg.hooks.PreToolUse.push({ matcher: "Bash", hooks: [pre] });
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

function cursorHooks(): ComponentSpec {
  const home = os.homedir();
  const hooksPath = path.join(home, ".cursor", "hooks.json");
  return {
    id: "cursor.hooks",
    platform: "cursor",
    kind: "hooks",
    description: "Cursor hooks (~/.cursor/hooks.json)",
    detectDir: path.join(home, ".cursor"),
    path: hooksPath,
    isInstalled: () => {
      if (!fs.existsSync(hooksPath)) return false;
      const cfg = readJson(hooksPath);
      for (const entry of cfg.hooks?.beforeShellExecution ?? []) {
        if (String(entry?.command ?? "").includes("rafter hook pretool")) return true;
      }
      return false;
    },
    install: () => {
      const dir = path.join(home, ".cursor");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const cfg: Record<string, any> = fs.existsSync(hooksPath) ? readJson(hooksPath) : {};
      cfg.version ??= 1;
      cfg.hooks ??= {};
      cfg.hooks.beforeShellExecution ??= [];
      cfg.hooks.beforeShellExecution = filterOutRafter(
        cfg.hooks.beforeShellExecution,
        (e) => String(e?.command ?? "").includes("rafter hook pretool"),
      );
      cfg.hooks.beforeShellExecution.push({
        command: "rafter hook pretool --format cursor",
        type: "command",
        timeout: 5000,
      });
      writeJson(hooksPath, cfg);
    },
    uninstall: () => {
      if (!fs.existsSync(hooksPath)) return;
      const cfg = readJson(hooksPath);
      if (cfg.hooks?.beforeShellExecution) {
        cfg.hooks.beforeShellExecution = filterOutRafter(
          cfg.hooks.beforeShellExecution,
          (e) => String(e?.command ?? "").includes("rafter hook pretool"),
        );
      }
      writeJson(hooksPath, cfg);
    },
  };
}

function cursorInstructions(): ComponentSpec {
  const home = os.homedir();
  const filePath = path.join(home, ".cursor", "rules", "rafter-security.mdc");
  return {
    id: "cursor.instructions",
    platform: "cursor",
    kind: "instructions",
    description: "Cursor global rule block (~/.cursor/rules/rafter-security.mdc)",
    detectDir: path.join(home, ".cursor"),
    path: filePath,
    isInstalled: () => hasMarkerBlock(filePath),
    install: () => injectInstructionFile(filePath),
    uninstall: () => {
      if (!fs.existsSync(filePath)) return;
      // This file is ours — delete it rather than editing around the block.
      fs.rmSync(filePath, { force: true });
    },
  };
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
      s.hooks.BeforeTool.push({
        matcher: "shell|write_file",
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

function windsurfHooks(): ComponentSpec {
  const home = os.homedir();
  const hooksPath = path.join(home, ".windsurf", "hooks.json");
  return {
    id: "windsurf.hooks",
    platform: "windsurf",
    kind: "hooks",
    description: "Windsurf hooks (~/.windsurf/hooks.json)",
    detectDir: path.join(home, ".codeium", "windsurf"),
    path: hooksPath,
    isInstalled: () => {
      if (!fs.existsSync(hooksPath)) return false;
      const cfg = readJson(hooksPath);
      for (const entry of cfg.hooks?.pre_run_command ?? []) {
        if (String(entry?.command ?? "").includes("rafter hook pretool")) return true;
      }
      return false;
    },
    install: () => {
      const dir = path.join(home, ".windsurf");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const cfg: Record<string, any> = fs.existsSync(hooksPath) ? readJson(hooksPath) : {};
      cfg.hooks ??= {};
      cfg.hooks.pre_run_command ??= [];
      cfg.hooks.pre_write_code ??= [];
      cfg.hooks.pre_run_command = filterOutRafter(
        cfg.hooks.pre_run_command,
        (e) => String(e?.command ?? "").includes("rafter hook pretool"),
      );
      cfg.hooks.pre_write_code = filterOutRafter(
        cfg.hooks.pre_write_code,
        (e) => String(e?.command ?? "").includes("rafter hook pretool"),
      );
      cfg.hooks.pre_run_command.push({
        command: "rafter hook pretool --format windsurf",
        show_output: true,
      });
      cfg.hooks.pre_write_code.push({
        command: "rafter hook pretool --format windsurf",
        show_output: true,
      });
      writeJson(hooksPath, cfg);
    },
    uninstall: () => {
      if (!fs.existsSync(hooksPath)) return;
      const cfg = readJson(hooksPath);
      if (cfg.hooks?.pre_run_command) {
        cfg.hooks.pre_run_command = filterOutRafter(
          cfg.hooks.pre_run_command,
          (e) => String(e?.command ?? "").includes("rafter hook pretool"),
        );
      }
      if (cfg.hooks?.pre_write_code) {
        cfg.hooks.pre_write_code = filterOutRafter(
          cfg.hooks.pre_write_code,
          (e) => String(e?.command ?? "").includes("rafter hook pretool"),
        );
      }
      writeJson(hooksPath, cfg);
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

function continueHooks(): ComponentSpec {
  const home = os.homedir();
  const settingsPath = path.join(home, ".continue", "settings.json");
  return {
    id: "continue.hooks",
    platform: "continue",
    kind: "hooks",
    description: "Continue.dev PreToolUse + PostToolUse hooks",
    detectDir: path.join(home, ".continue"),
    path: settingsPath,
    isInstalled: () => {
      if (!fs.existsSync(settingsPath)) return false;
      const s = readJson(settingsPath);
      for (const entry of s.hooks?.PreToolUse ?? []) {
        if (hookEntryMatchesRafter(entry, "rafter hook pretool")) return true;
      }
      return false;
    },
    install: () => {
      const dir = path.join(home, ".continue");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const s: Record<string, any> = fs.existsSync(settingsPath) ? readJson(settingsPath) : {};
      s.hooks ??= {};
      s.hooks.PreToolUse ??= [];
      s.hooks.PostToolUse ??= [];
      const pre = { type: "command", command: "rafter hook pretool" };
      const post = { type: "command", command: "rafter hook posttool" };
      s.hooks.PreToolUse = filterOutRafter(
        s.hooks.PreToolUse,
        (e) => hookEntryMatchesRafter(e, "rafter hook pretool"),
      );
      s.hooks.PostToolUse = filterOutRafter(
        s.hooks.PostToolUse,
        (e) => hookEntryMatchesRafter(e, "rafter hook posttool"),
      );
      s.hooks.PreToolUse.push(
        { matcher: "Bash", hooks: [pre] },
        { matcher: "Write|Edit", hooks: [pre] },
      );
      s.hooks.PostToolUse.push({ matcher: ".*", hooks: [post] });
      writeJson(settingsPath, s);
    },
    uninstall: () => {
      if (!fs.existsSync(settingsPath)) return;
      const s = readJson(settingsPath);
      if (s.hooks?.PreToolUse) {
        s.hooks.PreToolUse = filterOutRafter(
          s.hooks.PreToolUse,
          (e) => hookEntryMatchesRafter(e, "rafter hook pretool"),
        );
      }
      if (s.hooks?.PostToolUse) {
        s.hooks.PostToolUse = filterOutRafter(
          s.hooks.PostToolUse,
          (e) => hookEntryMatchesRafter(e, "rafter hook posttool"),
        );
      }
      writeJson(settingsPath, s);
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

function aiderMcp(): ComponentSpec {
  const home = os.homedir();
  const configPath = path.join(home, ".aider.conf.yml");
  const mcpLineHeader = "# Rafter security MCP server";
  return {
    id: "aider.mcp",
    platform: "aider",
    kind: "mcp",
    description: "Aider MCP server entry (~/.aider.conf.yml)",
    // Aider has no config dir — its presence is the file itself. Point detectDir
    // at $HOME so the platform is always considered "present enough to install into".
    detectDir: home,
    path: configPath,
    isInstalled: () => {
      if (!fs.existsSync(configPath)) return false;
      return fs.readFileSync(configPath, "utf-8").includes("rafter mcp serve");
    },
    install: () => {
      const content = fs.existsSync(configPath) ? fs.readFileSync(configPath, "utf-8") : "";
      if (content.includes("rafter mcp serve")) return;
      const block = `\n${mcpLineHeader}\nmcp-server-command: rafter mcp serve\n`;
      fs.writeFileSync(configPath, content + block, "utf-8");
    },
    uninstall: () => {
      if (!fs.existsSync(configPath)) return;
      const content = fs.readFileSync(configPath, "utf-8");
      // Remove both the comment marker and the command line; preserve everything else.
      const lines = content.split("\n");
      const next = lines.filter((l) => {
        const t = l.trim();
        if (t === mcpLineHeader) return false;
        if (t.startsWith("mcp-server-command:") && t.includes("rafter mcp serve")) return false;
        return true;
      });
      fs.writeFileSync(configPath, next.join("\n"), "utf-8");
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
      codexHooks(),
      codexSkills(),
      cursorHooks(),
      cursorInstructions(),
      cursorMcp(),
      geminiHooks(),
      geminiMcp(),
      windsurfHooks(),
      windsurfMcp(),
      continueHooks(),
      continueMcp(),
      aiderMcp(),
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
