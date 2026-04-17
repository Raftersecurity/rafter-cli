import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";
import { ConfigManager } from "../../core/config-manager.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Rafter-authored skills that ship inside this package. Lifecycle commands
 * (`rafter skill list/install/uninstall`) only operate on names in this list —
 * the intent is to manage first-party skills, not arbitrary third-party files.
 */
export const KNOWN_SKILL_NAMES = [
  "rafter",
  "rafter-agent-security",
  "rafter-secure-design",
  "rafter-code-review",
] as const;

export type SkillPlatform = "claude-code" | "codex" | "openclaw" | "cursor";

export const SKILL_PLATFORMS: SkillPlatform[] = [
  "claude-code",
  "codex",
  "openclaw",
  "cursor",
];

export interface SkillMeta {
  name: string;
  version: string;
  description: string;
  sourcePath: string;
}

export interface SkillTarget {
  platform: SkillPlatform;
  detectDir: string;
  destPath: string;
}

function skillsResourcesRoot(): string {
  return path.join(__dirname, "..", "..", "..", "resources", "skills");
}

function parseFrontmatter(content: string): Record<string, string> {
  const match = content.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return {};
  const out: Record<string, string> = {};
  for (const line of match[1].split("\n")) {
    const m = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (!m) continue;
    let val = m[2].trim();
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
    else if (val.startsWith("'") && val.endsWith("'")) val = val.slice(1, -1);
    out[m[1]] = val;
  }
  return out;
}

/** Read frontmatter from a SKILL.md file on disk. Returns {} on any failure. */
export function readSkillFrontmatter(filePath: string): Record<string, string> {
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    return parseFrontmatter(content);
  } catch {
    return {};
  }
}

/** Enumerate bundled rafter-authored skills present in this installation. */
export function listBundledSkills(): SkillMeta[] {
  const root = skillsResourcesRoot();
  const skills: SkillMeta[] = [];
  for (const name of KNOWN_SKILL_NAMES) {
    const sourcePath = path.join(root, name, "SKILL.md");
    if (!fs.existsSync(sourcePath)) continue;
    const fm = readSkillFrontmatter(sourcePath);
    skills.push({
      name,
      version: fm.version ?? "unknown",
      description: fm.description ?? "",
      sourcePath,
    });
  }
  return skills;
}

export function resolveSkill(name: string): SkillMeta | undefined {
  const normalized = name.trim();
  return listBundledSkills().find((s) => s.name === normalized);
}

export function skillDetectDir(platform: SkillPlatform): string {
  const home = os.homedir();
  switch (platform) {
    case "claude-code":
      return path.join(home, ".claude");
    case "codex":
      return path.join(home, ".codex");
    case "openclaw":
      return path.join(home, ".openclaw");
    case "cursor":
      return path.join(home, ".cursor");
  }
}

/** Destination file path for a skill on a given platform. */
export function skillDestPath(platform: SkillPlatform, skillName: string): string {
  const home = os.homedir();
  switch (platform) {
    case "claude-code":
      return path.join(home, ".claude", "skills", skillName, "SKILL.md");
    case "codex":
      return path.join(home, ".agents", "skills", skillName, "SKILL.md");
    case "openclaw":
      return path.join(home, ".openclaw", "skills", `${skillName}.md`);
    case "cursor":
      return path.join(home, ".cursor", "rules", `${skillName}.mdc`);
  }
}

/** Resolve a --to argument to a concrete file path for a skill.
 *
 * Rules:
 *  - If `dest` ends in `.md` / `.mdc`, it's taken as the literal file path.
 *  - Otherwise `dest` is treated as a skills *base* directory, and the skill
 *    is written to `<dest>/<skill>/SKILL.md` (matches claude-code / codex layout).
 */
export function resolveExplicitDest(dest: string, skillName: string): string {
  const lower = dest.toLowerCase();
  if (lower.endsWith(".md") || lower.endsWith(".mdc")) return dest;
  return path.join(dest, skillName, "SKILL.md");
}

function ensureParent(filePath: string): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

/** Write a skill's SKILL.md to `destPath`. Creates parent directories as needed. */
export function writeSkillTo(skill: SkillMeta, destPath: string): void {
  ensureParent(destPath);
  fs.copyFileSync(skill.sourcePath, destPath);
}

/** Delete a skill file at `destPath`; prune the immediate parent dir if empty. */
export function deleteSkillAt(destPath: string): boolean {
  if (!fs.existsSync(destPath)) return false;
  fs.rmSync(destPath, { force: true });
  const parent = path.dirname(destPath);
  try {
    if (fs.existsSync(parent) && fs.readdirSync(parent).length === 0) {
      fs.rmdirSync(parent);
    }
  } catch {
    // non-empty or races — leave it
  }
  return true;
}

export interface InstalledSkillInfo {
  platform: SkillPlatform;
  name: string;
  path: string;
  version: string;
}

/** Snapshot of every (platform, skill) pair's install state on disk. */
export function snapshotSkills(): Array<{
  name: string;
  platform: SkillPlatform;
  detected: boolean;
  installed: boolean;
  path: string;
  version: string | null;
}> {
  const bundled = listBundledSkills();
  const rows: Array<{
    name: string;
    platform: SkillPlatform;
    detected: boolean;
    installed: boolean;
    path: string;
    version: string | null;
  }> = [];
  for (const skill of bundled) {
    for (const platform of SKILL_PLATFORMS) {
      const destPath = skillDestPath(platform, skill.name);
      const detected = fs.existsSync(skillDetectDir(platform));
      const installed = fs.existsSync(destPath);
      let version: string | null = null;
      if (installed) {
        const fm = readSkillFrontmatter(destPath);
        version = fm.version ?? null;
      }
      rows.push({
        name: skill.name,
        platform,
        detected,
        installed,
        path: destPath,
        version,
      });
    }
  }
  return rows;
}

/**
 * Record a skill's install/uninstall state in ~/.rafter/config.json under
 * `skills.<platform>.<name>`. Writes the whole `skills` map in one shot to
 * avoid splitting the skill name (which can contain hyphens but not dots) —
 * unlike component IDs, there's no dot-key hazard here, but we keep one
 * serialization path for consistency.
 */
export function recordSkillState(
  platform: SkillPlatform,
  name: string,
  enabled: boolean,
  version: string | null,
): void {
  const cm = new ConfigManager();
  const existing = (cm.get("skillInstallations") ?? {}) as Record<string, any>;
  existing[platform] ??= {};
  existing[platform][name] = {
    enabled,
    version: version ?? undefined,
    updatedAt: new Date().toISOString(),
  };
  cm.set("skillInstallations", existing);
}
