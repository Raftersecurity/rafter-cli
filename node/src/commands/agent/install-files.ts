/**
 * Whole-file artifacts that `rafter agent init` installs (skill files and their
 * docs/, per-skill rule files, sub-agent files), and the policy for writing
 * them over whatever is already on disk.
 *
 * A re-run used to overwrite these silently, so a user's hand edit vanished
 * behind the same "Installed" line as a fresh install. Now init overwrites a
 * file only when it can prove the file still holds rafter's own content:
 *
 *   - the install manifest, <root>/.rafter/installed.json, records the sha256
 *     of every file init wrote; or
 *   - resources/shipped-hashes.json lists the sha256 of every bundled resource
 *     in every published release (regenerate with scripts/gen-shipped-hashes.py),
 *     which covers installs made before the manifest existed.
 *
 * Anything else is treated as the user's and kept; the new version lands
 * beside it as <file>.rafter-new. Marker-block files (CLAUDE.md, AGENTS.md, ...)
 * and merged JSON/YAML configs are not whole-file artifacts and do not pass
 * through here. Mirrors python/rafter_cli/commands/install_files.py.
 */
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { createRequire } from "module";
import { fileURLToPath } from "url";
import { fmt } from "../../utils/formatter.js";
import { KNOWN_SKILL_NAMES, RETIRED_SKILL_NAMES, isRafterAuthoredSkillDir, removeRetiredSkills } from "../skill/registry.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export type FileOutcome = "added" | "updated" | "unchanged" | "kept" | "replaced";

/**
 * What init does with an installed file the user has modified (or that it
 * cannot prove it wrote). "keep" leaves the file alone and writes the new
 * version to <file>.rafter-new; "replace-with-backup" saves the old file as
 * <file>.bak and installs the new one, which is what --force does. Switching
 * the default is a one-line change here.
 */
export const MODIFIED_FILE_POLICY: "keep" | "replace-with-backup" = "keep";

export const MANIFEST_SCHEMA = 1;
export const NEW_VERSION_SUFFIX = ".rafter-new";
export const BACKUP_SUFFIX = ".bak";

export interface InstallOutput {
  info(message?: string): void;
  warn(message: string): void;
}

export interface FileArtifact {
  dest: string;
  content: Buffer;
  /** Key into shipped-hashes.json: resource path, or "<path>#<variant>" when transformed. */
  resourceKey: string;
  component: string;
  platform: string;
}

export interface ManifestEntry {
  sha256: string;
  component: string;
  platform: string;
  cliVersion: string;
}

export interface InstallManifest {
  schema: number;
  cliVersion: string;
  files: Record<string, ManifestEntry>;
}

export function sha256(data: Buffer | string): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

export function resourcesDir(): string {
  // src/commands/agent -> ../../../resources (dist/ has the same depth).
  return path.resolve(__dirname, "..", "..", "..", "resources");
}

export function cliVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    return require("../../../package.json").version as string;
  } catch {
    return "unknown";
  }
}

let shippedCache: Map<string, Set<string>> | null = null;

/** sha256 sets per resource key, from resources/shipped-hashes.json. Missing or bad file → empty (fail safe: files are kept). */
export function shippedHashes(): Map<string, Set<string>> {
  if (shippedCache) return shippedCache;
  const table = new Map<string, Set<string>>();
  try {
    const doc = JSON.parse(fs.readFileSync(path.join(resourcesDir(), "shipped-hashes.json"), "utf-8"));
    for (const [key, shas] of Object.entries(doc?.files ?? {})) {
      if (Array.isArray(shas)) table.set(key, new Set(shas as string[]));
    }
  } catch {
    /* fail safe */
  }
  shippedCache = table;
  return table;
}

export function manifestPath(root: string): string {
  return path.join(root, ".rafter", "installed.json");
}

/** Forward-slash path of `dest` relative to `root` (the manifest key). */
export function manifestKey(root: string, dest: string): string {
  const rel = path.relative(root, dest);
  const key = rel.startsWith("..") || path.isAbsolute(rel) ? path.resolve(dest) : rel;
  return key.split(path.sep).join("/");
}

/**
 * One init run's view of the install root: the manifest (loaded once, so a
 * corrupt file warns once), the --force / --dry-run switches, and every
 * outcome so far. In a dry run nothing is written; `virtual` holds what the
 * run would have written so a path planned twice (Codex and Gemini share
 * .agents/skills) is predicted the way the real run will see it.
 */
export class InstallSession {
  readonly root: string;
  readonly force: boolean;
  readonly dryRun: boolean;
  readonly out: InstallOutput;
  readonly version: string;
  readonly outcomes: Array<{ dest: string; outcome: FileOutcome }> = [];
  private manifestCache: InstallManifest | null = null;
  private dirty = false;
  private virtual = new Map<string, Buffer>();

  constructor(opts: { root: string; out: InstallOutput; force?: boolean; dryRun?: boolean; version?: string }) {
    this.root = opts.root;
    this.out = opts.out;
    this.force = !!opts.force;
    this.dryRun = !!opts.dryRun;
    this.version = opts.version ?? cliVersion();
  }

  get manifest(): InstallManifest {
    if (this.manifestCache) return this.manifestCache;
    const empty: InstallManifest = { schema: MANIFEST_SCHEMA, cliVersion: this.version, files: {} };
    const p = manifestPath(this.root);
    if (fs.existsSync(p)) {
      try {
        const doc = JSON.parse(fs.readFileSync(p, "utf-8"));
        if (!doc || typeof doc !== "object" || typeof doc.files !== "object" || doc.files === null || Array.isArray(doc.files)) {
          throw new Error("no files map");
        }
        empty.files = doc.files;
      } catch (e) {
        this.out.warn(fmt.warning(
          `Ignoring unreadable install manifest ${p} (${(e as Error).message}); ` +
          `installed files are checked against shipped versions instead.`,
        ));
      }
    }
    this.manifestCache = empty;
    return empty;
  }

  /** True when `data` at `dest` is provably content rafter wrote. */
  owns(dest: string, resourceKey: string, data: Buffer): boolean {
    const sha = sha256(data);
    const entry = this.manifest.files[manifestKey(this.root, dest)];
    if (entry && entry.sha256 === sha) return true;
    return shippedHashes().get(resourceKey)?.has(sha) ?? false;
  }

  private read(dest: string): Buffer | null {
    const v = this.virtual.get(dest);
    if (v) return v;
    try {
      return fs.readFileSync(dest);
    } catch {
      return null;
    }
  }

  /** The outcome writing `a` would have, without writing anything. */
  classify(a: FileArtifact): FileOutcome {
    const current = this.read(a.dest);
    if (current === null) return "added";
    if (current.equals(a.content)) return "unchanged";
    if (this.owns(a.dest, a.resourceKey, current)) return "updated";
    return this.force || MODIFIED_FILE_POLICY === "replace-with-backup" ? "replaced" : "kept";
  }

  private record(a: FileArtifact): void {
    this.manifest.files[manifestKey(this.root, a.dest)] = {
      sha256: sha256(a.content),
      component: a.component,
      platform: a.platform,
      cliVersion: this.version,
    };
    this.dirty = true;
  }

  /** Install one artifact under the write policy (or, in a dry run, predict it). */
  apply(a: FileArtifact): FileOutcome {
    const outcome = this.classify(a);
    this.outcomes.push({ dest: a.dest, outcome });
    if (this.dryRun) {
      if (outcome !== "kept") this.virtual.set(a.dest, a.content);
      return outcome;
    }
    fs.mkdirSync(path.dirname(a.dest), { recursive: true });
    switch (outcome) {
      case "added":
      case "updated":
        fs.writeFileSync(a.dest, a.content);
        this.record(a);
        break;
      case "unchanged":
        this.record(a);
        break;
      case "replaced":
        fs.copyFileSync(a.dest, a.dest + BACKUP_SUFFIX);
        fs.writeFileSync(a.dest, a.content);
        this.record(a);
        break;
      case "kept":
        fs.writeFileSync(a.dest + NEW_VERSION_SUFFIX, a.content);
        break;
    }
    reportOutcome(this.out, a.dest, outcome);
    return outcome;
  }

  applyAll(artifacts: FileArtifact[]): FileOutcome[] {
    return artifacts.map((a) => this.apply(a));
  }

  forget(dest: string): void {
    const key = manifestKey(this.root, dest);
    if (key in this.manifest.files) {
      delete this.manifest.files[key];
      this.dirty = true;
    }
  }

  forgetUnder(dir: string): void {
    const prefix = manifestKey(this.root, dir) + "/";
    for (const key of Object.keys(this.manifest.files)) {
      if (key.startsWith(prefix)) {
        delete this.manifest.files[key];
        this.dirty = true;
      }
    }
  }

  save(): void {
    if (this.dryRun || !this.dirty) return;
    const p = manifestPath(this.root);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    const files = Object.fromEntries(Object.entries(this.manifest.files).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
    const doc: InstallManifest = { schema: MANIFEST_SCHEMA, cliVersion: this.version, files };
    fs.writeFileSync(p, JSON.stringify(doc, null, 2) + "\n", "utf-8");
    this.dirty = false;
  }

  keptCount(): number {
    return this.outcomes.filter((o) => o.outcome === "kept").length;
  }
}

export function outcomeLine(dest: string, outcome: FileOutcome): string {
  const label = outcome.padEnd(9);
  if (outcome === "kept") return `${label} ${dest} (modified; new version at ${dest}${NEW_VERSION_SUFFIX})`;
  if (outcome === "replaced") return `${label} ${dest} (backup at ${dest}${BACKUP_SUFFIX})`;
  return `${label} ${dest}`;
}

/** kept / replaced need the user's attention, so they print even under --quiet (to stderr). */
export function reportOutcome(out: InstallOutput, dest: string, outcome: FileOutcome): void {
  const line = outcomeLine(dest, outcome);
  if (outcome === "kept" || outcome === "replaced") out.warn(fmt.warning(line));
  else out.info(fmt.success(line));
}

/** Closing hint when init kept any modified files. */
export function reportKeptSummary(session: InstallSession): void {
  const n = session.keptCount();
  if (n === 0) return;
  session.out.warn(fmt.warning(
    `${n} installed file${n === 1 ? "" : "s"} had local changes and ${n === 1 ? "was" : "were"} kept. ` +
    `Compare each with its ${NEW_VERSION_SUFFIX} copy, or re-run with --force to replace ` +
    `(the old version is saved as ${BACKUP_SUFFIX}).`,
  ));
}

// ── artifact builders ────────────────────────────────────────────────

const SKIP_NAMES = new Set(["__init__.py", "__pycache__"]);

function walkFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (SKIP_NAMES.has(entry.name)) continue;
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(p));
    else if (entry.isFile()) out.push(p);
  }
  return out;
}

/** Every file of every shipped skill (SKILL.md plus docs/), installed under `skillsDir`. */
export function skillArtifacts(skillsDir: string, platform: string, component: string, out?: InstallOutput): FileArtifact[] {
  const artifacts: FileArtifact[] = [];
  for (const name of KNOWN_SKILL_NAMES) {
    const src = path.join(resourcesDir(), "skills", name);
    if (!fs.existsSync(path.join(src, "SKILL.md"))) {
      out?.warn(fmt.warning(`${name} skill template not found at ${path.join(src, "SKILL.md")}`));
      continue;
    }
    for (const file of walkFiles(src)) {
      const rel = path.relative(src, file).split(path.sep).join("/");
      artifacts.push({
        dest: path.join(skillsDir, name, ...rel.split("/")),
        content: fs.readFileSync(file),
        resourceKey: `skills/${name}/${rel}`,
        component,
        platform,
      });
    }
  }
  return artifacts;
}

export const RULE_SKILLS: readonly string[] = ["rafter", "rafter-secure-design", "rafter-code-review", "rafter-skill-review"];

export type RuleKind = "cursor" | "windsurf" | "continue";

const RULE_LAYOUT: Record<RuleKind, { resDir: string; destDir: string[]; ext: string; component: string; label: string }> = {
  cursor: { resDir: "cursor-rules", destDir: [".cursor", "rules"], ext: ".mdc", component: "cursor.instructions", label: "Cursor" },
  windsurf: { resDir: "windsurf-rules", destDir: [".windsurf", "rules"], ext: ".md", component: "windsurf.rules", label: "Windsurf" },
  continue: { resDir: "continue-rules", destDir: [".continue", "rules"], ext: ".md", component: "continue.rules", label: "Continue.dev" },
};

export function ruleDest(kind: RuleKind, root: string, name: string): string {
  const l = RULE_LAYOUT[kind];
  return path.join(root, ...l.destDir, `${name}${l.ext}`);
}

export function ruleArtifacts(kind: RuleKind, root: string, out?: InstallOutput): FileArtifact[] {
  const l = RULE_LAYOUT[kind];
  const srcDir = path.join(resourcesDir(), l.resDir);
  if (!fs.existsSync(srcDir)) {
    out?.warn(fmt.warning(`${l.label} rule templates not found in resources/${l.resDir}`));
    return [];
  }
  const artifacts: FileArtifact[] = [];
  for (const name of RULE_SKILLS) {
    const src = path.join(srcDir, `${name}${l.ext}`);
    if (!fs.existsSync(src)) {
      out?.warn(fmt.warning(`${l.label} rule template missing: ${src}`));
      continue;
    }
    artifacts.push({
      dest: ruleDest(kind, root, name),
      content: fs.readFileSync(src),
      resourceKey: `${l.resDir}/${name}${l.ext}`,
      component: l.component,
      platform: kind,
    });
  }
  return artifacts;
}

/** Strip the Claude-Code `tools:` line from sub-agent frontmatter — Cursor doesn't have it. */
export function stripToolsFromFrontmatter(content: string): string {
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

/** Sub-agents shipped for Claude Code; keep in sync with the Python installer. */
export const CLAUDE_CODE_SUBAGENTS: readonly string[] = ["rafter"];

export function claudeAgentArtifacts(root: string, out?: InstallOutput): FileArtifact[] {
  const artifacts: FileArtifact[] = [];
  for (const name of CLAUDE_CODE_SUBAGENTS) {
    const src = path.join(resourcesDir(), "agents", `${name}.md`);
    if (!fs.existsSync(src)) {
      out?.warn(fmt.warning(`${name} sub-agent template not found at ${src}`));
      continue;
    }
    artifacts.push({
      dest: path.join(root, ".claude", "agents", `${name}.md`),
      content: fs.readFileSync(src),
      resourceKey: `agents/${name}.md`,
      component: "claude-code.agents",
      platform: "claude-code",
    });
  }
  return artifacts;
}

export function cursorAgentArtifacts(root: string, out?: InstallOutput): FileArtifact[] {
  const src = path.join(resourcesDir(), "agents", "rafter.md");
  if (!fs.existsSync(src)) {
    out?.warn(fmt.warning(`Rafter sub-agent template not found in resources/agents`));
    return [];
  }
  return [{
    dest: path.join(root, ".cursor", "agents", "rafter.md"),
    content: Buffer.from(stripToolsFromFrontmatter(fs.readFileSync(src, "utf-8")), "utf-8"),
    resourceKey: "agents/rafter.md#cursor",
    component: "cursor.instructions",
    platform: "cursor",
  }];
}

// ── retired artifacts ────────────────────────────────────────────────

/** Every file in `dir` is provably rafter's own content for skill `name`. */
function ownsSkillDir(session: InstallSession, dir: string, name: string): boolean {
  const files = walkFiles(dir);
  return files.length > 0 && files.every((f) => {
    const rel = path.relative(dir, f).split(path.sep).join("/");
    return session.owns(f, `skills/${name}/${rel}`, fs.readFileSync(f));
  });
}

export interface RetiredResult { removed: string[]; kept: string[] }

/**
 * Remove retired rafter skill directories under `skillsDir`. A directory goes
 * when its SKILL.md carries rafter's publisher tag or every file in it hashes
 * to content rafter shipped or recorded; anything else is the user's and is
 * kept (and reported). In a dry run, reports what would happen.
 */
export function cleanupRetiredSkills(
  session: InstallSession,
  skillsDir: string,
  names: readonly string[] = RETIRED_SKILL_NAMES,
): RetiredResult {
  const present = names.filter((n) => fs.existsSync(path.join(skillsDir, n, "SKILL.md")));
  if (present.length === 0) return { removed: [], kept: [] };
  const owned = (dir: string, name: string) => ownsSkillDir(session, dir, name);
  let removed: string[];
  if (session.dryRun) {
    removed = present.filter((n) => wouldRemoveSkill(path.join(skillsDir, n), n, owned));
  } else {
    removed = removeRetiredSkills(skillsDir, present, owned);
    for (const n of removed) session.forgetUnder(path.join(skillsDir, n));
  }
  const kept = present.filter((n) => !removed.includes(n));
  if (!session.dryRun) {
    for (const n of removed) session.out.info(fmt.info(`Removed retired skill ${n} from ${skillsDir}`));
    for (const n of kept) {
      session.out.warn(fmt.warning(
        `Kept retired skill ${path.join(skillsDir, n)} (modified or not rafter's; remove it yourself if unused)`,
      ));
    }
  }
  return { removed: removed.map((n) => path.join(skillsDir, n)), kept: kept.map((n) => path.join(skillsDir, n)) };
}

function wouldRemoveSkill(dir: string, name: string, owned: (dir: string, name: string) => boolean): boolean {
  // The predicate removeRetiredSkills applies, evaluated without deleting.
  return isRafterAuthoredSkillDir(dir) || owned(dir, name);
}

/** Remove retired per-skill rule files of `kind` that hash to rafter's own content; keep and report the rest. */
export function cleanupRetiredRules(
  session: InstallSession,
  kind: RuleKind,
  names: readonly string[] = RETIRED_SKILL_NAMES,
): RetiredResult {
  const result: RetiredResult = { removed: [], kept: [] };
  const l = RULE_LAYOUT[kind];
  for (const name of names) {
    const dest = ruleDest(kind, session.root, name);
    if (!fs.existsSync(dest)) continue;
    if (session.owns(dest, `${l.resDir}/${name}${l.ext}`, fs.readFileSync(dest))) {
      result.removed.push(dest);
      if (!session.dryRun) {
        fs.unlinkSync(dest);
        session.forget(dest);
        session.out.info(fmt.info(`Removed retired rule ${dest}`));
      }
    } else {
      result.kept.push(dest);
      if (!session.dryRun) {
        session.out.warn(fmt.warning(`Kept retired rule ${dest} (modified; remove it yourself if unused)`));
      }
    }
  }
  return result;
}
