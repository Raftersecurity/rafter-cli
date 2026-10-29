/**
 * Whole-file artifacts that `rafter agent init` installs (skill files and their
 * docs/, per-skill rule files, sub-agent files, the OpenClaw skill), and the
 * policy for writing them over whatever is already on disk.
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
import os from "os";
import path from "path";
import { createRequire } from "module";
import { fileURLToPath } from "url";
import { fmt } from "../../utils/formatter.js";
import { KNOWN_SKILL_NAMES, RETIRED_SKILL_NAMES, isRafterAuthoredSkillDir, removeRetiredSkills } from "../skill/registry.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export type FileOutcome = "added" | "updated" | "unchanged" | "kept" | "replaced" | "reconciled";

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
  /** sha256 of the content rafter last wrote for this path. */
  sha256: string;
  component: string;
  platform: string;
  cliVersion: string;
  /** Set while a modified file is kept: sha256 of the version waiting in <file>.rafter-new. */
  pendingSha?: string;
  /** sha256 of the shipped version the user's modified file was reconciled against. */
  reconciledWith?: string;
}

export interface InstallManifest {
  schema: number;
  /**
   * The CLI version that last installed or updated the whole integration;
   * null when only the hook's auto-update has written (see auto-update.ts).
   */
  cliVersion: string | null;
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

/** True when `p` itself is a symbolic link, dangling or not. */
export function isSymlink(p: string): boolean {
  try {
    return fs.lstatSync(p).isSymbolicLink();
  } catch {
    return false;
  }
}

/**
 * Write `p` without following a symlink at `p`: a temp file in the same
 * directory, renamed over it. rename replaces a link instead of writing
 * through it, so a link a repo planted at one of rafter's files cannot aim
 * the write at ~/.bashrc; the write is atomic too.
 */
function writeNoFollow(p: string, content: string | Buffer): void {
  const tmp = path.join(path.dirname(p), `.${path.basename(p)}.${crypto.randomBytes(6).toString("hex")}.tmp`);
  fs.writeFileSync(tmp, content, { flag: "wx" });
  try {
    fs.renameSync(tmp, p);
  } catch (e) {
    fs.rmSync(tmp, { force: true });
    throw e;
  }
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
  /** Project scope: the root is a repo, and nothing may be written outside it. */
  private readonly contained: boolean;
  readonly force: boolean;
  readonly dryRun: boolean;
  readonly out: InstallOutput;
  readonly version: string;
  readonly outcomes: Array<{ dest: string; outcome: FileOutcome }> = [];
  private manifestCache: InstallManifest | null = null;
  /** cliVersion the manifest on disk names, kept on save when keepManifestVersion is set. */
  private loadedVersion: string | null = null;
  private readonly keepManifestVersion: boolean;
  private dirty = false;
  private virtual = new Map<string, Buffer>();

  /**
   * keepManifestVersion: save() keeps the manifest's cliVersion instead of
   * stamping this CLI's. The hook's auto-update sets it: it refreshes skill and
   * rule files only, so the install as a whole (hooks, MCP, instruction blocks)
   * is still the old version until `rafter agent update` runs (null when the
   * manifest had none).
   */
  constructor(opts: {
    root: string;
    out: InstallOutput;
    force?: boolean;
    dryRun?: boolean;
    version?: string;
    keepManifestVersion?: boolean;
  }) {
    this.root = opts.root;
    this.contained = path.resolve(opts.root) !== path.resolve(os.homedir());
    this.keepManifestVersion = !!opts.keepManifestVersion;
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
        if (typeof doc.cliVersion === "string") this.loadedVersion = doc.cliVersion;
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
    // A symlink is never written through: what sits at its target is not
    // rafter's to update, and a dangling one is not a free path to create.
    const link = !this.virtual.has(a.dest) && isSymlink(a.dest);
    if (current === null && !link) return "added";
    if (current?.equals(a.content)) return "unchanged";
    if (current !== null && !link && this.owns(a.dest, a.resourceKey, current)) return "updated";
    if (this.force || MODIFIED_FILE_POLICY === "replace-with-backup") return "replaced";
    // A modified file. The user reconciles it by merging into <file>.rafter-new
    // and moving that over the file (it then matches, above), or by deleting
    // <file>.rafter-new to keep their own version: that is "reconciled" once,
    // then "unchanged" until a release ships a different version.
    const entry = this.manifest.files[manifestKey(this.root, a.dest)];
    const newSha = sha256(a.content);
    if (!fs.existsSync(a.dest + NEW_VERSION_SUFFIX)) {
      if (entry?.reconciledWith === newSha) return "unchanged";
      if (entry?.pendingSha === newSha) return "reconciled";
    }
    return "kept";
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

  /**
   * Record reconcile state for a modified file without claiming its content.
   * With no prior entry, sha256 is the version just written to .rafter-new:
   * rafter's content, so it never matches the user's file and owns() stays false.
   */
  private recordReconcile(a: FileArtifact, state: { pendingSha?: string; reconciledWith?: string }): void {
    const key = manifestKey(this.root, a.dest);
    const prev = this.manifest.files[key];
    this.manifest.files[key] = {
      sha256: prev?.sha256 ?? sha256(a.content),
      component: a.component,
      platform: a.platform,
      cliVersion: prev?.cliVersion ?? this.version,
      ...state,
    };
    this.dirty = true;
  }

  /**
   * Whether <dest>.rafter-new may be (re)written: it is absent or holds a
   * version rafter wrote. Anything else is the user's merge in progress.
   */
  private mayWriteNewVersion(a: FileArtifact): boolean {
    let existing: Buffer;
    try {
      existing = fs.readFileSync(a.dest + NEW_VERSION_SUFFIX);
    } catch {
      return true;
    }
    const sha = sha256(existing);
    return existing.equals(a.content) ||
      this.manifest.files[manifestKey(this.root, a.dest)]?.pendingSha === sha ||
      (shippedHashes().get(a.resourceKey)?.has(sha) ?? false);
  }

  /** Drop a leftover <dest>.rafter-new that holds exactly what is now installed. */
  private dropStaleNewVersion(a: FileArtifact): void {
    const pending = a.dest + NEW_VERSION_SUFFIX;
    try {
      if (fs.readFileSync(pending).equals(a.content)) fs.unlinkSync(pending);
    } catch {
      /* absent or unreadable: nothing to drop */
    }
  }

  /** Install one artifact under the write policy (or, in a dry run, predict it). */
  apply(a: FileArtifact): FileOutcome {
    const outcome = this.classify(a);
    this.outcomes.push({ dest: a.dest, outcome });
    if (this.dryRun) {
      if (outcome === "added" || outcome === "updated" || outcome === "replaced") this.virtual.set(a.dest, a.content);
      return outcome;
    }
    this.makeDir(path.dirname(a.dest));
    switch (outcome) {
      case "added":
      case "updated":
        writeNoFollow(a.dest, a.content);
        this.record(a);
        this.dropStaleNewVersion(a);
        break;
      case "unchanged":
        // Unchanged is also a modified file already reconciled against this
        // version; only a file that holds rafter's content is recorded as such.
        if (this.read(a.dest)?.equals(a.content)) {
          this.record(a);
          this.dropStaleNewVersion(a);
        }
        break;
      case "replaced":
        // Moving the old file (or link) aside, not copying it, never reads or writes through a link.
        fs.renameSync(a.dest, a.dest + BACKUP_SUFFIX);
        writeNoFollow(a.dest, a.content);
        this.record(a);
        break;
      case "reconciled":
        this.recordReconcile(a, { reconciledWith: sha256(a.content) });
        break;
      case "kept":
        if (this.mayWriteNewVersion(a)) {
          writeNoFollow(a.dest + NEW_VERSION_SUFFIX, a.content);
          this.recordReconcile(a, { pendingSha: sha256(a.content) });
        }
        break;
    }
    if (outcome !== "unchanged") reportOutcome(this.out, a.dest, outcome);
    return outcome;
  }

  /**
   * mkdir -p, refusing in project scope when the directory resolves outside
   * the root: a repo can make `.claude/skills` a link to anywhere.
   */
  private makeDir(dir: string): void {
    if (!this.contained) {
      fs.mkdirSync(dir, { recursive: true });
      return;
    }
    const root = fs.realpathSync(this.root);
    const check = (d: string) => {
      const real = fs.realpathSync(d);
      if (real !== root && !real.startsWith(root + path.sep)) {
        throw new Error(`refusing to write in ${dir}: it resolves to ${real}, outside ${this.root}`);
      }
    };
    let existing = dir;
    while (!fs.existsSync(existing)) existing = path.dirname(existing);
    check(existing);
    fs.mkdirSync(dir, { recursive: true });
    check(dir);
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
    this.makeDir(path.dirname(p));
    const files = Object.fromEntries(Object.entries(this.manifest.files).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
    const version = this.keepManifestVersion ? this.loadedVersion : this.version;
    const doc: InstallManifest = { schema: MANIFEST_SCHEMA, cliVersion: version, files };
    writeNoFollow(p, JSON.stringify(doc, null, 2) + "\n");
    this.dirty = false;
  }

  count(outcome: FileOutcome): number {
    return this.outcomes.filter((o) => o.outcome === outcome).length;
  }

  /** Files kept as modified, each once (Codex and Gemini share .agents/skills). */
  keptFiles(): string[] {
    return [...new Set(this.outcomes.filter((o) => o.outcome === "kept").map((o) => o.dest))];
  }
}

export function outcomeLine(dest: string, outcome: FileOutcome): string {
  const label = outcome.padEnd(9);
  if (outcome === "kept") return `${label} ${dest} (modified; new version at ${dest}${NEW_VERSION_SUFFIX})`;
  if (outcome === "replaced") return `${label} ${dest} (backup at ${dest}${BACKUP_SUFFIX})`;
  if (outcome === "reconciled") return `${label} ${dest} (${NEW_VERSION_SUFFIX} gone; your version is kept for this release)`;
  return `${label} ${dest}`;
}

/**
 * One line per file that changed or needs attention; unchanged files are
 * summed into one line instead (reportUnchangedSummary). kept / replaced
 * print even under --quiet (to stderr).
 */
export function reportOutcome(out: InstallOutput, dest: string, outcome: FileOutcome): void {
  const line = outcomeLine(dest, outcome);
  if (outcome === "kept" || outcome === "replaced") out.warn(fmt.warning(line));
  else out.info(fmt.success(line));
}

export function unchangedLine(n: number): string {
  return `${n} file${n === 1 ? "" : "s"} unchanged`;
}

export function reportUnchangedSummary(session: InstallSession): void {
  const n = session.count("unchanged");
  if (n > 0) session.out.info(fmt.success(unchangedLine(n)));
}

export const FORCE_HINT = `re-run with --force (the old version is saved as ${BACKUP_SUFFIX})`;

/** The one-line instruction for reconciling a kept file; `updateCommand` is the command that records it. */
export function reconcileInstruction(updateCommand: string = "rafter agent update"): string {
  return `To reconcile: merge your changes into <file>${NEW_VERSION_SUFFIX}, move it over <file>, then run '${updateCommand}' ` +
    `(or delete <file>${NEW_VERSION_SUFFIX} to keep yours as is).`;
}

/**
 * Closing hint when any modified files were kept: the reconcile instruction,
 * and `replaceHint`, how to discard the local changes instead.
 */
export function reportKeptSummary(
  session: InstallSession,
  replaceHint: string = FORCE_HINT,
  updateCommand: string = "rafter agent update",
): void {
  const n = session.keptFiles().length;
  if (n === 0) return;
  session.out.warn(fmt.warning(
    `${n} installed file${n === 1 ? "" : "s"} had local changes and ${n === 1 ? "was" : "were"} kept; ` +
    `rafter's new version is beside ${n === 1 ? "it" : "each"} as <file>${NEW_VERSION_SUFFIX}. ` +
    `${reconcileInstruction(updateCommand)} To discard your changes instead, ${replaceHint}.`,
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

/**
 * The OpenClaw skill, at the ClawHub workspace path OpenClaw discovers
 * (<home>/.openclaw/workspace/skills/rafter-security/SKILL.md). User scope only.
 */
export function openclawSkillArtifacts(home: string, out?: InstallOutput): FileArtifact[] {
  const src = path.join(resourcesDir(), "rafter-security-skill.md");
  if (!fs.existsSync(src)) {
    out?.warn(fmt.warning(`OpenClaw skill template not found at ${src}`));
    return [];
  }
  return [{
    dest: openclawSkillPath(home),
    content: fs.readFileSync(src),
    resourceKey: "rafter-security-skill.md",
    component: "openclaw.skills",
    platform: "openclaw",
  }];
}

export function openclawSkillPath(home: string): string {
  return path.join(home, ".openclaw", "workspace", "skills", "rafter-security", "SKILL.md");
}

/**
 * Where rafter ≤ 0.7.7 put the OpenClaw skill, a path OpenClaw never reads.
 * Removed only when it hashes to content rafter shipped.
 */
export function openclawLegacySkillPath(home: string): string {
  return path.join(home, ".openclaw", "skills", "rafter-security.md");
}

// ── retired artifacts ────────────────────────────────────────────────

/** Remove the legacy OpenClaw skill file if it hashes to rafter's own content; otherwise keep and report it. */
export function cleanupLegacyOpenClaw(session: InstallSession): RetiredResult {
  const result: RetiredResult = { removed: [], kept: [] };
  const dest = openclawLegacySkillPath(session.root);
  if (!fs.existsSync(dest)) return result;
  if (session.owns(dest, "rafter-security-skill.md", fs.readFileSync(dest))) {
    result.removed.push(dest);
    if (!session.dryRun) {
      fs.unlinkSync(dest);
      session.forget(dest);
      session.out.info(fmt.info(`Removed legacy ${dest} (OpenClaw reads ${openclawSkillPath(session.root)})`));
    }
  } else {
    result.kept.push(dest);
    if (!session.dryRun) {
      session.out.warn(fmt.warning(`Kept legacy ${dest} (modified; OpenClaw never reads it, remove it yourself)`));
    }
  }
  const dir = path.dirname(dest);
  if (!session.dryRun && result.removed.length > 0) {
    try {
      if (fs.readdirSync(dir).length === 0) fs.rmdirSync(dir);
    } catch {
      /* best-effort */
    }
  }
  return result;
}

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

// ── per-platform artifact sets ───────────────────────────────────────

/** Platforms that install whole-file artifacts, in init's install order. */
export const WHOLE_FILE_PLATFORMS = ["claude-code", "codex", "gemini", "cursor", "windsurf", "continue", "openclaw"] as const;

/** Every whole-file artifact `agent init` installs for `platform` under `root`. */
export function platformArtifacts(platform: string, root: string): FileArtifact[] {
  switch (platform) {
    case "claude-code":
      return [...skillArtifacts(path.join(root, ".claude", "skills"), "claude-code", "claude-code.skills"), ...claudeAgentArtifacts(root)];
    case "codex":
      return skillArtifacts(path.join(root, ".agents", "skills"), "codex", "codex.skills");
    case "gemini":
      return skillArtifacts(path.join(root, ".agents", "skills"), "gemini", "gemini.skills");
    case "cursor":
      return [...ruleArtifacts("cursor", root), ...cursorAgentArtifacts(root)];
    case "windsurf":
    case "continue":
      return ruleArtifacts(platform, root);
    case "openclaw":
      return openclawSkillArtifacts(root);
    default:
      return [];
  }
}
