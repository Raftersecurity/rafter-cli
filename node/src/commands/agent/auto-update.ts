/**
 * The pretool hook's auto-update: after a CLI upgrade, bring installed skill,
 * rule and sub-agent files up to this version without waiting for the user to
 * run `rafter agent update`.
 *
 * It only rewrites files whose hash proves they hold rafter's own content (the
 * InstallSession policy); a file the user modified is kept, with the new
 * version written beside it as <file>.rafter-new and reported. Hooks, MCP
 * entries and instruction blocks are left to `rafter agent update`, so the
 * manifest keeps its old cliVersion and `agent status` still says to run it.
 *
 * Runs at most once a day per CLI version (stamp file), user scope only, never
 * throws, and writes nothing to stdout (stdout is the hook's decision).
 * RAFTER_DISABLE_AUTO_UPDATE=1 turns it off. Mirrors
 * python/rafter_cli/commands/auto_update.py.
 */
import fs from "fs";
import os from "os";
import path from "path";
import {
  FileArtifact,
  InstallSession,
  NEW_VERSION_SUFFIX,
  WHOLE_FILE_PLATFORMS,
  cleanupLegacyOpenClaw,
  cleanupRetiredRules,
  cliVersion,
  manifestPath,
  platformArtifacts,
} from "./install-files.js";
import { detectInstalledPlatforms, versionOlder } from "./update.js";

export const AUTO_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000;
/** A lock older than this is from a hook that died mid-update. */
const LOCK_STALE_MS = 60 * 1000;

export interface AutoUpdateResult {
  /** Files rewritten (or added to a skill that is installed) with this version's content. */
  updated: number;
  /** Modified files kept, each with a newer version waiting in <file>.rafter-new. */
  needsReconcile: string[];
  version: string;
}

export function autoUpdateStampPath(home: string): string {
  return path.join(home, ".rafter", ".update-check");
}

function readJson(p: string): any {
  try {
    return JSON.parse(fs.readFileSync(p, "utf-8"));
  } catch {
    return null;
  }
}

/** True when the stamp says this version was checked within the interval. */
function checkedRecently(home: string, version: string, now: number): boolean {
  const stamp = readJson(autoUpdateStampPath(home));
  return !!stamp && stamp.version === version && typeof stamp.checkedAt === "number" &&
    now - stamp.checkedAt >= 0 && now - stamp.checkedAt < AUTO_UPDATE_INTERVAL_MS;
}

function writeStamp(home: string, version: string, now: number): void {
  const p = autoUpdateStampPath(home);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify({ version, checkedAt: now }) + "\n", "utf-8");
}

/** Take the update lock; false when another hook holds a live one. */
function acquireLock(lock: string, now: number): boolean {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      fs.closeSync(fs.openSync(lock, "wx"));
      return true;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") return false;
      try {
        if (now - fs.statSync(lock).mtimeMs < LOCK_STALE_MS) return false;
        fs.unlinkSync(lock);
      } catch {
        return false;
      }
    }
  }
  return false;
}

/**
 * The installed unit an artifact belongs to: a skill directory for skill files,
 * otherwise the file itself. A unit with no file on disk was never installed or
 * was removed by the user, and the hook does not bring it back.
 */
function unitOf(a: FileArtifact): string {
  const m = a.resourceKey.match(/^skills\/([^/]+)\//);
  if (!m) return a.dest;
  const rel = a.resourceKey.slice("skills/".length + m[1].length + 1);
  return a.dest.slice(0, a.dest.length - rel.length - 1);
}

/**
 * Apply this CLI's whole-file content to the user-scope install if it is older.
 * Returns null when nothing ran (checked recently, already current, nothing
 * installed, disabled, or another hook is running it).
 */
export function maybeAutoUpdate(opts: { home?: string; now?: number; version?: string } = {}): AutoUpdateResult | null {
  if (/^(1|true|yes)$/i.test(process.env.RAFTER_DISABLE_AUTO_UPDATE ?? "")) return null;
  const home = opts.home ?? os.homedir();
  const now = opts.now ?? Date.now();
  const version = opts.version ?? cliVersion();
  if (checkedRecently(home, version, now)) return null;

  const recorded = readJson(manifestPath(home))?.cliVersion;
  if (typeof recorded === "string" && !versionOlder(recorded, version)) {
    writeStamp(home, version, now);
    return null;
  }
  const platforms = detectInstalledPlatforms(home, "user").filter((p) => (WHOLE_FILE_PLATFORMS as readonly string[]).includes(p));
  if (platforms.length === 0) {
    writeStamp(home, version, now);
    return null;
  }

  const lock = path.join(home, ".rafter", ".update-lock");
  fs.mkdirSync(path.dirname(lock), { recursive: true });
  if (!acquireLock(lock, now)) return null;
  try {
    // Stamp first: an update that fails is not retried on every tool call.
    writeStamp(home, version, now);
    const silent = { info: () => {}, warn: () => {} };
    const session = new InstallSession({ root: home, out: silent, version, keepManifestVersion: true });
    for (const platform of platforms) {
      const artifacts = platformArtifacts(platform, home);
      const present = new Set(artifacts.filter((a) => fs.existsSync(a.dest)).map(unitOf));
      session.applyAll(artifacts.filter((a) => present.has(unitOf(a))));
    }
    // Retired rule files and the legacy OpenClaw file go only when their hash
    // is rafter's. Retired skill directories are left to `agent update`: there
    // a publisher tag alone is enough to remove one, and that is not hash proof.
    if (platforms.includes("cursor")) cleanupRetiredRules(session, "cursor");
    if (platforms.includes("windsurf")) cleanupRetiredRules(session, "windsurf");
    if (platforms.includes("continue")) cleanupRetiredRules(session, "continue");
    if (platforms.includes("openclaw")) cleanupLegacyOpenClaw(session);
    session.save();
    return {
      updated: session.count("updated") + session.count("added"),
      needsReconcile: session.keptFiles(),
      version,
    };
  } finally {
    try {
      fs.unlinkSync(lock);
    } catch {
      /* already gone */
    }
  }
}

/** The one stderr line the hook prints after an auto-update; null when there is nothing to say. */
export function autoUpdateLine(r: AutoUpdateResult | null): string | null {
  if (!r || (r.updated === 0 && r.needsReconcile.length === 0)) return null;
  const parts: string[] = [];
  if (r.updated > 0) parts.push(`updated ${r.updated} skill/rule file${r.updated === 1 ? "" : "s"} to ${r.version}`);
  const n = r.needsReconcile.length;
  if (n > 0) {
    parts.push(
      `${n} file${n === 1 ? "" : "s"} you modified need${n === 1 ? "s" : ""} reconciling with ` +
      `${r.needsReconcile[0]}${NEW_VERSION_SUFFIX}${n > 1 ? " and others" : ""} (run 'rafter agent status')`,
    );
  }
  return `rafter: ${parts.join("; ")}`;
}

/** Hook entry point: run the auto-update and print its line to stderr. Never throws. */
export function runHookAutoUpdate(): void {
  try {
    const line = autoUpdateLine(maybeAutoUpdate());
    if (line) process.stderr.write(line + "\n");
  } catch {
    /* the hook's decision is already written; an update failure must not change it */
  }
}
