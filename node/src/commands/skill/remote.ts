// Remote source resolution and persistent cache for `rafter skill review`.
//
// Accepts three shorthands and a persistent cache, in addition to the local
// path / raw git URL forms already handled by review.ts:
//
//   github:owner/repo[/subpath]
//   gitlab:owner/repo[/subpath]
//   npm:<pkg>[@<version>]
//
// Cache layout under ~/.rafter/skill-cache/:
//
//   resolutions/<sha256(shorthand)>.json   — {shorthand, sha|version, resolvedAt}
//   content/<key>/                         — extracted working tree
//     meta.json                            — {source, key, sha|version, fetchedAt}
//
// The resolution cache memoizes "what SHA is github:foo/bar@HEAD right now?"
// The content cache memoizes "what does that SHA look like on disk?"
// Both expire on --cache-ttl (default 24h).

import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import zlib from "zlib";
import { spawnSync } from "child_process";
// tar@7 is dual CJS/ESM. We use its sync API (`tar.x({ sync, file, cwd, strip })`)
// so the rest of the reviewer stays synchronous.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
import * as tarModule from "tar";

export type ShorthandKind = "github" | "gitlab" | "npm";

export interface ParsedShorthand {
  kind: ShorthandKind;
  raw: string;
  // git-based:
  host?: string; // github.com | gitlab.com
  owner?: string;
  repo?: string;
  subpath?: string; // "" when absent
  gitUrl?: string; // https URL
  // npm-based:
  pkg?: string;
  version?: string; // "latest" when absent
}

export function isShorthand(input: string): boolean {
  return /^(github|gitlab|npm):/.test(input);
}

/**
 * Parse a shorthand source spec. Throws on malformed input.
 */
export function parseShorthand(input: string): ParsedShorthand {
  const m = input.match(/^(github|gitlab|npm):(.+)$/);
  if (!m) throw new Error(`Not a shorthand: ${input}`);
  const kind = m[1] as ShorthandKind;
  const tail = m[2];

  if (kind === "npm") {
    // Forms: pkg | pkg@version | @scope/pkg | @scope/pkg@version
    let pkg = tail;
    let version = "latest";
    if (tail.startsWith("@")) {
      // Scoped: locate the second '@' (after the scope)
      const secondAt = tail.indexOf("@", 1);
      if (secondAt !== -1) {
        pkg = tail.slice(0, secondAt);
        version = tail.slice(secondAt + 1) || "latest";
      }
    } else {
      const at = tail.indexOf("@");
      if (at !== -1) {
        pkg = tail.slice(0, at);
        version = tail.slice(at + 1) || "latest";
      }
    }
    if (!pkg) throw new Error(`Invalid npm shorthand: ${input}`);
    return { kind, raw: input, pkg, version };
  }

  // git-based: owner/repo[/subpath]
  const parts = tail.split("/").filter(Boolean);
  if (parts.length < 2) {
    throw new Error(
      `Invalid ${kind} shorthand: expected ${kind}:owner/repo[/subpath], got ${input}`,
    );
  }
  const owner = parts[0];
  const repo = parts[1];
  const subpath = parts.slice(2).join("/");
  const host = kind === "github" ? "github.com" : "gitlab.com";
  const gitUrl = `https://${host}/${owner}/${repo}.git`;
  return { kind, raw: input, host, owner, repo, subpath, gitUrl };
}

// ── Cache layout ───────────────────────────────────────────────────

export const DEFAULT_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24h

export function defaultCacheRoot(): string {
  // Honor RAFTER_SKILL_CACHE_DIR for tests.
  if (process.env.RAFTER_SKILL_CACHE_DIR) {
    return process.env.RAFTER_SKILL_CACHE_DIR;
  }
  return path.join(os.homedir(), ".rafter", "skill-cache");
}

export function resolutionPath(cacheRoot: string, shorthand: string): string {
  const hash = crypto.createHash("sha256").update(shorthand).digest("hex").slice(0, 40);
  return path.join(cacheRoot, "resolutions", `${hash}.json`);
}

export function contentDir(cacheRoot: string, key: string): string {
  return path.join(cacheRoot, "content", key);
}

function safeSlug(input: string): string {
  return input.replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 80);
}

export function contentKeyGit(parsed: ParsedShorthand, sha: string): string {
  const owner = safeSlug(parsed.owner ?? "unknown");
  const repo = safeSlug(parsed.repo ?? "unknown");
  return `git-${parsed.kind}-${owner}-${repo}-${sha.slice(0, 40)}`;
}

export function contentKeyNpm(pkg: string, version: string): string {
  return `npm-${safeSlug(pkg)}-${safeSlug(version)}`;
}

// ── Resolution cache ────────────────────────────────────────────────

export interface Resolution {
  shorthand: string;
  sha?: string; // git
  version?: string; // npm (resolved concrete version)
  resolvedAt: number; // epoch ms
}

export function readResolution(cacheRoot: string, shorthand: string): Resolution | null {
  const fpath = resolutionPath(cacheRoot, shorthand);
  if (!fs.existsSync(fpath)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(fpath, "utf-8"));
    if (
      typeof raw !== "object" ||
      raw === null ||
      typeof raw.shorthand !== "string" ||
      typeof raw.resolvedAt !== "number"
    ) {
      return null;
    }
    return raw as Resolution;
  } catch {
    return null;
  }
}

export function writeResolution(cacheRoot: string, res: Resolution): void {
  const fpath = resolutionPath(cacheRoot, res.shorthand);
  fs.mkdirSync(path.dirname(fpath), { recursive: true });
  fs.writeFileSync(fpath, JSON.stringify(res, null, 2));
}

export function resolutionIsFresh(r: Resolution, ttlMs: number): boolean {
  return Date.now() - r.resolvedAt < ttlMs;
}

// ── Content cache ──────────────────────────────────────────────────

export interface ContentMeta {
  source: "git" | "npm";
  shorthand: string;
  key: string;
  sha?: string;
  version?: string;
  fetchedAt: number;
}

export function readContentMeta(cacheRoot: string, key: string): ContentMeta | null {
  const dir = contentDir(cacheRoot, key);
  const meta = path.join(dir, "meta.json");
  if (!fs.existsSync(meta)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(meta, "utf-8"));
    if (
      typeof raw !== "object" ||
      raw === null ||
      typeof raw.source !== "string" ||
      typeof raw.key !== "string" ||
      typeof raw.fetchedAt !== "number"
    ) {
      return null;
    }
    return raw as ContentMeta;
  } catch {
    return null;
  }
}

export function contentWorkingTree(cacheRoot: string, key: string): string {
  return path.join(contentDir(cacheRoot, key), "content");
}

export function contentIsUsable(cacheRoot: string, key: string): boolean {
  const meta = readContentMeta(cacheRoot, key);
  if (!meta) return false;
  const tree = contentWorkingTree(cacheRoot, key);
  if (!fs.existsSync(tree)) return false;
  try {
    const entries = fs.readdirSync(tree);
    // Empty directory counts as corrupt — a real clone/extract leaves something.
    if (entries.length === 0) return false;
  } catch {
    return false;
  }
  return true;
}

export function dropCacheEntry(cacheRoot: string, key: string): void {
  const dir = contentDir(cacheRoot, key);
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // ignore
  }
}

// ── Network ops (injectable for tests) ────────────────────────────

export interface RemoteOps {
  gitLsRemoteHead(url: string): string; // returns SHA
  gitCloneAtSha(url: string, sha: string, destDir: string): void; // clone into destDir
  npmFetchMetadata(pkg: string): NpmMetadata;
  /** Sync: downloads the tarball (bytes) and writes it to destFile. */
  npmFetchTarball(tarballUrl: string, destFile: string): void;
}

export interface NpmMetadata {
  "dist-tags"?: Record<string, string>;
  versions?: Record<string, { dist?: { tarball?: string } }>;
}

export const defaultRemoteOps: RemoteOps = {
  gitLsRemoteHead(url: string): string {
    const r = spawnSync("git", ["ls-remote", url, "HEAD"], {
      encoding: "utf-8",
      timeout: 30_000,
    });
    if (r.status !== 0) {
      const err = (r.stderr ?? "").toString().trim() || "git ls-remote failed";
      throw new Error(`ls-remote ${url}: ${err}`);
    }
    const line = (r.stdout ?? "").split("\n")[0] ?? "";
    const sha = line.split(/\s+/)[0];
    if (!/^[0-9a-f]{40}$/i.test(sha)) {
      throw new Error(`ls-remote ${url}: could not parse SHA from "${line}"`);
    }
    return sha.toLowerCase();
  },
  gitCloneAtSha(url: string, sha: string, destDir: string): void {
    // Shallow clone then checkout the pinned SHA. We do a --depth 1 of default
    // branch first (fastest common case) and only fall back to a full fetch if
    // the target SHA isn't HEAD.
    fs.mkdirSync(destDir, { recursive: true });
    const r = spawnSync(
      "git",
      ["clone", "--depth", "1", "--quiet", url, destDir],
      { encoding: "utf-8", timeout: 120_000 },
    );
    if (r.status !== 0) {
      const err = (r.stderr ?? "").toString().trim() || "git clone failed";
      throw new Error(`clone ${url}: ${err}`);
    }
    // Best-effort: check that the resulting HEAD matches the expected SHA.
    // If not, fetch that specific SHA explicitly.
    const headR = spawnSync("git", ["rev-parse", "HEAD"], {
      cwd: destDir,
      encoding: "utf-8",
    });
    const head = (headR.stdout ?? "").trim().toLowerCase();
    if (head !== sha) {
      const fetchR = spawnSync(
        "git",
        ["fetch", "--depth", "1", "origin", sha],
        { cwd: destDir, encoding: "utf-8", timeout: 120_000 },
      );
      if (fetchR.status === 0) {
        spawnSync("git", ["checkout", "--quiet", sha], {
          cwd: destDir,
          encoding: "utf-8",
        });
      }
      // If the fetch failed we keep whatever HEAD we have — audit still works,
      // we just mismatched the resolved SHA. Record that in meta.
    }
  },
  npmFetchMetadata(pkg: string): NpmMetadata {
    const encoded = pkg.startsWith("@")
      ? `@${encodeURIComponent(pkg.slice(1))}`
      : encodeURIComponent(pkg);
    const url = `https://registry.npmjs.org/${encoded}`;
    return syncHttpJson(url) as NpmMetadata;
  },
  npmFetchTarball(tarballUrl: string, destFile: string): void {
    fs.mkdirSync(path.dirname(destFile), { recursive: true });
    // Spawn a short-lived node subprocess that awaits fetch() and streams the
    // tarball to destFile. Keeps the caller synchronous.
    const script = `
      (async () => {
        const fs = require('fs');
        const r = await fetch(${JSON.stringify(tarballUrl)});
        if (!r.ok) { process.stderr.write('HTTP ' + r.status); process.exit(2); }
        const buf = Buffer.from(await r.arrayBuffer());
        fs.writeFileSync(${JSON.stringify(destFile)}, buf);
      })().catch((e) => { process.stderr.write(String(e?.message || e)); process.exit(1); });
    `;
    const r = spawnSync(process.execPath, ["-e", script], {
      encoding: "utf-8",
      timeout: 120_000,
    });
    if (r.status !== 0) {
      throw new Error(
        `fetch ${tarballUrl}: ${(r.stderr ?? "").toString().trim() || "failed"}`,
      );
    }
  },
};

// Tiny blocking HTTP-GET-JSON helper. npm registry endpoints are small,
// latency-insensitive, and called at most once per audit — we do this inline
// rather than bolting an async path through the whole reviewer.
function syncHttpJson(url: string): unknown {
  // Node 18+ has global fetch, but it's async. For synchronous behavior we
  // spawn a short-lived node subprocess. This keeps review.ts synchronous.
  const script = `
    (async () => {
      const r = await fetch(${JSON.stringify(url)});
      if (!r.ok) { process.stderr.write("HTTP " + r.status); process.exit(2); }
      const txt = await r.text();
      process.stdout.write(txt);
    })().catch((e) => { process.stderr.write(String(e?.message || e)); process.exit(1); });
  `;
  const r = spawnSync(process.execPath, ["-e", script], {
    encoding: "utf-8",
    timeout: 30_000,
  });
  if (r.status !== 0) {
    throw new Error(`GET ${url}: ${(r.stderr ?? "").toString().trim() || "failed"}`);
  }
  try {
    return JSON.parse(r.stdout ?? "");
  } catch (e) {
    throw new Error(`GET ${url}: invalid JSON (${(e as Error).message})`);
  }
}

// ── Extraction helpers ─────────────────────────────────────────────

export function extractNpmTarball(tgzFile: string, destDir: string): void {
  fs.mkdirSync(destDir, { recursive: true });
  // npm tarballs have a leading "package/" directory; strip it.
  // tar@7 exposes a sync option that writes everything before returning.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (tarModule as any).x({ sync: true, file: tgzFile, cwd: destDir, strip: 1 });
}

/** Gunzip a .tgz file synchronously to a .tar, for fixture generation in tests. */
export function gunzipFile(src: string, dest: string): void {
  const zipped = fs.readFileSync(src);
  fs.writeFileSync(dest, zlib.gunzipSync(zipped));
}

// ── Multi-SKILL.md discovery ───────────────────────────────────────

export interface SkillLocation {
  /** path to the SKILL.md file, absolute */
  file: string;
  /** containing directory (used as audit scope), absolute */
  dir: string;
  /** directory path relative to the root of the fetched/passed tree */
  relDir: string;
}

const SKILL_WALK_SKIP = new Set([".git", "node_modules", ".venv", "__pycache__"]);
const SKILL_WALK_MAX_FILES = 5000;

/** Depth-first walk looking for every SKILL.md file. Deterministic order. */
export function findSkillFiles(root: string): SkillLocation[] {
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) return [];
  const out: SkillLocation[] = [];
  const stack: string[] = [root];
  let visited = 0;
  while (stack.length && visited < SKILL_WALK_MAX_FILES) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    // Sort for determinism (stack order reverses; pre-sort so pops ordered).
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of [...entries].reverse()) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKILL_WALK_SKIP.has(entry.name)) continue;
        stack.push(full);
      } else if (entry.isFile()) {
        visited += 1;
        if (entry.name.toLowerCase() === "skill.md") {
          const rel = path.relative(root, dir) || ".";
          out.push({ file: full, dir, relDir: rel });
        }
      }
    }
  }
  out.sort((a, b) => a.relDir.localeCompare(b.relDir));
  return out;
}
