import fs from "fs";
import path from "path";
import crypto from "crypto";
import { execSync } from "child_process";
import { loadPolicy, PolicyDocEntry } from "./policy-loader.js";
import { getRafterDir } from "./config-defaults.js";

const DEFAULT_TTL_SECONDS = 86400;

export interface ResolvedDoc extends PolicyDocEntry {
  source: string;
  sourceKind: "path" | "url";
  cacheStatus: "local" | "cached" | "not-cached" | "stale";
  cachedPath?: string;
}

export interface FetchResult {
  content: string;
  cached: boolean;
  stale: boolean;
  source: string;
  sourceKind: "path" | "url";
}

function getCacheDir(): string {
  return path.join(getRafterDir(), "docs-cache");
}

function cacheKey(url: string): string {
  return crypto.createHash("sha256").update(url).digest("hex").slice(0, 32);
}

function cachePaths(url: string): { content: string; meta: string } {
  const dir = getCacheDir();
  const key = cacheKey(url);
  return {
    content: path.join(dir, `${key}.txt`),
    meta: path.join(dir, `${key}.meta.json`),
  };
}

function readCache(url: string): { content: string; fetchedAt: number } | null {
  const { content, meta } = cachePaths(url);
  if (!fs.existsSync(content) || !fs.existsSync(meta)) return null;
  try {
    const metaData = JSON.parse(fs.readFileSync(meta, "utf-8"));
    const body = fs.readFileSync(content, "utf-8");
    const fetchedAt = Date.parse(metaData.fetched_at);
    if (isNaN(fetchedAt)) return null;
    return { content: body, fetchedAt };
  } catch {
    return null;
  }
}

function writeCache(url: string, body: string, contentType: string): void {
  const dir = getCacheDir();
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const { content, meta } = cachePaths(url);
  fs.writeFileSync(content, body, "utf-8");
  fs.writeFileSync(meta, JSON.stringify({
    fetched_at: new Date().toISOString(),
    url,
    content_type: contentType,
  }, null, 2) + "\n", "utf-8");
}

function isExpired(fetchedAt: number, ttlSeconds: number): boolean {
  return Date.now() - fetchedAt > ttlSeconds * 1000;
}

function resolvePolicyPath(relative: string): string {
  if (path.isAbsolute(relative)) return relative;
  let root: string;
  try {
    root = execSync("git rev-parse --show-toplevel", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();
  } catch {
    root = process.cwd();
  }
  return path.resolve(root, relative);
}

/**
 * List docs from the active policy with resolution metadata.
 * Never performs network I/O.
 */
export function listDocs(entries?: PolicyDocEntry[]): ResolvedDoc[] {
  const policy = entries ? { docs: entries } : loadPolicy();
  const docs = policy?.docs || [];

  return docs.map(entry => {
    if (entry.path) {
      return {
        ...entry,
        source: entry.path,
        sourceKind: "path" as const,
        cacheStatus: "local" as const,
      };
    }
    const url = entry.url!;
    const ttl = entry.cache?.ttlSeconds ?? DEFAULT_TTL_SECONDS;
    const cached = readCache(url);
    const { content: cachedPath } = cachePaths(url);
    let cacheStatus: ResolvedDoc["cacheStatus"] = "not-cached";
    if (cached) {
      cacheStatus = isExpired(cached.fetchedAt, ttl) ? "stale" : "cached";
    }
    return {
      ...entry,
      source: url,
      sourceKind: "url" as const,
      cacheStatus,
      cachedPath: cached ? cachedPath : undefined,
    };
  });
}

/**
 * Resolve docs matching an id or tag. Exact id first, then any entry with that tag.
 */
export function resolveDocSelector(selector: string, entries?: PolicyDocEntry[]): PolicyDocEntry[] {
  const policy = entries ? { docs: entries } : loadPolicy();
  const docs = policy?.docs || [];
  const byId = docs.find(d => d.id === selector);
  if (byId) return [byId];
  return docs.filter(d => Array.isArray(d.tags) && d.tags.includes(selector));
}

export interface FetchOptions {
  refresh?: boolean;
}

/**
 * Return content for a doc entry, fetching URL docs on miss/expired/refresh.
 * On network failure with stale cache, returns stale content with stale=true.
 */
export async function fetchDoc(entry: PolicyDocEntry, opts: FetchOptions = {}): Promise<FetchResult> {
  if (entry.path) {
    const abs = resolvePolicyPath(entry.path);
    const content = fs.readFileSync(abs, "utf-8");
    return { content, cached: false, stale: false, source: entry.path, sourceKind: "path" };
  }

  const url = entry.url!;
  const ttl = entry.cache?.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  const cached = readCache(url);
  const fresh = cached && !isExpired(cached.fetchedAt, ttl);

  if (!opts.refresh && fresh) {
    return { content: cached.content, cached: true, stale: false, source: url, sourceKind: "url" };
  }

  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const body = await response.text();
    const contentType = response.headers.get("content-type") || "text/plain";
    writeCache(url, body, contentType);
    return { content: body, cached: false, stale: false, source: url, sourceKind: "url" };
  } catch (err) {
    if (cached) {
      return { content: cached.content, cached: true, stale: true, source: url, sourceKind: "url" };
    }
    throw err;
  }
}
