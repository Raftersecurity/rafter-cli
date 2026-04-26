import fs from "fs";
import path from "path";

export interface SecretToPersist {
  /** Suggested env var name derived from pattern type, e.g. "STRIPE_LIVE_KEY". */
  baseName: string;
  /** Raw secret value to store. */
  value: string;
}

export interface PersistedSecret {
  /** Final env var name (may have a numeric suffix if base collided). */
  name: string;
  value: string;
  /** True if an identical name=value line was already present and we reused it. */
  alreadyPresent: boolean;
}

export interface EnvWriteResult {
  envFilePath: string;
  envFileCreated: boolean;
  gitignorePath: string;
  gitignoreCreated: boolean;
  gitignoreUpdated: boolean;
  written: PersistedSecret[];
}

/**
 * Persist secrets to a project-local .env and ensure .gitignore protects it.
 *
 * Idempotent on exact name=value matches: if .env already contains the same
 * value under some name, that existing name is reused instead of writing a
 * duplicate. New values get a fresh name (with a numeric suffix on collision).
 *
 * The .env is created in the given root (typically cwd). .gitignore is
 * located/created in the same root — we don't try to walk up to the git root
 * because that risks writing secrets into a .env shared with other projects.
 */
export function persistSecrets(
  secrets: SecretToPersist[],
  root: string
): EnvWriteResult {
  const envFilePath = path.join(root, ".env");
  const gitignorePath = path.join(root, ".gitignore");

  const envFileCreated = !fs.existsSync(envFilePath);
  const existing = envFileCreated
    ? new Map<string, string>()
    : parseEnvFile(fs.readFileSync(envFilePath, "utf-8"));

  const valueToExistingName = new Map<string, string>();
  for (const [k, v] of existing) {
    if (!valueToExistingName.has(v)) valueToExistingName.set(v, k);
  }

  const written: PersistedSecret[] = [];
  const linesToAppend: string[] = [];
  const seenInThisCall = new Map<string, string>(); // value -> name (within this batch)

  for (const secret of secrets) {
    // Reuse if same value already present in file
    const reuse = valueToExistingName.get(secret.value);
    if (reuse) {
      written.push({ name: reuse, value: secret.value, alreadyPresent: true });
      continue;
    }
    // Reuse if same value already chosen earlier in this call
    const sameBatch = seenInThisCall.get(secret.value);
    if (sameBatch) {
      written.push({ name: sameBatch, value: secret.value, alreadyPresent: true });
      continue;
    }

    const name = uniqueName(secret.baseName, existing, seenInThisCall);
    existing.set(name, secret.value);
    seenInThisCall.set(secret.value, name);
    linesToAppend.push(`${name}=${quoteValue(secret.value)}`);
    written.push({ name, value: secret.value, alreadyPresent: false });
  }

  if (linesToAppend.length > 0 || envFileCreated) {
    const header = envFileCreated
      ? `# Created by Rafter prompt-shield. Do not commit this file.\n`
      : "";
    const existingContent = envFileCreated ? "" : fs.readFileSync(envFilePath, "utf-8");
    const sep = existingContent.length > 0 && !existingContent.endsWith("\n") ? "\n" : "";
    const newContent =
      existingContent + sep + header + linesToAppend.join("\n") + (linesToAppend.length > 0 ? "\n" : "");
    fs.writeFileSync(envFilePath, newContent, { encoding: "utf-8", mode: 0o600 });
  }

  const gitignoreResult = ensureGitignored(gitignorePath, ".env");

  return {
    envFilePath,
    envFileCreated,
    gitignorePath,
    gitignoreCreated: gitignoreResult.created,
    gitignoreUpdated: gitignoreResult.updated,
    written,
  };
}

interface GitignoreResult {
  created: boolean;
  updated: boolean;
}

/**
 * Ensure `entry` (a single ignore pattern) is present in the .gitignore at
 * `gitignorePath`. Creates the file if missing. Idempotent.
 */
export function ensureGitignored(gitignorePath: string, entry: string): GitignoreResult {
  if (!fs.existsSync(gitignorePath)) {
    fs.writeFileSync(gitignorePath, `${entry}\n`, "utf-8");
    return { created: true, updated: true };
  }

  const content = fs.readFileSync(gitignorePath, "utf-8");
  if (gitignoreCovers(content, entry)) {
    return { created: false, updated: false };
  }

  const sep = content.length > 0 && !content.endsWith("\n") ? "\n" : "";
  fs.writeFileSync(gitignorePath, `${content}${sep}${entry}\n`, "utf-8");
  return { created: false, updated: true };
}

/**
 * Conservative check: does the .gitignore already cover `entry`? We match the
 * exact entry line (ignoring leading "/" and trailing whitespace, not full
 * gitignore-glob semantics — close enough for the .env case).
 */
function gitignoreCovers(content: string, entry: string): boolean {
  const target = entry.replace(/^\//, "").trim();
  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.replace(/^\//, "") === target) return true;
    // A bare wildcard like "*" or ".*" effectively covers .env too — treat as covered.
    if (line === "*") return true;
  }
  return false;
}

function parseEnvFile(content: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const name = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    out.set(name, value);
  }
  return out;
}

function uniqueName(
  base: string,
  existing: Map<string, string>,
  pending: Map<string, string>
): string {
  const sanitized = sanitizeName(base);
  if (!existing.has(sanitized) && !nameInPending(pending, sanitized)) {
    return sanitized;
  }
  for (let i = 1; i < 1000; i++) {
    const candidate = `${sanitized}_${i}`;
    if (!existing.has(candidate) && !nameInPending(pending, candidate)) {
      return candidate;
    }
  }
  return `${sanitized}_${Date.now()}`;
}

function nameInPending(pending: Map<string, string>, name: string): boolean {
  for (const v of pending.values()) {
    if (v === name) return true;
  }
  return false;
}

function sanitizeName(base: string): string {
  const cleaned = base
    .toUpperCase()
    .replace(/[^A-Z0-9_]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .replace(/_+/g, "_");
  if (!cleaned) return "RAFTER_SECRET";
  if (/^[0-9]/.test(cleaned)) return `RAFTER_${cleaned}`;
  return cleaned;
}

function quoteValue(value: string): string {
  // Quote if value contains whitespace, =, #, or quotes — keeps .env parsers happy.
  if (/[\s="'#$`\\]/.test(value)) {
    const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    return `"${escaped}"`;
  }
  return value;
}
