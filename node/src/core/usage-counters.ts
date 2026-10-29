/**
 * Local-only usage counters (`~/.rafter/usage/<YYYY-MM-DD>.json`).
 *
 * Counts are keyed by allowlisted enums, counts and duration buckets only; the
 * allowlist is shared-docs/usage-counters.json, embedded below and checked
 * against that file by a test. Nothing here touches the network: the counters
 * stay on this machine until a person pastes `rafter telemetry show` output
 * somewhere.
 *
 * Recorders only add to an in-memory buffer; the buffer is written once, when
 * the process exits, by one read-modify-write of a tiny file (temp file +
 * rename). Concurrent rafter processes can therefore lose each other's
 * increments (last rename wins); they never leave a torn file, and an
 * unreadable file is replaced. Every entry point swallows its own errors and
 * none writes to stdout.
 *
 * Mirrors python/rafter_cli/core/usage_counters.py. Deleting this file, its
 * Python twin, the two `telemetry` command files and their one-line call sites
 * removes the feature.
 */
import fs from "fs";
import path from "path";
import type { Command } from "commander";
import { getConfigPath, getRafterDir } from "./config-defaults.js";

export const USAGE_SCHEMA = 1;

/** Same values as shared-docs/usage-counters.json (minus its prose description). */
export const USAGE_ALLOWLIST = {
  schema: 1,
  families: {
    unknown_command: ["unknown_command"],
    unknown_option: ["unknown_option"],
    command: ["command_path", "literal:exit", "exit"],
    hook: ["hook_tool", "hook_decision", "hook_risk"],
    scan_engine: ["scan_engine", "scan_engine"],
    scan_fallback: ["scan_fallback"],
    scan_duration: ["scan_engine", "duration_bucket"],
    error_class: ["command_path", "error_class"],
  } as Record<string, string[]>,
  patterns: {
    unknown_command: "^[a-z][a-z-]{0,31}$",
    unknown_option: "^--[a-z][a-z-]{0,31}$",
    command_path: "^[a-z][a-z0-9-]{0,31}(\\.[a-z][a-z0-9-]{0,31}){0,3}$",
    error_class: "^([A-Z][A-Za-z0-9]{0,29})?(Error|Exception|Exit|Interrupt)$",
  } as Record<string, string>,
  pattern_fallback: "other",
  enums: {
    exit: ["0", "1", "2", "other"],
    hook_tool: ["shell", "write", "other"],
    hook_decision: ["allow", "deny", "defer", "ask", "error"],
    hook_risk: ["low", "medium", "high", "critical", "none"],
    scan_engine: ["auto", "betterleaks", "patterns", "both"],
    scan_fallback: ["missing", "timeout", "error", "stale", "other"],
    duration_bucket: ["lt1s", "1-5s", "5-30s", "30-120s", "gt120s"],
  } as Record<string, string[]>,
  duration_bucket_edges_seconds: [1, 5, 30, 120],
  retention_days: 7,
};

export const USAGE_FAMILIES = Object.keys(USAGE_ALLOWLIST.families);
export const USAGE_STORE_DISPLAY = "~/.rafter/usage";
export const USAGE_NOTICE = "Nothing leaves this machine: these counts are stored locally and rafter has no code to upload them.";

const PATTERNS: Record<string, RegExp> = Object.fromEntries(
  Object.entries(USAGE_ALLOWLIST.patterns).map(([k, v]) => [k, new RegExp(v)]),
);
const FALLBACK = USAGE_ALLOWLIST.pattern_fallback;

/** Value for a pattern part: itself if it matches, else "other". */
function patterned(kind: string, value: unknown): string {
  return typeof value === "string" && PATTERNS[kind].test(value) ? value : FALLBACK;
}

function partAllowed(spec: string, part: string): boolean {
  if (spec.startsWith("literal:")) return part === spec.slice("literal:".length);
  if (spec in USAGE_ALLOWLIST.enums) return USAGE_ALLOWLIST.enums[spec].includes(part);
  if (spec in PATTERNS) return part === FALLBACK || PATTERNS[spec].test(part);
  return false;
}

/** True if every part of `key` is built from the allowlist. */
export function isAllowedKey(key: string): boolean {
  if (typeof key !== "string") return false;
  const [family, ...parts] = key.split(":");
  const spec = USAGE_ALLOWLIST.families[family];
  if (!spec || !Object.prototype.hasOwnProperty.call(USAGE_ALLOWLIST.families, family)) return false;
  return parts.length === spec.length && spec.every((s, i) => partAllowed(s, parts[i]));
}

// ── in-memory buffer ────────────────────────────────────────────────

const pending = new Map<string, number>();
let commandPath: string | null = null;
let discarded = false;

function bump(key: string): void {
  if (discarded || !isAllowedKey(key)) return;
  pending.set(key, (pending.get(key) ?? 0) + 1);
}

function guard(fn: () => void): void {
  try {
    fn();
  } catch {
    // Counting must never affect the command.
  }
}

/** Test hook: the keys buffered so far. */
export function pendingCounts(): Record<string, number> {
  return Object.fromEntries(pending);
}

/** Test hook: forget buffered counts and the command path. */
export function resetPending(): void {
  pending.clear();
  commandPath = null;
  discarded = false;
}

/** Drop everything buffered and stop counting for this process (`telemetry clear`). */
export function discardPending(): void {
  pending.clear();
  discarded = true;
}

// ── recorders ───────────────────────────────────────────────────────

export function countUnknownCommand(token: unknown): void {
  guard(() => bump(`unknown_command:${patterned("unknown_command", token)}`));
}

export function countUnknownOption(flag: unknown): void {
  guard(() => {
    const name = typeof flag === "string" ? flag.split("=")[0] : flag;
    bump(`unknown_option:${patterned("unknown_option", name)}`);
  });
}

/** Set the resolved command path from registered command names (not argv). */
export function setCommandPath(names: string[]): void {
  guard(() => {
    commandPath = patterned("command_path", names.length ? names.join(".") : "root");
  });
}

function currentPath(): string {
  return commandPath ?? "root";
}

export function exitBucket(code: unknown): string {
  return code === 0 || code === 1 || code === 2 ? String(code) : "other";
}

export function countHook(tool: unknown, decision: unknown, risk: unknown): void {
  guard(() => {
    const e = USAGE_ALLOWLIST.enums;
    const t = e.hook_tool.includes(tool as string) ? tool : "other";
    const d = e.hook_decision.includes(decision as string) ? decision : "error";
    const r = e.hook_risk.includes(risk as string) ? risk : "none";
    bump(`hook:${t}:${d}:${r}`);
  });
}

/** Map a free-text fall-back reason onto the enum. The text itself is never stored. */
export function classifyFallback(reason: unknown): string {
  const s = typeof reason === "string" ? reason.toLowerCase() : "";
  if (/timed out|timeout/.test(s)) return "timeout";
  if (/stale|update/.test(s)) return "stale";
  if (/not available|unavailable|not found|missing|enoent/.test(s)) return "missing";
  if (/fail|error|crash|exit/.test(s)) return "error";
  return "other";
}

export function durationBucket(ms: number): string {
  const s = ms / 1000;
  const [a, b, c, d] = USAGE_ALLOWLIST.duration_bucket_edges_seconds;
  if (s < a) return "lt1s";
  if (s < b) return "1-5s";
  if (s < c) return "5-30s";
  if (s < d) return "30-120s";
  return "gt120s";
}

/** Record one local scan from its engine report and elapsed time. */
export function countScan(
  report: { requested: string; used: string; degraded: boolean; reason?: string } | undefined,
  elapsedMs: number,
): void {
  guard(() => {
    if (!report) return;
    bump(`scan_engine:${report.requested}:${report.used}`);
    if (report.degraded) bump(`scan_fallback:${classifyFallback(report.reason)}`);
    bump(`scan_duration:${report.used}:${durationBucket(elapsedMs)}`);
  });
}

/** Record an uncaught error by class name only. */
export function countError(err: unknown): void {
  guard(() => {
    const name = err instanceof Error ? err.constructor?.name : typeof err;
    bump(`error_class:${currentPath()}:${patterned("error_class", name)}`);
  });
}

// ── settings ────────────────────────────────────────────────────────

export interface UsageStatus {
  enabled: boolean;
  /** "default" | "config" | "env:RAFTER_TELEMETRY" | "env:DO_NOT_TRACK" */
  source: string;
}

/**
 * Whether counting is on, and why. Read only from the environment and the
 * global ~/.rafter/config.json (`agent.usage.enabled`); a project .rafter.yml
 * is never consulted.
 */
export function usageStatus(env: NodeJS.ProcessEnv = process.env): UsageStatus {
  const rt = (env.RAFTER_TELEMETRY ?? "").trim().toLowerCase();
  if (rt === "0" || rt === "false" || rt === "off") return { enabled: false, source: "env:RAFTER_TELEMETRY" };
  const dnt = (env.DO_NOT_TRACK ?? "").trim().toLowerCase();
  if (dnt !== "" && dnt !== "0" && dnt !== "false") return { enabled: false, source: "env:DO_NOT_TRACK" };
  try {
    const cfg = JSON.parse(fs.readFileSync(getConfigPath(), "utf-8"));
    const v = cfg?.agent?.usage?.enabled;
    if (v === false) return { enabled: false, source: "config" };
    if (v === true) return { enabled: true, source: "config" };
  } catch {
    // Missing or unreadable config: the default applies.
  }
  return { enabled: true, source: "default" };
}

// ── store ───────────────────────────────────────────────────────────

export function usageDir(): string {
  return path.join(getRafterDir(), "usage");
}

export function utcDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

const DAY_FILE = /^(\d{4}-\d{2}-\d{2})\.json$/;

/** Allowlisted, positive-integer counts from one day file; {} if missing or corrupt. */
function readDay(file: string): Record<string, number> {
  const out: Record<string, number> = {};
  try {
    const raw = JSON.parse(fs.readFileSync(file, "utf-8"));
    if (!raw || typeof raw !== "object" || Array.isArray(raw) || raw.schema !== USAGE_SCHEMA) return out;
    for (const [k, v] of Object.entries(raw)) {
      if (k !== "schema" && isAllowedKey(k) && Number.isSafeInteger(v) && (v as number) > 0) out[k] = v as number;
    }
  } catch {
    // Missing or corrupt: treated as empty and replaced on the next write.
  }
  return out;
}

function prune(dir: string, today: string): void {
  const keep = USAGE_ALLOWLIST.retention_days;
  const oldest = utcDay(new Date(Date.parse(today) - (keep - 1) * 86_400_000));
  for (const name of fs.readdirSync(dir)) {
    try {
      const m = DAY_FILE.exec(name);
      if (m && m[1] < oldest) fs.unlinkSync(path.join(dir, name));
      else if (name.endsWith(".tmp") && Date.now() - fs.statSync(path.join(dir, name)).mtimeMs > 60_000) {
        fs.unlinkSync(path.join(dir, name));
      }
    } catch {
      // best effort
    }
  }
}

/** Add `counts` to today's file. Throws on I/O failure; callers guard. */
export function writeCounts(counts: Map<string, number> | Record<string, number>, now: Date = new Date()): void {
  const entries = counts instanceof Map ? [...counts] : Object.entries(counts);
  if (entries.length === 0) return;
  const dir = usageDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const day = utcDay(now);
  const file = path.join(dir, `${day}.json`);
  const firstToday = !fs.existsSync(file);
  const merged = readDay(file);
  for (const [k, n] of entries) {
    if (isAllowedKey(k) && Number.isSafeInteger(n) && n > 0) merged[k] = (merged[k] ?? 0) + n;
  }
  const body: Record<string, number> = { schema: USAGE_SCHEMA };
  for (const k of Object.keys(merged).sort()) body[k] = merged[k];
  const tmp = path.join(dir, `.${day}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`);
  try {
    fs.writeFileSync(tmp, JSON.stringify(body, null, 2) + "\n", { mode: 0o600 });
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch { /* already gone */ }
    throw e;
  }
  if (firstToday) {
    try { fs.chmodSync(dir, 0o700); } catch { /* best effort */ }
    prune(dir, day);
  }
}

/**
 * Record the command result and write the buffer, if counting is enabled.
 * Called once, at process exit.
 */
export function flush(exitCode: unknown): void {
  guard(() => {
    if (discarded) return;
    bump(`command:${currentPath()}:exit:${exitBucket(exitCode)}`);
    if (!usageStatus().enabled) return;
    writeCounts(pending);
    pending.clear();
  });
}

/** Sum the last `days` daily files (today included), grouped by family. */
export function readCounters(days: number, now: Date = new Date()): {
  since: string;
  counters: Record<string, Record<string, number>>;
} {
  const counters: Record<string, Record<string, number>> = Object.fromEntries(USAGE_FAMILIES.map((f) => [f, {}]));
  const today = Date.parse(utcDay(now));
  let since = utcDay(now);
  for (let i = 0; i < days; i++) {
    const day = utcDay(new Date(today - i * 86_400_000));
    since = day;
    for (const [k, n] of Object.entries(readDay(path.join(usageDir(), `${day}.json`)))) {
      const fam = counters[k.split(":")[0]];
      fam[k] = (fam[k] ?? 0) + n;
    }
  }
  for (const f of USAGE_FAMILIES) {
    counters[f] = Object.fromEntries(Object.entries(counters[f]).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  }
  return { since, counters };
}

/** Delete the usage directory. Returns whether it existed. */
export function clearStore(): boolean {
  const dir = usageDir();
  const existed = fs.existsSync(dir);
  fs.rmSync(dir, { recursive: true, force: true });
  return existed;
}

// ── commander wiring ────────────────────────────────────────────────

function registeredPath(cmd: Command): string[] {
  const names: string[] = [];
  for (let c: Command | null = cmd; c && c.parent; c = c.parent) names.unshift(c.name());
  return names;
}

const QUOTED = /'([^']*)'/;

/**
 * Wire the counters into a commander program: command path from the
 * registered tree, unknown commands/options from commander's own errors,
 * uncaught errors by class, and one flush at exit. Call once, before parse().
 */
export function installUsageCounters(program: Command): void {
  guard(() => {
    const visit = (cmd: Command): void => {
      cmd.hook("preAction", (_self, actionCommand) => setCommandPath(registeredPath(actionCommand)));
      // A callback that returns lets commander exit exactly as it would have.
      cmd.exitOverride((err) => {
        guard(() => {
          if (commandPath === null) setCommandPath(registeredPath(cmd));
          const token = QUOTED.exec(err.message ?? "")?.[1];
          if (err.code === "commander.unknownCommand") countUnknownCommand(token);
          else if (err.code === "commander.unknownOption") countUnknownOption(token);
        });
      });
      for (const sub of cmd.commands) visit(sub);
    };
    visit(program);
    process.on("uncaughtExceptionMonitor", (err) => countError(err));
    process.on("exit", (code) => flush(code));
  });
}
