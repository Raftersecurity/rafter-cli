import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import yaml from "js-yaml";
import { findPolicyFile } from "./policy-loader.js";

export interface SuppressionInput {
  /** File path or glob to suppress findings in. Required, non-empty. */
  paths: string[];
  /** Specific rule/pattern names to suppress. Omitted/empty = suppress all rules for those paths. */
  rules?: string[];
  /** Human-readable rationale, persisted alongside the rule. */
  reason?: string;
  /** Base directory for resolving the policy file. Defaults to process.cwd(). */
  cwd?: string;
}

export interface SuppressionResult {
  /** Absolute path of the policy file written. */
  file: string;
  /** What happened: a new file was created, a rule appended, or an existing rule's reason updated. */
  action: "created" | "appended" | "updated";
  /** The ignore rule as persisted. */
  entry: { paths: string[]; rules?: string[]; reason?: string };
  /** Total number of ignore rules in the file after the write. */
  suppressionCount: number;
}

function getGitRoot(cwd: string): string | null {
  try {
    return execSync("git rev-parse --show-toplevel", {
      cwd,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Normalize a rule for dedup comparison: an ignore rule is "the same" if it
 * targets the same set of paths and the same set of rule names (order- and
 * duplicate-insensitive). Reason is intentionally excluded — re-suppressing
 * the same scope just updates the reason.
 */
function ruleKey(paths: string[], rules?: string[]): string {
  const norm = (xs?: string[]) =>
    Array.from(new Set((xs ?? []).map((x) => String(x)))).sort();
  return JSON.stringify({ paths: norm(paths), rules: norm(rules) });
}

/**
 * Persist a finding suppression into the project's `.rafter.yml` `ignore`
 * list. Resolves the policy file via the same precedence the loader uses;
 * if none exists, creates a canonical `.rafter.yml` at the git root (or cwd).
 *
 * Merge semantics: if an existing ignore rule targets the same paths + rules,
 * its reason is updated in place rather than appending a duplicate.
 */
export function writeSuppression(input: SuppressionInput): SuppressionResult {
  const paths = (input.paths ?? []).map((p) => String(p)).filter((p) => p.length > 0);
  if (paths.length === 0) {
    throw new Error('"paths" must be a non-empty array of file paths or globs.');
  }
  const rules = Array.isArray(input.rules)
    ? input.rules.map((r) => String(r)).filter((r) => r.length > 0)
    : undefined;
  const reason = typeof input.reason === "string" && input.reason.trim() ? input.reason.trim() : undefined;
  const baseDir = input.cwd || process.cwd();

  // Resolve target file: existing policy file wins; else canonical dotfile at git root / cwd.
  let target = findPolicyFile(baseDir);
  let action: SuppressionResult["action"];
  let raw: Record<string, any> = {};

  if (target && fs.existsSync(target)) {
    const content = fs.readFileSync(target, "utf-8");
    const parsed = yaml.load(content);
    raw = parsed && typeof parsed === "object" ? (parsed as Record<string, any>) : {};
    action = "appended";
  } else {
    const root = getGitRoot(baseDir) || baseDir;
    target = path.join(root, ".rafter.yml");
    action = "created";
  }

  const ignoreList: any[] = Array.isArray(raw.ignore) ? raw.ignore : [];

  const newEntry: { paths: string[]; rules?: string[]; reason?: string } = { paths };
  if (rules && rules.length > 0) newEntry.rules = rules;
  if (reason) newEntry.reason = reason;

  const key = ruleKey(paths, rules);
  const existing = ignoreList.find(
    (e) => e && typeof e === "object" && Array.isArray(e.paths) && ruleKey(e.paths, e.rules) === key,
  );

  if (existing) {
    // Same scope already suppressed — update the reason in place.
    if (reason) existing.reason = reason;
    else delete existing.reason;
    if (action !== "created") action = "updated";
  } else {
    ignoreList.push(newEntry);
  }

  raw.ignore = ignoreList;

  const dumped = yaml.dump(raw, { lineWidth: 100, noRefs: true, sortKeys: false });
  const dir = path.dirname(target);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(target, dumped, "utf-8");

  return {
    file: target,
    action,
    entry: existing ? { ...newEntry, ...(existing.reason ? { reason: existing.reason } : {}) } : newEntry,
    suppressionCount: ignoreList.length,
  };
}
