/**
 * Every `rafter …` command named in the docs we SHIP must exist in the CLI we ship.
 *
 * `rafter brief <topic>` exists to feed rafter's own knowledge to an AI coding
 * agent, and the agent follows it literally. A beta persona playing a platform
 * engineer did exactly that: the briefing told them to write a `risk:` key in
 * `.rafter.yml` (the loader only accepts `command_policy:`), so their policy
 * silently matched nothing and the dangerous command was ALLOWED. They then
 * tried the two commands the same briefing names for CI — `rafter policy
 * validate` and `rafter agent exec --dry-run` — and neither exists. They
 * concluded the guardrails feature was entirely non-functional. It works; the
 * docs were wrong.
 *
 * Auditing by hand found eight wrong references across three shipped docs, so
 * this checks the whole surface rather than those eight.
 *
 * Note on method: `rafter <bad-subcommand> --help` exits 0, because commander
 * handles --help before it validates the subcommand. Appending --help to probe
 * a reference therefore reports everything as fine. This walks the real command
 * tree from the help output instead, which is also side-effect free — running
 * each referenced command for real would fire `agent init`, `update-betterleaks`
 * and friends.
 */
import { describe, it, expect } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";

const CLI = path.resolve(__dirname, "../dist/index.js");
const DOCS_DIR = path.resolve(__dirname, "../resources/skills/rafter/docs");

function help(args: string[]): string {
  try {
    return execFileSync("node", [CLI, ...args, "--help"], {
      encoding: "utf-8",
      timeout: 30_000,
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch {
    return "";
  }
}

/** Subcommand names commander lists under "Commands:" for a given path. */
function subcommands(args: string[]): Set<string> {
  const names = new Set<string>();
  let inBlock = false;
  for (const line of help(args).split("\n")) {
    if (/^Commands:/.test(line)) { inBlock = true; continue; }
    if (!inBlock) continue;
    if (!line.trim()) continue;
    const m = line.match(/^ {2}([a-z][a-z0-9-]*)/);
    if (m) names.add(m[1]);
    else if (!line.startsWith(" ")) break;
  }
  return names;
}

function options(args: string[]): Set<string> {
  return new Set(help(args).match(/--[a-z][a-z0-9-]*/g) ?? []);
}

const topLevel = subcommands([]);
const childrenOf = new Map<string, Set<string>>();
for (const c of topLevel) childrenOf.set(c, subcommands([c]));

/**
 * Aliases that work but that commander does not list under "Commands:", so the
 * help-derived tree cannot see them. Verified by running each one. Keep this
 * list tiny and only for aliases confirmed working — it is the one place this
 * test can be lied to.
 */
const UNLISTED_ALIASES = new Set(["scan local"]);

interface Ref { file: string; line: number; text: string; command: string[]; flag?: string }

function referencesIn(file: string): Ref[] {
  const refs: Ref[] = [];
  const lines = fs.readFileSync(path.join(DOCS_DIR, file), "utf-8").split("\n");
  lines.forEach((line, i) => {
    const re = /rafter ([a-z][a-z0-9-]*)(?: ([a-z][a-z0-9-]*))?((?: --?[a-z][\w-]*)*)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(line))) {
      const [, first, second, flagBlob] = m;
      if (!topLevel.has(first)) {
        // Prose like "rafter knowledge for any agent" — only a reference if it
        // reads as a command, which we approximate by requiring a code span.
        if (line.includes(`\`rafter ${first}`)) {
          refs.push({ file, line: i + 1, text: m[0], command: [first] });
        }
        continue;
      }
      const cmd = [first];
      const kids = childrenOf.get(first)!;
      if (second && kids.size > 0 && kids.has(second)) cmd.push(second);
      else if (second && kids.size > 0 && !kids.has(second) && line.includes(`\`rafter ${first} ${second}`)) {
        refs.push({ file, line: i + 1, text: m[0], command: [first, second] });
        continue;
      }
      for (const flag of flagBlob.match(/--[a-z][\w-]*/g) ?? []) {
        refs.push({ file, line: i + 1, text: m[0], command: cmd, flag });
      }
      if (!flagBlob.trim()) refs.push({ file, line: i + 1, text: m[0], command: cmd });
    }
  });
  return refs;
}

const DOC_FILES = fs.readdirSync(DOCS_DIR).filter((f) => f.endsWith(".md"));

describe("shipped agent-facing docs match the shipped CLI", () => {
  it("finds docs to check", () => {
    expect(DOC_FILES.length).toBeGreaterThan(0);
    expect(topLevel.size).toBeGreaterThan(5);
  });

  it.each(DOC_FILES)("%s names only commands and flags that exist", (file) => {
    const broken: string[] = [];
    for (const ref of referencesIn(file)) {
      const [first, second] = ref.command;
      if (!topLevel.has(first)) {
        broken.push(`${file}:${ref.line} — no such command: rafter ${first}`);
        continue;
      }
      if (second && !childrenOf.get(first)!.has(second) && !UNLISTED_ALIASES.has(`${first} ${second}`)) {
        broken.push(`${file}:${ref.line} — no such subcommand: rafter ${first} ${second}`);
        continue;
      }
      if (ref.flag && !options(ref.command).has(ref.flag)) {
        // A placeholder like --with-<platform> is documentation, not a flag.
        if (ref.flag.endsWith("-")) continue;
        broken.push(`${file}:${ref.line} — no such option: rafter ${ref.command.join(" ")} ${ref.flag}`);
      }
    }
    expect(broken, `\n${broken.join("\n")}\n`).toEqual([]);
  });

  it("documents the policy key the loader actually accepts", async () => {
    // The specific instance that fooled a beta user: `risk:` was documented,
    // `command_policy:` is what works, and the mismatch fails OPEN — the
    // command is allowed, with only a stderr warning nobody reads.
    const { VALID_TOP_LEVEL_POLICY_KEYS } = await import("../src/core/policy-loader.js");
    const guardrails = fs.readFileSync(path.join(DOCS_DIR, "guardrails.md"), "utf-8");

    const yamlKeys = [...guardrails.matchAll(/^([a-z_]+):$/gm)].map((m) => m[1]);
    expect(yamlKeys.length).toBeGreaterThan(0);
    for (const key of yamlKeys) {
      expect(VALID_TOP_LEVEL_POLICY_KEYS.has(key), `guardrails.md documents "${key}:"`).toBe(true);
    }
  });
});
