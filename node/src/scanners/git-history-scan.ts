import { execFileSync, spawn } from "child_process";
import path from "path";
import { createAddedLineParser } from "../utils/git-diff.js";
import { RegexScanner, ScanResult } from "./regex-scanner.js";

/**
 * The repository root containing `dirPath`. Throws when `dirPath` is not
 * inside a git work tree, so `--history` never reports a clean scan of a
 * history it could not read.
 */
export function gitRepoRoot(dirPath: string): string {
  try {
    return execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: dirPath, encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    throw new Error(`--history: not a git repository: ${dirPath}`);
  }
}

/**
 * Scan every line ever added in the repository's history with the patterns
 * engine (sable-28lv). Reads the same commits as `betterleaks git`
 * (`git log -p -U0 --full-history --all`), streamed line by line, so memory
 * holds one line plus the findings, whatever the size of the history.
 *
 * Files are reported as absolute paths under the repo root and lines as the
 * line number in the commit that added them, the same shape betterleaks
 * history results take after `absolutize`, so the union merges the two.
 */
export async function scanGitHistory(
  dirPath: string,
  customPatterns?: Array<{ name: string; regex: string; severity: string }>,
): Promise<ScanResult[]> {
  const repoRoot = gitRepoRoot(dirPath);
  const scanner = new RegexScanner(customPatterns);
  const feed = createAddedLineParser();
  const byFile = new Map<string, Map<string, ScanResult["matches"][number]>>();

  const onLine = (rawLine: string): void => {
    const added = feed(rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine);
    if (!added) return;
    for (const m of scanner.scanLine(added.text, added.line)) {
      const file = path.join(repoRoot, added.file);
      let found = byFile.get(file);
      if (!found) byFile.set(file, (found = new Map()));
      // The same secret re-added at the same place in a later commit is one finding.
      const key = `${m.line} ${m.column} ${m.match}`;
      if (!found.has(key)) found.set(key, m);
    }
  };

  await new Promise<void>((resolve, reject) => {
    const child = spawn(
      "git",
      ["-c", "core.quotePath=false", "log", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-textconv",
        "--full-history", "--all", "--format=commit %H"],
      { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] },
    );
    let pending = "";
    let stderr = "";
    child.stdout.setEncoding("utf-8");
    child.stdout.on("data", (chunk: string) => {
      const lines = (pending + chunk).split("\n");
      pending = lines.pop()!;
      for (const l of lines) onLine(l);
    });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("error", (e) => reject(new Error(`--history: git log failed: ${e.message}`)));
    child.on("close", (code) => {
      if (pending) onLine(pending);
      // An empty repository has no history to read; git says so with exit 128.
      if (code === 0 || /does not have any commits/.test(stderr)) resolve();
      else reject(new Error(`--history: git log failed (exit ${code}): ${stderr.trim()}`));
    });
  });

  return [...byFile.entries()].map(([file, found]) => ({ file, matches: [...found.values()] }));
}
