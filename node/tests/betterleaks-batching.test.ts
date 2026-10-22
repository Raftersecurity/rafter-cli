import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { BetterleaksScanner, MAX_FILES_PER_CALL } from "../src/scanners/betterleaks.js";
import { execTmpDir } from "./exec-tmp.js";

// sable-jiqb — betterleaks' cost scales with the explicit file list it is handed
// (~0.2s/file), so one `dir -- <all tracked files>` call on a few-hundred-file
// repo exceeds the per-invocation timeout and the engine silently falls back to
// patterns. The scanner must split the file list into batches small enough that
// no single invocation approaches the timeout, while still finding every secret
// and honoring .gitignore. This fake betterleaks records, per invocation, the
// count of file targets it was handed (the args after `--`).
const FAKE_BL = `#!/bin/sh
count=0; after=0
for a in "$@"; do
  [ "$after" = 1 ] && count=$((count+1))
  [ "$a" = "--" ] && after=1
done
echo "$count" >> "$FAKE_BL_CALLS"
report=""
while [ $# -gt 0 ]; do
  case "$1" in --report-path) report="$2"; shift 2;; --) shift; break;; *) shift;; esac
done
out=""; sep=""
for f in $(find "$@" -type f 2>/dev/null); do
  if grep -q AKIA "$f" 2>/dev/null; then
    out="$out$sep{\\"File\\":\\"$f\\",\\"RuleID\\":\\"aws-access-token\\",\\"Description\\":\\"AWS\\",\\"Secret\\":\\"AKIAQYLPMN5HHHFPZAM2\\",\\"Match\\":\\"AKIAQYLPMN5HHHFPZAM2\\",\\"StartLine\\":1,\\"EndLine\\":1,\\"StartColumn\\":1,\\"EndColumn\\":1,\\"Tags\\":[]}"
    sep=","
  fi
done
echo "[$out]" > "$report"
[ -n "$sep" ] && exit 1
exit 0
`;

describe("BetterleaksScanner batches the file list (sable-jiqb)", () => {
  let tmp: string;
  let binDir: string;
  let repo: string;
  let callsLog: string;
  let scanner: BetterleaksScanner;
  const N = MAX_FILES_PER_CALL + 10; // guarantees more than one batch

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-bl-batch-"));
    repo = path.join(tmp, "repo");
    fs.mkdirSync(repo, { recursive: true });
    binDir = execTmpDir("bl-batch-");
    const bin = path.join(binDir, "betterleaks");
    fs.writeFileSync(bin, FAKE_BL, { mode: 0o755 });
    callsLog = path.join(tmp, "calls.log");
    process.env.FAKE_BL_CALLS = callsLog;

    execSync("git init -q", { cwd: repo });
    // N tracked files; the planted secret sits in the middle so it must land in
    // a batch other than the first.
    for (let i = 0; i < N; i++) {
      const body = i === Math.floor(N / 2) ? "const k = 'AKIAQYLPMN5HHHFPZAM2';\n" : `export const x${i} = ${i};\n`;
      fs.writeFileSync(path.join(repo, `f${i}.ts`), body);
    }
    // A gitignored file carrying a secret must never be scanned.
    fs.writeFileSync(path.join(repo, ".gitignore"), "secret.local\n");
    fs.writeFileSync(path.join(repo, "secret.local"), "const s = 'AKIAQYLPMN5HHHFPZAM2';\n");
    execSync("git add .gitignore && git add -A", { cwd: repo });

    scanner = new BetterleaksScanner();
    (scanner as any).resolvedPath = bin;
  });

  afterEach(() => {
    delete process.env.FAKE_BL_CALLS;
    fs.rmSync(tmp, { recursive: true, force: true });
    fs.rmSync(binDir, { recursive: true, force: true });
  });

  it("splits a large tracked-file list into bounded batches", async () => {
    await scanner.scanDirectory(repo);
    const calls = fs
      .readFileSync(callsLog, "utf-8")
      .trim()
      .split("\n")
      .map(Number);
    // More than one invocation, and no invocation above the per-call ceiling.
    expect(calls.length).toBeGreaterThan(1);
    expect(Math.max(...calls)).toBeLessThanOrEqual(MAX_FILES_PER_CALL);
  });

  it("still finds the planted secret and skips the gitignored file", async () => {
    const results = await scanner.scanDirectory(repo);
    const reported = results.map((r) => path.basename(r.file)).sort();
    expect(reported).toContain(`f${Math.floor(N / 2)}.ts`);
    expect(reported).not.toContain("secret.local");
  });
});
