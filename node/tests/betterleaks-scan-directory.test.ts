import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { BetterleaksScanner } from "../src/scanners/betterleaks.js";

// #262 — `betterleaks dir` ignores .gitignore, so handed a directory it walked
// node_modules / build output / .env: slow enough to hit the timeout, and it
// reported gitignored local secret stores. A fake binary stands in for
// betterleaks: it logs its argv and reports every scanned file containing AKIA.
const FAKE_BL = `#!/bin/sh
printf '%s\\n' "$@" >> "$FAKE_BL_ARGV"
[ -n "$FAKE_BL_SLEEP" ] && sleep "$FAKE_BL_SLEEP"
report=""
while [ $# -gt 0 ]; do
  case "$1" in -r|--report-path) report="$2"; shift 2;; --) shift; break;; *) shift;; esac
done
out=""; sep=""
for f in $(find "$@" -type f); do
  if grep -q AKIA "$f"; then
    out="$out$sep{\\"File\\":\\"$f\\",\\"RuleID\\":\\"aws-access-token\\",\\"Description\\":\\"AWS\\",\\"Secret\\":\\"AKIAQYLPMN5HHHFPZAM2\\",\\"Match\\":\\"AKIAQYLPMN5HHHFPZAM2\\",\\"StartLine\\":1,\\"EndLine\\":1,\\"StartColumn\\":1,\\"EndColumn\\":1,\\"Tags\\":[]}"
    sep=","
  fi
done
echo "[$out]" > "$report"
[ -n "$sep" ] && exit 1
exit 0
`;

const SECRET = "aws_key = AKIAQYLPMN5HHHFPZAM2\n";

describe("BetterleaksScanner.scanDirectory and .gitignore", () => {
  let tmp: string;
  let repo: string;
  let argvLog: string;
  let scanner: BetterleaksScanner;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-bl-dir-"));
    repo = path.join(tmp, "repo");
    fs.mkdirSync(path.join(repo, "build"), { recursive: true });
    const bin = path.join(tmp, "betterleaks");
    fs.writeFileSync(bin, FAKE_BL, { mode: 0o755 });
    argvLog = path.join(tmp, "argv.log");
    process.env.FAKE_BL_ARGV = argvLog;

    execSync("git init -q", { cwd: repo });
    fs.writeFileSync(path.join(repo, ".gitignore"), ".env\nbuild/\n");
    fs.writeFileSync(path.join(repo, ".env"), SECRET);
    fs.writeFileSync(path.join(repo, "build", "out.js"), SECRET);
    fs.writeFileSync(path.join(repo, "tracked.js"), SECRET);
    fs.writeFileSync(path.join(repo, "untracked.js"), SECRET);
    execSync("git add .gitignore tracked.js", { cwd: repo });

    scanner = new BetterleaksScanner();
    (scanner as any).resolvedPath = bin;
  });

  afterEach(() => {
    delete process.env.FAKE_BL_ARGV;
    delete process.env.FAKE_BL_SLEEP;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const reported = (rs: { file: string }[]) =>
    rs.map((r) => path.relative(repo, r.file)).sort();

  it("skips gitignored files by default, keeping tracked and untracked ones", async () => {
    const results = await scanner.scanDirectory(repo);
    expect(reported(results)).toEqual(["tracked.js", "untracked.js"]);
  });

  it("scans gitignored files with respectGitignore: false", async () => {
    const results = await scanner.scanDirectory(repo, { respectGitignore: false });
    expect(reported(results)).toEqual(
      [".env", path.join("build", "out.js"), "tracked.js", "untracked.js"].sort(),
    );
  });

  it("still applies the target's own .betterleaks.toml", async () => {
    fs.writeFileSync(path.join(repo, ".betterleaks.toml"), "[extend]\nuseDefault = true\n");
    await scanner.scanDirectory(repo);
    const argv = fs.readFileSync(argvLog, "utf-8").split("\n");
    expect(argv[argv.indexOf("-c") + 1]).toBe(path.join(repo, ".betterleaks.toml"));
  });
});
