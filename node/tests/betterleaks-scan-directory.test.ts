import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { execSync, spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { BetterleaksScanner } from "../src/scanners/betterleaks.js";
import { execTmpDir } from "./exec-tmp.js";

// #262 — `betterleaks dir` ignores .gitignore, so handed a directory it walked
// node_modules / build output / .env: slow enough to hit the timeout, and it
// reported gitignored local secret stores. A fake binary stands in for
// betterleaks: it logs its argv, keeps a copy of its -c config, and reports
// every file under its targets containing AKIA.
const FAKE_BL = `#!/bin/sh
printf '%s\\n' "$@" >> "$FAKE_BL_ARGV"
prev=""; for a in "$@"; do [ "$prev" = "-c" ] && cp "$a" "$FAKE_BL_CFG"; prev="$a"; done
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
  let binDir: string;
  let repo: string;
  let argvLog: string;
  let cfgCopy: string;
  let scanner: BetterleaksScanner;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-bl-dir-"));
    repo = path.join(tmp, "repo");
    fs.mkdirSync(path.join(repo, "build"), { recursive: true });
    binDir = execTmpDir("bl-");
    const bin = path.join(binDir, "betterleaks");
    fs.writeFileSync(bin, FAKE_BL, { mode: 0o755 });
    argvLog = path.join(tmp, "argv.log");
    process.env.FAKE_BL_ARGV = argvLog;
    cfgCopy = path.join(tmp, "scan.toml");
    process.env.FAKE_BL_CFG = cfgCopy;
    // The developer's own betterleaks config must not leak into these tests.
    for (const v of ["BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML"]) {
      vi.stubEnv(v, "");
    }

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
    delete process.env.FAKE_BL_CFG;
    delete process.env.FAKE_BL_SLEEP;
    vi.unstubAllEnvs();
    fs.rmSync(tmp, { recursive: true, force: true });
    fs.rmSync(binDir, { recursive: true, force: true });
  });

  const reported = (rs: { file: string }[]) =>
    rs.map((r) => path.relative(repo, r.file)).sort();

  // The fake ignores the config, so read off it what betterleaks would skip.
  const skippedBy = (toml: string) => {
    const pats = [...toml.matchAll(/^ {2}(".*"),$/gm)].map((m) => new RegExp(JSON.parse(m[1])));
    return (rel: string) => pats.some((p) => p.test(path.join(repo, rel)));
  };

  it("walks the target once, under a config that skips what git ignores", async () => {
    await scanner.scanDirectory(repo);
    const argv = fs.readFileSync(argvLog, "utf-8").trim().split("\n");
    expect(argv.slice(argv.indexOf("--") + 1)).toEqual([repo]);
    const toml = fs.readFileSync(cfgCopy, "utf-8");
    expect(toml).toMatch(/^useDefault = true$/m);
    const files = [".env", path.join("build", "out.js"), "tracked.js", "untracked.js"];
    expect(files.filter(skippedBy(toml))).toEqual([".env", path.join("build", "out.js")]);
  });

  it("scans gitignored files with respectGitignore: false", async () => {
    const results = await scanner.scanDirectory(repo, { respectGitignore: false });
    expect(reported(results)).toEqual(
      [".env", path.join("build", "out.js"), "tracked.js", "untracked.js"].sort(),
    );
  });

  it("extends the target's own .betterleaks.toml", async () => {
    fs.writeFileSync(path.join(repo, ".betterleaks.toml"), "[extend]\nuseDefault = true\n");
    await scanner.scanDirectory(repo);
    expect(fs.readFileSync(cfgCopy, "utf-8")).toContain(
      `path = ${JSON.stringify(path.join(repo, ".betterleaks.toml"))}`,
    );
  });
});

// #262 — betterleaks 1.1.x never resets its extend-depth counter, so handed many
// paths under a config that extends the default rules, it applied rules to the
// first two paths only. Needs the real binary on PATH; skipped without it.
const realBl = spawnSync("betterleaks", ["version"], { stdio: "ignore" }).status === 0;

describe.skipIf(!realBl)("BetterleaksScanner.scanDirectory with the real betterleaks", () => {
  it("applies the extended rules to every file and skips gitignored ones", async () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-bl-real-"));
    try {
      execSync("git init -q", { cwd: repo });
      fs.writeFileSync(path.join(repo, ".betterleaks.toml"), "[extend]\nuseDefault = true\n");
      fs.writeFileSync(path.join(repo, ".gitignore"), ".env\n");
      const pat = (i: number) => `const t = "ghp_${String(i).repeat(4)}Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXyZ0";\n`;
      for (let i = 1; i <= 4; i++) fs.writeFileSync(path.join(repo, `f${i}.js`), pat(i));
      fs.writeFileSync(path.join(repo, ".env"), pat(9));
      const scanner = new BetterleaksScanner();
      (scanner as any).resolvedPath = "betterleaks";
      const files = (await scanner.scanDirectory(repo)).map((r) => path.basename(r.file)).sort();
      expect(files).toEqual(["f1.js", "f2.js", "f3.js", "f4.js"]);
    } finally {
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });
});
