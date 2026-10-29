import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { execSync, spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { BetterleaksScanner, gitSkippedPaths, scanConfigToml } from "../src/scanners/betterleaks.js";
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

  it("carries the config betterleaks would pick: env path, then env content, then the target's file", async () => {
    fs.writeFileSync(path.join(repo, ".betterleaks.toml"), "# repo file\n");
    vi.stubEnv("GITLEAKS_CONFIG_TOML", "# env content\n");
    await scanner.scanDirectory(repo);
    expect(fs.readFileSync(cfgCopy, "utf-8")).toContain("# env content\n");

    const envFile = path.join(repo, "env-path.toml");
    fs.writeFileSync(envFile, "# env path\n");
    vi.stubEnv("BETTERLEAKS_CONFIG", envFile);
    await scanner.scanDirectory(repo);
    const cfg = fs.readFileSync(cfgCopy, "utf-8");
    expect(cfg).toContain("# env path\n");
    expect(cfg).not.toContain("# env content");
    expect(cfg).not.toContain("# repo file");
  });

  it("carries the target's own .betterleaks.toml", async () => {
    fs.writeFileSync(path.join(repo, ".betterleaks.toml"), "[extend]\nuseDefault = true\n\n[allowlist]\npaths = ['x']\n");
    await scanner.scanDirectory(repo);
    const cfg = fs.readFileSync(cfgCopy, "utf-8");
    expect(cfg).toContain("[extend]\nuseDefault = true\n\n[[allowlists]]\npaths = ['x']\n");
    expect(cfg).not.toMatch(/^\[allowlist\]/m);
  });
});

// The skip list and the generated config decide what betterleaks never reads,
// so an error in either hides secrets. These need git but not betterleaks.
describe("gitSkippedPaths and scanConfigToml", () => {
  let repo: string;
  const git = (...args: string[]) =>
    execSync(["git", "-c", "user.name=t", "-c", "user.email=t@t", ...args].map((a) => `'${a}'`).join(" "), {
      cwd: repo, stdio: "pipe",
    }).toString();
  const patternsOf = (toml: string) =>
    [...toml.matchAll(/^ {2}(".*"),$/gm)].map((m) => new RegExp(JSON.parse(m[1])));
  const skips = (toml: string, abs: string) => patternsOf(toml).some((p) => p.test(abs));

  beforeEach(() => {
    repo = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-bl-skip-"));
    git("init", "-q");
  });
  afterEach(() => fs.rmSync(repo, { recursive: true, force: true }));

  it("scans a tracked file that is now a directory, skips submodules and nested repos", () => {
    fs.writeFileSync(path.join(repo, "vendor"), "x\n");
    git("add", "vendor");
    git("commit", "-qm", "c");
    fs.rmSync(path.join(repo, "vendor"));
    fs.mkdirSync(path.join(repo, "vendor"));
    fs.writeFileSync(path.join(repo, "vendor", "s.js"), SECRET);
    const sha = git("rev-parse", "HEAD").trim();
    git("update-index", "--add", "--cacheinfo", `160000,${sha},sub`);
    fs.mkdirSync(path.join(repo, "sub"));
    fs.mkdirSync(path.join(repo, "nested"));
    execSync("git init -q", { cwd: path.join(repo, "nested") });
    fs.writeFileSync(path.join(repo, "nested", "n.js"), SECRET);
    expect(gitSkippedPaths(repo)!.sort()).toEqual(["nested/", "sub"]);
  });

  it.skipIf(process.platform === "win32")("keeps a backslash in a POSIX filename literal", () => {
    const toml = scanConfigToml(repo, ["trigger\\x.txt"], null);
    expect(skips(toml, path.join(repo, "trigger\\x.txt"))).toBe(true);
    expect(skips(toml, path.join(repo, "trigger", "x.txt"))).toBe(false);
  });

  it("writes no character TOML forbids raw in a basic string", () => {
    const toml = scanConfigToml(repo, ["d\x7fel.txt", "t\tab", "n\nl"], null);
    // Line feeds separate entries; any other control character must be escaped.
    expect(toml).not.toMatch(/[\x00-\x08\x0b-\x1f\x7f]/);
    expect(patternsOf(toml)).toHaveLength(4);
    expect(skips(toml, path.join(repo, "d\x7fel.txt"))).toBe(true);
  });
});

// #262 — betterleaks 1.1.x never resets its extend-depth counter, so handed many
// paths under a config that extends the default rules, it applied rules to the
// first two paths only. Needs the real binary on PATH; skipped without it.
const realBl = spawnSync("betterleaks", ["version"], { stdio: "ignore" }).status === 0;

describe.skipIf(!realBl)("BetterleaksScanner.scanDirectory with the real betterleaks", () => {
  it("scans files the skip list must not touch, under a config betterleaks can read", async () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-bl-real-"));
    try {
      const g = (cmd: string) => execSync(`git -c user.name=t -c user.email=t@t ${cmd}`, { cwd: repo });
      g("init -q");
      fs.writeFileSync(path.join(repo, ".gitignore"), "*.txt\n");
      fs.writeFileSync(path.join(repo, "vendor"), "x\n");
      g("add vendor .gitignore");
      g("commit -qm c");
      fs.rmSync(path.join(repo, "vendor"));
      fs.mkdirSync(path.join(repo, "vendor"));
      const pat = (i: number) => `const t = "ghp_${String(i).repeat(4)}Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXyZ0";\n`;
      fs.writeFileSync(path.join(repo, "vendor", "v.js"), pat(1));
      fs.mkdirSync(path.join(repo, "trigger"));
      fs.writeFileSync(path.join(repo, "trigger", "x.txt"), pat(2));
      g("add -f trigger/x.txt");
      fs.writeFileSync(path.join(repo, "trigger\\x.txt"), "ignored\n");
      fs.writeFileSync(path.join(repo, "d\x7fel.txt"), pat(3));
      const scanner = new BetterleaksScanner();
      (scanner as any).resolvedPath = "betterleaks";
      const files = (await scanner.scanDirectory(repo)).map((r) => path.relative(repo, r.file)).sort();
      expect(files).toEqual([path.join("trigger", "x.txt"), path.join("vendor", "v.js")]);
    } finally {
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });

  it("keeps the default rules under a repo config two extends away from them, and its own allowlist", async () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-bl-real-"));
    try {
      execSync("git init -q", { cwd: repo });
      // repo config -> shared org config -> default rules: a depth betterleaks
      // follows itself, which a generated config that extended the repo's exceeded.
      const org = path.join(repo, "org.toml");
      fs.writeFileSync(org, "[extend]\nuseDefault = true\n");
      fs.writeFileSync(path.join(repo, ".betterleaks.toml"), [
        "[extend]", `path = ${JSON.stringify(org)}`, "",
        "[[rules]]", 'id = "repo-custom"', "regex = 'REPOSECRET_[0-9]{6}'", "",
        "[allowlist]", "paths = ['allowed\\.js$']", "",
      ].join("\n"));
      fs.writeFileSync(path.join(repo, ".gitignore"), ".env\n");
      const gh = 'const t = "ghp_1111Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXyZ0";\n';
      fs.writeFileSync(path.join(repo, "a.js"), gh + 'const r = "REPOSECRET_123456";\n');
      fs.writeFileSync(path.join(repo, "allowed.js"), gh);
      fs.writeFileSync(path.join(repo, ".env"), gh);
      const scanner = new BetterleaksScanner();
      (scanner as any).resolvedPath = "betterleaks";
      const found = (await scanner.scanDirectory(repo))
        .flatMap((r) => r.matches.map((m) => `${path.basename(r.file)}:${m.pattern.name}`))
        .sort();
      expect(found).toEqual(["a.js:github-pat", "a.js:repo-custom"]);
    } finally {
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });

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
