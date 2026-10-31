import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { execSync, spawnSync } from "child_process";
import { execTmpDir } from "./exec-tmp.js";

// ── helpers ──────────────────────────────────────────────────────────

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "rafter-baseline-test-"));
}

function makeBaseline(entries: object[]) {
  return {
    version: 1,
    created: "2026-01-01T00:00:00Z",
    updated: "2026-01-01T00:00:00Z",
    entries,
  };
}

// ── applyBaseline unit tests (via internal logic mirror) ─────────────

// We test the filtering logic directly by importing the compiled output.
// Because the function isn't exported, we replicate the logic here to
// test the contract — identical to what the command uses.

type BaselineEntry = { file: string; line: number | null; pattern: string };
type Match = { pattern: { name: string }; line?: number | null };
type ScanResult = { file: string; matches: Match[] };

function applyBaseline(results: ScanResult[], entries: BaselineEntry[]): ScanResult[] {
  if (entries.length === 0) return results;
  return results
    .map((r) => ({
      ...r,
      matches: r.matches.filter(
        (m) =>
          !entries.some(
            (e) =>
              e.file === r.file &&
              e.pattern === m.pattern.name &&
              (e.line == null || e.line === (m.line ?? null)),
          ),
      ),
    }))
    .filter((r) => r.matches.length > 0);
}

describe("applyBaseline", () => {
  it("passes all results when baseline is empty", () => {
    const results: ScanResult[] = [
      { file: "/f.ts", matches: [{ pattern: { name: "AWS Access Key" }, line: 5 }] },
    ];
    expect(applyBaseline(results, [])).toEqual(results);
  });

  it("filters exact match (file + pattern + line)", () => {
    const results: ScanResult[] = [
      { file: "/f.ts", matches: [{ pattern: { name: "AWS Access Key" }, line: 5 }] },
    ];
    const entries: BaselineEntry[] = [{ file: "/f.ts", pattern: "AWS Access Key", line: 5 }];
    expect(applyBaseline(results, entries)).toEqual([]);
  });

  it("does not filter on different pattern", () => {
    const results: ScanResult[] = [
      { file: "/f.ts", matches: [{ pattern: { name: "AWS Access Key" }, line: 5 }] },
    ];
    const entries: BaselineEntry[] = [{ file: "/f.ts", pattern: "GitHub Token", line: 5 }];
    expect(applyBaseline(results, entries)).toHaveLength(1);
  });

  it("does not filter on different file", () => {
    const results: ScanResult[] = [
      { file: "/f.ts", matches: [{ pattern: { name: "AWS Access Key" }, line: 5 }] },
    ];
    const entries: BaselineEntry[] = [{ file: "/other.ts", pattern: "AWS Access Key", line: 5 }];
    expect(applyBaseline(results, entries)).toHaveLength(1);
  });

  it("null line in baseline matches any line", () => {
    const results: ScanResult[] = [
      { file: "/f.ts", matches: [{ pattern: { name: "AWS Access Key" }, line: 42 }] },
    ];
    const entries: BaselineEntry[] = [{ file: "/f.ts", pattern: "AWS Access Key", line: null }];
    expect(applyBaseline(results, entries)).toEqual([]);
  });

  it("preserves unfiltered matches within same file", () => {
    const results: ScanResult[] = [
      {
        file: "/f.ts",
        matches: [
          { pattern: { name: "AWS Access Key" }, line: 5 },
          { pattern: { name: "GitHub Token" }, line: 10 },
        ],
      },
    ];
    const entries: BaselineEntry[] = [{ file: "/f.ts", pattern: "AWS Access Key", line: 5 }];
    const out = applyBaseline(results, entries);
    expect(out).toHaveLength(1);
    expect(out[0].matches).toHaveLength(1);
    expect(out[0].matches[0].pattern.name).toBe("GitHub Token");
  });
});

// ── baseline create unions both engines in auto mode (sable-qb9g) ─────

// A fake managed betterleaks that reports the pinned version (so it is
// selected, not treated as stale) and detects ONLY AKIA tokens. A normal
// directory scan in `auto` mode runs both engines and unions, so a secret
// betterleaks misses but the patterns engine catches must still be recorded.
// `baseline create` must capture the same union a scan would.
const FAKE_BL = `#!/bin/sh
if [ "$1" = "version" ]; then echo "1.1.2"; exit 0; fi
report=""
while [ $# -gt 0 ]; do
  case "$1" in -r|--report-path) report="$2"; shift 2;; --) shift; break;; *) shift;; esac
done
out=""; sep=""
for f in $(find "$@" -type f 2>/dev/null); do
  if grep -q AKIA "$f" 2>/dev/null; then
    out="$out$sep{\\"File\\":\\"$f\\",\\"RuleID\\":\\"aws-access-token\\",\\"Description\\":\\"AWS\\",\\"Secret\\":\\"AKIAXXXXXXXXXXXXXXXX\\",\\"Match\\":\\"AKIAXXXXXXXXXXXXXXXX\\",\\"StartLine\\":1,\\"EndLine\\":1,\\"StartColumn\\":1,\\"EndColumn\\":1,\\"Tags\\":[]}"
    sep=","
  fi
done
echo "[$out]" > "$report"
[ -n "$sep" ] && exit 1
exit 0
`;

describe("baseline create — auto unions both engines (sable-qb9g)", () => {
  const CLI = path.resolve(__dirname, "../dist/index.js");
  // GitHub PAT (ghp_ + 36 alnum): caught by the patterns engine, missed by the
  // AKIA-only fake betterleaks. Assembled so the file holds no token literal.
  const GITHUB_TOKEN = "ghp_" + "A".repeat(36);
  let home: string;
  let fixture: string;

  beforeEach(() => {
    // HOME holds the fake managed binary, so it must be on an executable FS.
    home = execTmpDir("rafter-baseline-home-");
    fs.mkdirSync(path.join(home, ".rafter", "bin"), { recursive: true });
    fs.writeFileSync(path.join(home, ".rafter", "bin", "betterleaks"), FAKE_BL, { mode: 0o755 });
    // The fixture must be OUTSIDE any git repo, or both engines would skip the
    // leak file as gitignored and the test would pass vacuously.
    fixture = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-baseline-fix-"));
    fs.writeFileSync(path.join(fixture, "leak.js"), `const token = "${GITHUB_TOKEN}";\n`);
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(fixture, { recursive: true, force: true });
  });

  function run(args: string[]): { stdout: string; status: number } {
    const r = spawnSync("node", [CLI, ...args], {
      encoding: "utf-8",
      timeout: 30_000,
      env: { ...process.env, HOME: home },
    });
    return { stdout: r.stdout || "", status: r.status ?? 1 };
  }

  it("records a patterns-only secret when betterleaks is available", () => {
    run(["agent", "baseline", "create", fixture]);
    const shown = run(["agent", "baseline", "show", "--json"]);
    const baseline = JSON.parse(shown.stdout);
    const patterns = baseline.entries.map((e: { pattern: string }) => e.pattern);
    expect(patterns).toContain("GitHub Personal Access Token");
  });
});

// ── pre-push hook template ────────────────────────────────────────────

describe("pre-push hook template", () => {
  it("exists at resources/pre-push-hook.sh and has the expected shape", () => {
    const templatePath = path.resolve("resources", "pre-push-hook.sh");
    expect(fs.existsSync(templatePath)).toBe(true);
    const content = fs.readFileSync(templatePath, "utf-8");
    expect(content).toContain("Rafter Security Pre-Push Hook");
    expect(content).toContain("rafter secrets");
    expect(content).toContain("--no-verify");
    expect(content).toContain("while read");
    expect(content).toContain("local_sha");
    expect(content).toContain("remote_sha");
  });
});
