import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { spawnSync, execSync } from "child_process";
import { randomBytes } from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";
import {
  InstallSession,
  claudeAgentArtifacts,
  cleanupRetiredRules,
  cleanupRetiredSkills,
  cursorAgentArtifacts,
  manifestPath,
  ruleArtifacts,
  sha256,
  skillArtifacts,
  type FileArtifact,
  type InstallOutput,
} from "../src/commands/agent/install-files.js";

/**
 * `rafter agent init` must not destroy a user's edit to a file it installed.
 *
 * The fixture, fixtures/install-0.11.2/home, is the real on-disk state of the
 * published 0.11.2 `agent init --all` (captured from the npm package; ~/.rafter
 * left out). Hook and config files carry __RAFTER_BIN__ / __HOME__ placeholders.
 * Each test copies it to a temp HOME, so these run against what users have.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");
const FIXTURE = path.resolve(PROJECT_ROOT, "..", "fixtures", "install-0.11.2", "home");
const CLI_DIST = path.join(PROJECT_ROOT, "dist", "index.js");

let home: string;

function copyFixture(dest: string): void {
  fs.cpSync(FIXTURE, dest, { recursive: true });
  for (const rel of [".claude/settings.json", ".codex/hooks.json", ".cursor/hooks.json", ".gemini/settings.json"]) {
    const p = path.join(dest, rel);
    fs.writeFileSync(p, fs.readFileSync(p, "utf-8").replaceAll("__RAFTER_BIN__", "/usr/local/bin/rafter"));
  }
}

function silentOut(): InstallOutput & { warnings: string[] } {
  const warnings: string[] = [];
  return { info: () => {}, warn: (m: string) => warnings.push(m), warnings };
}

function session(opts: { force?: boolean; dryRun?: boolean } = {}) {
  const out = silentOut();
  return { s: new InstallSession({ root: home, out, version: "test", ...opts }), out };
}

const PLATFORMS: Record<string, () => FileArtifact[]> = {
  "claude-code": () => [
    ...skillArtifacts(path.join(home, ".claude", "skills"), "claude-code", "claude-code.skills"),
    ...claudeAgentArtifacts(home),
  ],
  codex: () => skillArtifacts(path.join(home, ".agents", "skills"), "codex", "codex.skills"),
  gemini: () => skillArtifacts(path.join(home, ".agents", "skills"), "gemini", "gemini.skills"),
  cursor: () => [...ruleArtifacts("cursor", home), ...cursorAgentArtifacts(home)],
  windsurf: () => ruleArtifacts("windsurf", home),
  continue: () => ruleArtifacts("continue", home),
};

beforeEach(() => {
  home = path.join(fs.realpathSync(os.tmpdir()), `rafter-manifest-${Date.now()}-${randomBytes(4).toString("hex")}`);
  fs.mkdirSync(home, { recursive: true });
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe("upgrade over a real 0.11.2 install", () => {
  for (const [platform, artifacts] of Object.entries(PLATFORMS)) {
    it(`${platform}: every file rafter shipped is brought to the current version`, () => {
      copyFixture(home);
      const before = new Map(artifacts().map((a) => [a.dest, fs.readFileSync(a.dest)]));
      const { s } = session();
      const outcomes = s.applyAll(artifacts());
      s.save();

      artifacts().forEach((a, i) => {
        expect(sha256(fs.readFileSync(a.dest)), a.dest).toBe(sha256(a.content));
        expect(outcomes[i], a.dest).toBe(before.get(a.dest)!.equals(a.content) ? "unchanged" : "updated");
        expect(fs.existsSync(a.dest + ".rafter-new"), a.dest).toBe(false);
      });
      expect(outcomes).toContain("updated");
      const manifest = JSON.parse(fs.readFileSync(manifestPath(home), "utf-8"));
      expect(Object.keys(manifest.files)).toContain(path.relative(home, artifacts()[0].dest));
    });
  }

  it("cursor: the sub-agent as the Python CLI wrote it through 0.11.x is recognized as rafter's", () => {
    copyFixture(home);
    // Python's old strip left a blank line where `tools:` was; re-create it from the 0.11.2 source.
    const raw = fs.readFileSync(path.join(FIXTURE, ".claude", "agents", "rafter.md"), "utf-8");
    const end = raw.indexOf("\n---", 4);
    const legacy = `---\n${raw.slice(4, end).replace(/^tools:\s.*$\n?/m, "")}${raw.slice(end)}`;
    const dest = path.join(home, ".cursor", "agents", "rafter.md");
    fs.writeFileSync(dest, legacy);
    expect(legacy).not.toBe(fs.readFileSync(path.join(FIXTURE, ".cursor", "agents", "rafter.md"), "utf-8"));
    expect(session().s.applyAll(cursorAgentArtifacts(home))).toEqual(["updated"]);
  });

  it("a hand-edited skill file and rule file are kept, with the new version beside them", () => {
    copyFixture(home);
    const skill = path.join(home, ".claude", "skills", "rafter", "SKILL.md");
    const rule = path.join(home, ".cursor", "rules", "rafter.mdc");
    fs.appendFileSync(skill, "\nmy local note\n");
    fs.appendFileSync(rule, "\nmy local note\n");
    const edited = new Map([skill, rule].map((p) => [p, fs.readFileSync(p)]));

    const { s, out } = session();
    const all = [...PLATFORMS["claude-code"](), ...PLATFORMS.cursor()];
    const outcomes = new Map(all.map((a) => [a.dest, s.apply(a)]));

    for (const [p, bytes] of edited) {
      expect(outcomes.get(p), p).toBe("kept");
      expect(fs.readFileSync(p).equals(bytes), p).toBe(true);
      const fresh = all.find((a) => a.dest === p)!.content;
      expect(fs.readFileSync(p + ".rafter-new").equals(fresh), p).toBe(true);
    }
    expect(out.warnings.filter((w) => w.includes("kept"))).toHaveLength(2);
    expect([...outcomes].filter(([p]) => !edited.has(p)).every(([, o]) => o === "updated" || o === "unchanged")).toBe(true);
  });

  it("a second run reports every file unchanged", () => {
    copyFixture(home);
    const all = () => Object.values(PLATFORMS).flatMap((f) => f());
    const first = session();
    first.s.applyAll(all());
    first.s.save();
    const second = session();
    expect(new Set(second.s.applyAll(all()))).toEqual(new Set(["unchanged"]));
  });

  it("--force replaces a modified file and keeps the old one as .bak", () => {
    copyFixture(home);
    const skill = path.join(home, ".claude", "skills", "rafter", "SKILL.md");
    fs.writeFileSync(skill, "my rewrite\n");
    const { s } = session({ force: true });
    const a = PLATFORMS["claude-code"]().find((x) => x.dest === skill)!;
    expect(s.apply(a)).toBe("replaced");
    expect(fs.readFileSync(skill).equals(a.content)).toBe(true);
    expect(fs.readFileSync(skill + ".bak", "utf-8")).toBe("my rewrite\n");
  });
});

describe("write policy", () => {
  const artifact = (content: string): FileArtifact => ({
    dest: path.join(home, "f.md"),
    content: Buffer.from(content),
    resourceKey: "not-shipped",
    component: "c",
    platform: "p",
  });

  it("a file the manifest says rafter wrote is updated; the same bytes unrecorded are kept", () => {
    const first = session();
    expect(first.s.apply(artifact("v1"))).toBe("added");
    first.s.save();
    expect(session().s.apply(artifact("v2"))).toBe("updated");

    fs.writeFileSync(path.join(home, "f.md"), "v1");
    fs.rmSync(manifestPath(home));
    expect(session().s.apply(artifact("v3"))).toBe("kept");
  });

  it("a corrupt manifest is treated as absent and warns once", () => {
    fs.mkdirSync(path.dirname(manifestPath(home)), { recursive: true });
    fs.writeFileSync(manifestPath(home), "{not json");
    fs.writeFileSync(path.join(home, "f.md"), "theirs");
    const { s, out } = session();
    expect(s.apply(artifact("ours"))).toBe("kept");
    expect(s.apply({ ...artifact("ours"), dest: path.join(home, "g.md") })).toBe("added");
    expect(out.warnings.filter((w) => w.includes("unreadable install manifest"))).toHaveLength(1);
  });

  it("a dry run predicts without writing, and sees its own earlier predictions", () => {
    copyFixture(home);
    const { s } = session({ dryRun: true });
    const codex = s.applyAll(PLATFORMS.codex());
    const gemini = s.applyAll(PLATFORMS.gemini());
    expect(codex).toContain("updated");
    expect(new Set(gemini)).toEqual(new Set(["unchanged"]));
    expect(fs.existsSync(manifestPath(home))).toBe(false);
    const skill = path.join(home, ".agents", "skills", "rafter", "SKILL.md");
    expect(fs.readFileSync(skill).equals(fs.readFileSync(path.join(FIXTURE, ".agents", "skills", "rafter", "SKILL.md")))).toBe(true);
  });
});

describe("retired-artifact cleanup uses hashes as proof of ownership", () => {
  // 0.11.2 skills carry no publisher tag, so only the hash table can prove
  // these are rafter's. "rafter" stands in for a retired name.
  it("removes an untagged skill dir and rule file that hash to shipped content", () => {
    copyFixture(home);
    const { s } = session();
    const skills = cleanupRetiredSkills(s, path.join(home, ".claude", "skills"), ["rafter"]);
    const rules = cleanupRetiredRules(s, "windsurf", ["rafter"]);
    expect(skills.removed).toHaveLength(1);
    expect(rules.removed).toHaveLength(1);
    expect(fs.existsSync(path.join(home, ".claude", "skills", "rafter"))).toBe(false);
    expect(fs.existsSync(path.join(home, ".windsurf", "rules", "rafter.md"))).toBe(false);
  });

  it("keeps a retired skill dir or rule file the user modified", () => {
    copyFixture(home);
    fs.appendFileSync(path.join(home, ".claude", "skills", "rafter", "docs", "backend.md"), "\nmine\n");
    fs.appendFileSync(path.join(home, ".windsurf", "rules", "rafter.md"), "\nmine\n");
    const { s } = session();
    expect(cleanupRetiredSkills(s, path.join(home, ".claude", "skills"), ["rafter"]).kept).toHaveLength(1);
    expect(cleanupRetiredRules(s, "windsurf", ["rafter"]).kept).toHaveLength(1);
    expect(fs.existsSync(path.join(home, ".claude", "skills", "rafter", "SKILL.md"))).toBe(true);
    expect(fs.existsSync(path.join(home, ".windsurf", "rules", "rafter.md"))).toBe(true);
  });
});

describe("shipped-hashes table", () => {
  it("node and python ship byte-identical copies", () => {
    const node = fs.readFileSync(path.join(PROJECT_ROOT, "resources", "shipped-hashes.json"));
    const py = fs.readFileSync(path.join(PROJECT_ROOT, "..", "python", "rafter_cli", "resources", "shipped-hashes.json"));
    expect(node.equals(py)).toBe(true);
  });
});

// One end-to-end pass through the built CLI: the per-file report, the dry-run
// plan agreeing with the real run, and the marker-block / merged-config files
// (which do not go through the write policy) surviving an upgrade intact.
describe("agent init over the 0.11.2 fixture (built CLI)", () => {
  const FLAGS = ["--with-claude-code", "--with-codex", "--with-gemini", "--with-cursor", "--with-windsurf", "--with-continue", "--with-aider"];

  beforeAll(() => {
    if (!fs.existsSync(CLI_DIST)) execSync("pnpm run build", { cwd: PROJECT_ROOT, stdio: "inherit" });
  });

  function init(extra: string[] = []): string {
    const r = spawnSync(process.execPath, [CLI_DIST, "agent", "init", ...FLAGS, ...extra], {
      cwd: home,
      encoding: "utf-8",
      timeout: 60_000,
      env: { ...process.env, HOME: home, XDG_CONFIG_HOME: path.join(home, ".config"), CI: "1", PATH: "/usr/bin:/bin" },
    });
    expect(r.status, r.stderr).toBe(0);
    return r.stdout;
  }

  /** [path, outcome] per whole-file artifact line of a real run. */
  const realOutcomes = (stdout: string) =>
    [...stdout.matchAll(/(added|updated|unchanged|kept|replaced)\s+(\S+)/g)].map((m) => [m[2], m[1]]);
  /** The same, recovered from a dry-run plan. */
  const plannedOutcomes = (stdout: string) =>
    [...stdout.matchAll(/^\s+(WRITE|SKIP)\s+(\S+)\s+\((added|updated|unchanged|(\S+) kept: modified)\)/gm)]
      .map((m) => (m[4] ? [m[4], "kept"] : [m[2], m[3]]));

  it("reports each file, keeps edits, preserves user text, and does not duplicate hooks", () => {
    copyFixture(home);
    const userText = "\n\nMY OWN NOTES — keep me\n";
    const markerFiles = [".claude/CLAUDE.md", "AGENTS.md", ".gemini/GEMINI.md", "RAFTER.md"].map((p) => path.join(home, p));
    for (const p of markerFiles) fs.appendFileSync(p, userText);
    const edited = path.join(home, ".continue", "rules", "rafter.md");
    fs.appendFileSync(edited, "\nmine\n");

    const plan = plannedOutcomes(init(["--dry-run"]));
    const first = realOutcomes(init());
    expect(plan).toEqual(first);
    expect(first).toContainEqual([edited, "kept"]);
    expect(first.filter(([, o]) => o === "updated").length).toBeGreaterThan(0);

    for (const p of markerFiles) {
      const text = fs.readFileSync(p, "utf-8");
      expect(text, p).toContain("MY OWN NOTES — keep me");
      expect(text.match(/<!-- rafter:start -->/g), p).toHaveLength(1);
    }
    const hookCount = (rel: string) => (fs.readFileSync(path.join(home, rel), "utf-8").match(/hook pretool/g) ?? []).length;
    const hooksBefore = [".claude/settings.json", ".codex/hooks.json", ".cursor/hooks.json", ".gemini/settings.json"].map(hookCount);
    expect(fs.readFileSync(path.join(home, ".aider.conf.yml"), "utf-8").match(/RAFTER\.md/g)).toHaveLength(1);

    const second = realOutcomes(init());
    expect(second.filter(([, o]) => o !== "unchanged" && o !== "kept")).toEqual([]);
    expect([".claude/settings.json", ".codex/hooks.json", ".cursor/hooks.json", ".gemini/settings.json"].map(hookCount)).toEqual(hooksBefore);
    expect(JSON.parse(fs.readFileSync(path.join(home, ".cursor", "mcp.json"), "utf-8")).mcpServers).toHaveProperty("rafter");
  });
});
