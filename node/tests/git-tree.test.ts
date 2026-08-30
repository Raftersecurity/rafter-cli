import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
  BaseTreeReader,
  EMPTY_TREE_OID,
  InvalidRefError,
  MAX_CANDIDATES,
  RefResolutionError,
  type GitRunner,
} from "../src/utils/git-tree.js";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const tempDirs: string[] = [];

function tempDir(prefix = "rafter-git-tree-"): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function git(cwd: string, args: string[]): Buffer {
  return execFileSync("git", args, {
    cwd,
    encoding: "buffer",
    stdio: ["pipe", "pipe", "pipe"],
  });
}

function initRepo(commit = true): string {
  const repo = tempDir();
  git(repo, ["init", "-q"]);
  git(repo, ["config", "user.email", "tests@example.com"]);
  git(repo, ["config", "user.name", "Rafter Tests"]);
  if (commit) {
    fs.writeFileSync(path.join(repo, "tracked.txt"), "base\n");
    git(repo, ["add", "--", "tracked.txt"]);
    git(repo, ["commit", "-qm", "initial"]);
  }
  return repo;
}

function commitAll(repo: string, message: string): string {
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-qm", message]);
  return git(repo, ["rev-parse", "HEAD"]).toString("utf8").trim();
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("BaseTreeReader ref handling", () => {
  it("resolves a commit with --end-of-options before the user ref", () => {
    const calls: string[][] = [];
    const oid = "a".repeat(40);
    const runner: GitRunner = (args) => {
      calls.push([...args]);
      return Buffer.from(`${oid}\n`);
    };

    const reader = new BaseTreeReader("/repo", { runner });
    expect(reader.resolveRef("main")).toBe(oid);
    expect(calls).toEqual([
      ["rev-parse", "--verify", "--quiet", "--end-of-options", "main^{commit}"],
    ]);
  });

  it.each(["--upload-pack=/bin/false", "-i"])(
    "rejects option-shaped ref %s before spawning git",
    (ref) => {
      let calls = 0;
      const reader = new BaseTreeReader("/repo", {
        runner: () => {
          calls++;
          return Buffer.alloc(0);
        },
      });

      expect(() => reader.resolveRef(ref)).toThrowError(InvalidRefError);
      try {
        reader.resolveRef(ref);
      } catch (error) {
        expect(error).toMatchObject({ code: "invalid_ref", exitCode: 2 });
      }
      expect(calls).toBe(0);
    },
  );

  it("does not turn an ordinary missing ref into the empty tree", () => {
    const reader = new BaseTreeReader(initRepo());
    expect(() => reader.resolveRef("does-not-exist")).toThrowError(RefResolutionError);
  });

  it("does not mistake a git spawn failure for an unborn repository", () => {
    const failure = Object.assign(new Error("git is unavailable"), { code: "ENOENT" });
    const reader = new BaseTreeReader("/repo", {
      runner: () => {
        throw failure;
      },
    });
    expect(() => reader.resolveRef("HEAD")).toThrow(failure);
  });

  it("does not mistake a non-repository for an unborn repository", () => {
    expect(() => new BaseTreeReader(tempDir()).resolveRef("HEAD")).toThrow();
  });

  it("rejects non-OID downstream arguments before spawning git", () => {
    let calls = 0;
    const reader = new BaseTreeReader("/repo", {
      runner: () => {
        calls++;
        return Buffer.alloc(0);
      },
    });
    expect(() => reader.listTree("--upload-pack=/bin/false")).toThrow(/resolved 40-hex/);
    expect(() => reader.changedPaths("-i")).toThrow(/resolved 40-hex/);
    expect(() => reader.changedPaths("a".repeat(40), "")).toThrow(/resolved 40-hex/);
    expect(() => reader.readBlob("HEAD:policy.json")).toThrow(/resolved 40-hex/);
    expect(calls).toBe(0);
  });

  it("maps only a proven root parent or unborn repository to the empty tree", () => {
    const rootRepo = initRepo();
    const root = git(rootRepo, ["rev-parse", "HEAD"]).toString("utf8").trim();
    const rootReader = new BaseTreeReader(rootRepo);

    expect(rootReader.resolveRef("HEAD")).toBe(root);
    expect(rootReader.resolveRef("HEAD^")).toBe(EMPTY_TREE_OID);
    expect(new BaseTreeReader(initRepo(false)).resolveRef("HEAD")).toBe(EMPTY_TREE_OID);
  });
});

describe("BaseTreeReader tree plumbing", () => {
  it("lists committed and working-tree paths without mangling tabs or newlines", () => {
    const repo = initRepo();
    const special = 'policy\nwith\ttab "quote" and \\slash-e\u0301.json';
    const normalized = special.normalize("NFC");
    fs.writeFileSync(path.join(repo, special), '{"Statement":[]}\n');
    const oid = commitAll(repo, "special path");
    fs.appendFileSync(path.join(repo, special), "changed\n");

    const reader = new BaseTreeReader(repo);
    expect(reader.listTree(oid).map((entry) => entry.path)).toContain(normalized);
    expect(reader.listWorkTree().map((entry) => entry.path)).toContain(normalized);
    expect(reader.changedPaths(rootOid(repo))).toContain(normalized);
    expect(
      reader.readWorkTreeCandidates((candidate) => candidate.endsWith(".json")).files.get(normalized),
    ).toContain('{"Statement":[]}');
  });

  it("abstains when distinct raw paths collide after NFC normalization", () => {
    const repo = initRepo();
    const normalized = "policy-é.json";
    const decomposed = "policy-e\u0301.json";
    fs.writeFileSync(path.join(repo, normalized), "composed\n");
    fs.writeFileSync(path.join(repo, decomposed), "decomposed\n");

    const result = new BaseTreeReader(repo).readWorkTreeCandidates((candidate) =>
      candidate.endsWith(".json"),
    );
    expect(result.files.size).toBe(0);
    expect(result.unanalyzed).toHaveLength(2);
    expect(result.unanalyzed.every((item) => item.reason === "parse_error")).toBe(true);
  });

  it("includes untracked files in working-tree listings and changed paths", () => {
    const repo = initRepo();
    const untracked = "new policy.json";
    fs.writeFileSync(path.join(repo, untracked), "{}\n");
    const reader = new BaseTreeReader(repo);
    const base = rootOid(repo);

    expect(reader.listWorkTree().map((entry) => entry.path)).toContain(untracked);
    expect(reader.changedPaths(base)).toContain(untracked);
  });

  it("omits tracked paths deleted from the working tree", () => {
    const repo = initRepo();
    fs.unlinkSync(path.join(repo, "tracked.txt"));
    expect(new BaseTreeReader(repo).listWorkTree().map((entry) => entry.path)).not.toContain(
      "tracked.txt",
    );
  });

  it("reads blob bytes in one batch and candidate text from a resolved tree", () => {
    const repo = initRepo();
    fs.writeFileSync(path.join(repo, "policy.json"), '{"Statement":[]}\n');
    const oid = commitAll(repo, "policy");
    const reader = new BaseTreeReader(repo);
    const entry = reader.listTree(oid).find((item) => item.path === "policy.json");

    expect(entry).toBeDefined();
    expect(reader.readBlob(entry!.oid)).toEqual(Buffer.from('{"Statement":[]}\n'));
    expect(reader.readAt(oid, "policy.json")).toEqual(Buffer.from('{"Statement":[]}\n'));
    const result = reader.readTreeCandidates(oid, (candidate) => candidate.endsWith(".json"));
    expect(result.files.get("policy.json")).toBe('{"Statement":[]}\n');
    expect(result.unanalyzed).toEqual([]);
  });

  it("uses one cat-file batch process for multiple tree candidates", () => {
    const repo = initRepo();
    fs.writeFileSync(path.join(repo, "one.json"), "{\"one\":1}\n");
    fs.writeFileSync(path.join(repo, "two.json"), "{\"two\":2}\n");
    const oid = commitAll(repo, "two blobs");
    const calls: string[][] = [];
    const runner: GitRunner = (args, options) => {
      calls.push([...args]);
      return execFileSync("git", args, {
        cwd: options.cwd,
        input: options.input,
        encoding: "buffer",
        stdio: ["pipe", "pipe", "pipe"],
        timeout: options.timeoutMs,
      });
    };

    const result = new BaseTreeReader(repo, { runner }).readTreeCandidates(
      oid,
      (candidate) => candidate.endsWith(".json"),
    );
    expect([...result.files.keys()]).toEqual(["one.json", "two.json"]);
    expect(calls.filter((args) => args[0] === "cat-file")).toEqual([
      ["cat-file", "--batch"],
    ]);
  });

  it("bounds each cat-file batch by candidate bytes", () => {
    const repo = initRepo();
    fs.writeFileSync(path.join(repo, "one.json"), "1234567890");
    fs.writeFileSync(path.join(repo, "two.json"), "abcdefghij");
    const oid = commitAll(repo, "two blobs");
    const calls: string[][] = [];
    const runner: GitRunner = (args, options) => {
      calls.push([...args]);
      return execFileSync("git", args, {
        cwd: options.cwd,
        input: options.input,
        encoding: "buffer",
        stdio: ["pipe", "pipe", "pipe"],
        timeout: options.timeoutMs,
      });
    };

    const result = new BaseTreeReader(repo, { runner, maxBatchBytes: 10 }).readTreeCandidates(
      oid,
      (candidate) => candidate.endsWith(".json"),
    );
    expect(result.files.size).toBe(2);
    expect(calls.filter((args) => args[0] === "cat-file")).toEqual([
      ["cat-file", "--batch"],
      ["cat-file", "--batch"],
    ]);
  });

  it("enumerates changed paths between two resolved commit OIDs", () => {
    const repo = initRepo();
    const base = rootOid(repo);
    fs.writeFileSync(path.join(repo, "next.txt"), "next\n");
    const head = commitAll(repo, "next");
    expect([...new BaseTreeReader(repo).changedPaths(base, head)]).toEqual(["next.txt"]);
  });

  it("reports true for a depth-one clone", () => {
    const source = initRepo();
    fs.writeFileSync(path.join(source, "second.txt"), "second\n");
    commitAll(source, "second");
    const clone = tempDir("rafter-shallow-");
    git(path.dirname(clone), ["clone", "-q", "--depth=1", `file://${source}`, clone]);

    expect(new BaseTreeReader(clone).isShallow()).toBe(true);
    expect(new BaseTreeReader(source).isShallow()).toBe(false);
  });
});

describe("BaseTreeReader hardening and budgets", () => {
  it("never follows committed, final-component, or ancestor symlinks", () => {
    const repo = initRepo();
    const outside = tempDir("rafter-outside-");
    const marker = "outside-secret-marker";
    fs.writeFileSync(path.join(outside, "policy.json"), marker);

    fs.symlinkSync(path.join(outside, "policy.json"), path.join(repo, "link.json"));
    fs.mkdirSync(path.join(repo, "nested"));
    fs.writeFileSync(path.join(repo, "nested", "policy.json"), "safe\n");
    const oid = commitAll(repo, "symlinks");

    fs.rmSync(path.join(repo, "nested"), { recursive: true });
    fs.symlinkSync(outside, path.join(repo, "nested"), "dir");

    const reader = new BaseTreeReader(repo);
    const base = reader.readTreeCandidates(oid, (candidate) => candidate.endsWith(".json"));
    const head = reader.readWorkTreeCandidates((candidate) => candidate.endsWith(".json"));

    expect(base.unanalyzed).toContainEqual(
      expect.objectContaining({ file: "link.json", side: "base", reason: "symlink" }),
    );
    expect(head.unanalyzed).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ file: "link.json", side: "head", reason: "symlink" }),
        expect.objectContaining({
          file: "nested/policy.json",
          side: "head",
          reason: "symlink",
        }),
      ]),
    );
    expect([...base.files.values(), ...head.files.values()].join("\n")).not.toContain(marker);
  });

  it.skipIf(process.platform === "win32")("never opens a nonregular candidate", () => {
    const repo = initRepo();
    fs.writeFileSync(path.join(repo, "pipe.json"), "regular\n");
    commitAll(repo, "tracked regular file");
    fs.unlinkSync(path.join(repo, "pipe.json"));
    execFileSync("mkfifo", [path.join(repo, "pipe.json")]);

    const result = new BaseTreeReader(repo).readWorkTreeCandidates((candidate) =>
      candidate.endsWith(".json"),
    );
    expect(result.files.has("pipe.json")).toBe(false);
    expect(result.unanalyzed).toContainEqual(
      expect.objectContaining({ file: "pipe.json", reason: "symlink" }),
    );
  });

  it("emits too_large for a two-MiB candidate without returning its content", () => {
    const repo = initRepo();
    fs.writeFileSync(path.join(repo, "large.json"), Buffer.alloc(2 * 1024 * 1024, 65));
    const oid = commitAll(repo, "large");
    const result = new BaseTreeReader(repo).readTreeCandidates(
      oid,
      (candidate) => candidate.endsWith(".json"),
      new Set(["large.json"]),
    );

    expect(result.files.has("large.json")).toBe(false);
    expect(result.unanalyzed).toContainEqual(
      expect.objectContaining({ file: "large.json", reason: "too_large", changed: true }),
    );
  });

  it("abstains from the whole side when post-filter candidates exceed 2000", () => {
    const repo = initRepo();
    for (let index = 0; index <= MAX_CANDIDATES; index++) {
      const file = `candidate-${index.toString().padStart(4, "0")}.json`;
      fs.writeFileSync(path.join(repo, file), "{}");
    }

    const result = new BaseTreeReader(repo).readWorkTreeCandidates((candidate) =>
      candidate.endsWith(".json"),
    );
    expect(MAX_CANDIDATES).toBe(2000);
    expect(result.files.size).toBe(0);
    expect(result.unanalyzed).toHaveLength(MAX_CANDIDATES + 1);
    expect(result.unanalyzed.every((item) => item.reason === "too_many_candidates")).toBe(true);
  });

  it("marks candidates binary when their first 8 KiB contains NUL", () => {
    const repo = initRepo();
    fs.writeFileSync(path.join(repo, "binary.json"), Buffer.from("before\0after"));
    const result = new BaseTreeReader(repo).readWorkTreeCandidates((candidate) =>
      candidate.endsWith(".json"),
    );
    expect(result.files.size).toBe(0);
    expect(result.unanalyzed).toContainEqual(
      expect.objectContaining({ file: "binary.json", reason: "binary" }),
    );
  });

  it("turns an expired extraction budget into timeout records", () => {
    const repo = initRepo();
    fs.writeFileSync(path.join(repo, "policy.json"), "{}\n");
    const ticks = [0, 0, 200, 200];
    const result = new BaseTreeReader(repo, {
      timeoutMs: 100,
      clock: () => ticks.shift() ?? 200,
    }).readWorkTreeCandidates((candidate) => candidate.endsWith(".json"));

    expect(result.files.size).toBe(0);
    expect(result.unanalyzed).toContainEqual(
      expect.objectContaining({ file: "policy.json", reason: "timeout" }),
    );
  });

  it("uses argv-only subprocess calls and never imports the unsafe git helper", () => {
    const source = fs.readFileSync(path.resolve(TEST_DIR, "../src/utils/git-tree.ts"), "utf8");
    expect(source).toContain('execFileSync("git", args');
    expect(source).not.toMatch(/\bexecSync\b/);
    expect(source).not.toContain('./git.js');
  });
});

function rootOid(repo: string): string {
  return git(repo, ["rev-parse", "HEAD"]).toString("utf8").trim();
}
