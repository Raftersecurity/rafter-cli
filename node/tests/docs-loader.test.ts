import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { execSync } from "child_process";

/**
 * Tests for policy `docs:` parsing plus docs-loader resolution, listing, and
 * URL caching fallback behavior. We use a temp git root + a temp ~/.rafter dir
 * by overriding HOME.
 */

describe("Policy docs parsing", () => {
  let tmpDir: string;
  let origCwd: string;

  beforeEach(() => {
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "rafter-docs-")));
    origCwd = process.cwd();
    execSync("git init", { cwd: tmpDir, stdio: "ignore" });
    process.chdir(tmpDir);
  });

  afterEach(() => {
    process.chdir(origCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  async function freshLoadPolicy() {
    const mod = await import("../src/core/policy-loader.js");
    return mod.loadPolicy();
  }

  it("parses path and url entries with derived ids", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), `
docs:
  - path: docs/security/secure.md
    description: Internal rules
    tags: [owasp, internal]
  - url: https://example.com/policy.md
    cache:
      ttl_seconds: 3600
`);
    const policy = await freshLoadPolicy();
    expect(policy?.docs).toHaveLength(2);
    expect(policy?.docs?.[0]).toMatchObject({
      id: "secure",
      path: "docs/security/secure.md",
      description: "Internal rules",
      tags: ["owasp", "internal"],
    });
    expect(policy?.docs?.[1].url).toBe("https://example.com/policy.md");
    expect(policy?.docs?.[1].cache?.ttlSeconds).toBe(3600);
    // URL id is derived 8-char hex
    expect(policy?.docs?.[1].id).toMatch(/^[a-f0-9]{8}$/);
  });

  it("uses explicit id over derived id", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), `
docs:
  - id: my-policy
    path: rules.md
`);
    const policy = await freshLoadPolicy();
    expect(policy?.docs?.[0].id).toBe("my-policy");
  });

  it("skips entries with both path and url, or neither", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), `
docs:
  - id: good
    path: a.md
  - id: bad-both
    path: b.md
    url: https://example.com
  - id: bad-neither
    description: nothing
`);
    const warnSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const policy = await freshLoadPolicy();
    expect(policy?.docs).toHaveLength(1);
    expect(policy?.docs?.[0].id).toBe("good");
    expect(warnSpy.mock.calls.flat().some(s => typeof s === "string" && s.includes("exactly one"))).toBe(true);
  });

  it("skips duplicate ids", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), `
docs:
  - id: dup
    path: a.md
  - id: dup
    path: b.md
`);
    vi.spyOn(console, "error").mockImplementation(() => {});
    const policy = await freshLoadPolicy();
    expect(policy?.docs).toHaveLength(1);
    expect(policy?.docs?.[0].path).toBe("a.md");
  });

  it("ignores cache on path entries", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), `
docs:
  - id: p
    path: x.md
    cache:
      ttl_seconds: 100
`);
    const warnSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const policy = await freshLoadPolicy();
    expect(policy?.docs?.[0].cache).toBeUndefined();
    expect(warnSpy.mock.calls.flat().some(s => typeof s === "string" && s.includes("cache is only valid"))).toBe(true);
  });

  it("warns on unknown per-entry keys", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), `
docs:
  - id: p
    path: x.md
    weird: true
`);
    const warnSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await freshLoadPolicy();
    expect(warnSpy.mock.calls.flat().some(s => typeof s === "string" && s.includes('unknown key "weird"'))).toBe(true);
  });
});

describe("Docs loader listing and resolution", () => {
  let tmpDir: string;
  let origCwd: string;
  let origHome: string | undefined;

  beforeEach(() => {
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "rafter-docs-list-")));
    origCwd = process.cwd();
    origHome = process.env.HOME;
    process.env.HOME = tmpDir; // isolates ~/.rafter/docs-cache
    execSync("git init", { cwd: tmpDir, stdio: "ignore" });
    process.chdir(tmpDir);
  });

  afterEach(() => {
    process.chdir(origCwd);
    if (origHome !== undefined) process.env.HOME = origHome;
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  async function freshListDocs() {
    const mod = await import("../src/core/docs-loader.js");
    return mod.listDocs();
  }

  async function freshResolveSelector(sel: string) {
    const mod = await import("../src/core/docs-loader.js");
    return mod.resolveDocSelector(sel);
  }

  async function freshFetchDoc(entry: any) {
    const mod = await import("../src/core/docs-loader.js");
    return mod.fetchDoc(entry);
  }

  it("reports local status for path docs and not-cached for url docs", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), `
docs:
  - id: local
    path: a.md
  - id: remote
    url: https://example.com/p.md
`);
    const docs = await freshListDocs();
    const byId = Object.fromEntries(docs.map((d: any) => [d.id, d]));
    expect(byId.local.cacheStatus).toBe("local");
    expect(byId.local.sourceKind).toBe("path");
    expect(byId.remote.cacheStatus).toBe("not-cached");
    expect(byId.remote.sourceKind).toBe("url");
  });

  it("resolves selector by exact id, then by tag", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), `
docs:
  - id: a
    path: a.md
    tags: [team-sec]
  - id: b
    path: b.md
    tags: [team-sec, extra]
`);
    const byId = await freshResolveSelector("a");
    expect(byId).toHaveLength(1);
    expect(byId[0].id).toBe("a");

    const byTag = await freshResolveSelector("team-sec");
    expect(byTag).toHaveLength(2);
    expect(byTag.map((d: any) => d.id).sort()).toEqual(["a", "b"]);
  });

  it("fetches path-backed docs from the git root", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), `
docs:
  - id: r
    path: rules.md
`);
    fs.writeFileSync(path.join(tmpDir, "rules.md"), "# Internal Rules\n");
    const res = await freshFetchDoc({ id: "r", path: "rules.md" });
    expect(res.sourceKind).toBe("path");
    expect(res.content).toContain("Internal Rules");
  });

  it("returns stale cache when network fetch fails", async () => {
    fs.writeFileSync(path.join(tmpDir, ".rafter.yml"), `
docs:
  - id: remote
    url: https://example.invalid/x.md
`);
    // Seed cache manually so we can exercise the stale path
    const crypto = require("crypto");
    const key = crypto.createHash("sha256").update("https://example.invalid/x.md").digest("hex").slice(0, 32);
    const cacheDir = path.join(tmpDir, ".rafter", "docs-cache");
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(path.join(cacheDir, `${key}.txt`), "stale body");
    // Write a very old fetched_at so TTL is already exceeded
    fs.writeFileSync(
      path.join(cacheDir, `${key}.meta.json`),
      JSON.stringify({ fetched_at: "2000-01-01T00:00:00.000Z", url: "https://example.invalid/x.md", content_type: "text/plain" })
    );

    // Mock fetch to fail
    const originalFetch = globalThis.fetch;
    (globalThis as any).fetch = async () => { throw new Error("network down"); };
    try {
      const res = await freshFetchDoc({ id: "remote", url: "https://example.invalid/x.md" });
      expect(res.stale).toBe(true);
      expect(res.cached).toBe(true);
      expect(res.content).toBe("stale body");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
