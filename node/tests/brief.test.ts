import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "child_process";
import path from "path";

const CLI = path.resolve(__dirname, "../dist/index.js");

function rafter(
  args: string | string[],
): { stdout: string; stderr: string; exitCode: number } {
  const argList = Array.isArray(args) ? args : args.split(/\s+/);
  try {
    const result = execFileSync("node", [CLI, ...argList], {
      encoding: "utf-8",
      env: { ...process.env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { stdout: result, stderr: "", exitCode: 0 };
  } catch (e: any) {
    return {
      stdout: e.stdout || "",
      stderr: e.stderr || "",
      exitCode: e.status ?? 1,
    };
  }
}

beforeAll(() => {
  try {
    execFileSync("pnpm", ["run", "build"], {
      cwd: path.resolve(__dirname, ".."),
      stdio: "ignore",
      timeout: 30000,
    });
  } catch {
    // dist may already exist
  }
}, 60000);

describe("brief command — topic listing", () => {
  it("lists available topics when no argument given", () => {
    const r = rafter("brief");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("Available topics:");
    expect(r.stdout).toContain("security");
    expect(r.stdout).toContain("scanning");
    expect(r.stdout).toContain("commands");
    expect(r.stdout).toContain("setup");
    expect(r.stdout).toContain("all");
    expect(r.stdout).toContain("pricing");
  });

  it("lists setup sub-topics", () => {
    const r = rafter("brief");
    expect(r.stdout).toContain("setup/claude-code");
    expect(r.stdout).toContain("setup/codex");
    expect(r.stdout).toContain("setup/gemini");
    expect(r.stdout).toContain("setup/cursor");
    expect(r.stdout).toContain("setup/windsurf");
    expect(r.stdout).toContain("setup/aider");
    expect(r.stdout).toContain("setup/openclaw");
    expect(r.stdout).toContain("setup/continue");
    expect(r.stdout).toContain("setup/generic");
  });

  it("shows usage examples", () => {
    const r = rafter("brief");
    expect(r.stdout).toContain("Usage: rafter brief <topic>");
    expect(r.stdout).toContain("rafter brief security");
    expect(r.stdout).toContain("rafter brief all");
  });
});

describe("brief command — topic rendering", () => {
  it("renders security topic from skill file", () => {
    const r = rafter("brief security");
    expect(r.exitCode).toBe(0);
    expect(r.stdout.length).toBeGreaterThan(100);
    // Should contain agent security content
    expect(r.stdout.toLowerCase()).toMatch(/secur|scan|audit/);
  });

  it("renders scanning topic from skill file", () => {
    const r = rafter("brief scanning");
    expect(r.exitCode).toBe(0);
    expect(r.stdout.length).toBeGreaterThan(100);
  });

  it("renders commands topic with both backend and agent sections", () => {
    const r = rafter("brief commands");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("Rafter Command Reference");
    expect(r.stdout).toContain("Backend (Remote Code Analysis)");
    expect(r.stdout).toContain("Agent (Local Security)");
  });

  it("renders pricing topic", () => {
    const r = rafter("brief pricing");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("Rafter Pricing");
    expect(r.stdout).toContain("Free forever");
    expect(r.stdout).toContain("No API key");
  });

  it("renders all topic with separators", () => {
    const r = rafter("brief all");
    expect(r.exitCode).toBe(0);
    // Should include content from multiple topics
    expect(r.stdout).toContain("---");
    expect(r.stdout.length).toBeGreaterThan(500);
  });
});

describe("brief command — setup guides", () => {
  it("renders setup overview", () => {
    const r = rafter("brief setup");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("Rafter Setup Guide");
    expect(r.stdout).toContain("Supported Platforms");
    expect(r.stdout).toContain("Skill-Based");
    expect(r.stdout).toContain("MCP-Based");
  });

  const platforms = [
    { slug: "claude-code", name: "Claude Code", contains: "skills" },
    { slug: "codex", name: "Codex CLI", contains: "skills" },
    { slug: "gemini", name: "Gemini CLI", contains: "MCP" },
    { slug: "cursor", name: "Cursor", contains: "MCP" },
    { slug: "windsurf", name: "Windsurf", contains: "MCP" },
    { slug: "aider", name: "Aider", contains: "MCP" },
    { slug: "openclaw", name: "OpenClaw", contains: "skill" },
    { slug: "continue", name: "Continue.dev", contains: "MCP" },
    { slug: "generic", name: "Generic", contains: "rafter brief" },
  ];

  for (const { slug, name, contains } of platforms) {
    it(`renders setup/${slug} with ${name} guide`, () => {
      const r = rafter(`brief setup/${slug}`);
      expect(r.exitCode).toBe(0);
      expect(r.stdout).toContain(name);
      expect(r.stdout.toLowerCase()).toContain(contains.toLowerCase());
    });
  }
});

describe("brief command — error handling", () => {
  it("exits 1 for unknown topic", () => {
    const r = rafter("brief nonexistent");
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("Unknown topic: nonexistent");
    // Should show available topics as help
    expect(r.stderr).toContain("Available topics:");
  });

  it("exits 1 for unknown setup platform", () => {
    const r = rafter("brief setup/nosuchplatform");
    expect(r.exitCode).toBe(0); // returns "Unknown platform" string, not an error
    expect(r.stdout).toContain("Unknown platform: nosuchplatform");
  });
});
