import { describe, it, expect, beforeAll, vi } from "vitest";
import { execFileSync, execSync } from "child_process";
import path from "path";
import { detectPlatforms, getSnippet, Platform } from "../src/commands/recommend.js";

const CLI = path.resolve(__dirname, "../dist/index.js");

function rafter(
  args: string | string[],
  opts?: { env?: Record<string, string> }
): { stdout: string; stderr: string; exitCode: number } {
  const argList = Array.isArray(args) ? args : args.split(/\s+/);
  try {
    const result = execFileSync("node", [CLI, ...argList], {
      encoding: "utf-8",
      env: { ...process.env, ...opts?.env },
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
    execSync("pnpm run build", {
      cwd: path.resolve(__dirname, ".."),
      stdio: "ignore",
      timeout: 30000,
    });
  } catch {
    // Build may already be done
  }
}, 60000);

describe("recommend — unit tests", () => {
  it("detectPlatforms returns an array", () => {
    const result = detectPlatforms();
    expect(Array.isArray(result)).toBe(true);
  });

  it("getSnippet returns valid info for each platform", () => {
    const platforms: Platform[] = [
      "claude-code",
      "gemini",
      "cursor",
      "windsurf",
      "codex",
      "aider",
      "continue",
      "generic",
    ];

    for (const p of platforms) {
      const info = getSnippet(p);
      expect(info.name).toBeTruthy();
      expect(info.configPath).toBeTruthy();
      expect(info.oneLiner).toBeTruthy();
      expect(info.snippet).toBeTruthy();
    }
  });

  it("claude-code snippet contains hook config", () => {
    const info = getSnippet("claude-code");
    expect(info.snippet).toContain("PreToolUse");
    expect(info.snippet).toContain("rafter hook pretool");
    expect(info.oneLiner).toContain("--with-claude-code");
  });

  it("gemini snippet contains MCP server config", () => {
    const info = getSnippet("gemini");
    expect(info.snippet).toContain("mcpServers");
    expect(info.snippet).toContain("mcp");
    expect(info.snippet).toContain("serve");
  });

  it("cursor snippet references mcp.json", () => {
    const info = getSnippet("cursor");
    expect(info.configPath).toContain("mcp.json");
    expect(info.snippet).toContain("mcpServers");
  });

  it("windsurf snippet references mcp_config.json", () => {
    const info = getSnippet("windsurf");
    expect(info.configPath).toContain("mcp_config.json");
  });

  it("aider snippet contains YAML config", () => {
    const info = getSnippet("aider");
    expect(info.snippet).toContain("mcp-server-command");
  });

  it("generic snippet provides CLAUDE.md instruction", () => {
    const info = getSnippet("generic");
    expect(info.snippet).toContain("CLAUDE.md");
    expect(info.snippet).toContain("rafter agent init");
  });
});

describe("recommend — e2e CLI", () => {
  it("recommend --help shows usage", () => {
    const r = rafter("recommend --help");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("platform");
  });

  it("recommend generic outputs a snippet", () => {
    const r = rafter("recommend generic");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("rafter agent init");
  });

  it("recommend claude-code outputs hook config", () => {
    const r = rafter("recommend claude-code");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("rafter hook pretool");
  });

  it("recommend gemini outputs MCP config", () => {
    const r = rafter("recommend gemini");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("mcpServers");
  });

  it("recommend --json outputs valid JSON", () => {
    const r = rafter("recommend --json generic");
    expect(r.exitCode).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.platform).toBe("generic");
    expect(parsed.name).toBe("Generic");
    expect(parsed.oneLiner).toBeTruthy();
  });

  it("recommend --json --all outputs platforms array", () => {
    const r = rafter("recommend --json --all");
    expect(r.exitCode).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.platforms).toBeDefined();
    expect(Array.isArray(parsed.platforms)).toBe(true);
  });

  it("recommend with invalid platform exits with error", () => {
    const r = rafter("recommend nonexistent");
    expect(r.exitCode).not.toBe(0);
    expect(r.stderr).toContain("Unknown platform");
  });

  it("recommend --agent outputs plain text", () => {
    const r = rafter(["-a", "recommend", "claude-code"]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("platform: Claude Code");
    expect(r.stdout).toContain("install:");
  });
});
