import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "child_process";
import { existsSync } from "fs";
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
  // dist is built once by tests/global-setup.ts before the (parallel) suite.
  // Only build here as a fallback if it's somehow missing — rebuilding
  // unconditionally rewrites dist while other parallel workers are spawning
  // `node dist/index.js`, which intermittently loads a half-written module
  // (e.g. "does not provide an export named ...").
  if (!existsSync(CLI)) {
    execFileSync("pnpm", ["run", "build"], {
      cwd: path.resolve(__dirname, ".."),
      stdio: "ignore",
      timeout: 60000,
    });
  }
}, 60000);

describe("completion command — bash", () => {
  it("generates bash completion script", () => {
    const r = rafter("completion bash");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("_rafter_completions");
    expect(r.stdout).toContain("complete -F");
    expect(r.stdout).toContain("COMPREPLY");
  });

  it("includes top-level commands in bash completion", () => {
    const r = rafter("completion bash");
    expect(r.stdout).toContain("run");
    expect(r.stdout).toContain("scan");
    expect(r.stdout).toContain("agent");
    expect(r.stdout).toContain("brief");
    expect(r.stdout).toContain("mcp");
    expect(r.stdout).toContain("policy");
    expect(r.stdout).toContain("completion");
  });

  it("includes agent subcommands in bash completion", () => {
    const r = rafter("completion bash");
    expect(r.stdout).toContain("audit");
    expect(r.stdout).toContain("config");
    expect(r.stdout).toContain("exec");
    expect(r.stdout).toContain("verify");
  });
});

describe("completion command — zsh", () => {
  it("generates zsh completion script", () => {
    const r = rafter("completion zsh");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("#compdef rafter");
    expect(r.stdout).toContain("_rafter");
    expect(r.stdout).toContain("_arguments");
  });

  it("includes brief topics in zsh completion", () => {
    const r = rafter("completion zsh");
    expect(r.stdout).toContain("security");
    expect(r.stdout).toContain("scanning");
    expect(r.stdout).toContain("setup/claude-code");
  });
});

describe("completion command — fish", () => {
  it("generates fish completion script", () => {
    const r = rafter("completion fish");
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("complete -c rafter");
    expect(r.stdout).toContain("__fish_use_subcommand");
  });

  it("includes all top-level commands in fish completion", () => {
    const r = rafter("completion fish");
    expect(r.stdout).toContain("-a run");
    expect(r.stdout).toContain("-a brief");
    expect(r.stdout).toContain("-a agent");
    expect(r.stdout).toContain("-a completion");
  });
});

describe("completion command — error handling", () => {
  it("exits 1 for unknown shell", () => {
    const r = rafter("completion powershell");
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("Unknown shell: powershell");
    expect(r.stderr).toContain("bash, zsh, fish");
  });
});
