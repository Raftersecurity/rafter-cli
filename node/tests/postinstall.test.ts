import { describe, it, expect } from "vitest";
import { execFileSync } from "child_process";
import path from "path";
import fs from "fs";

const scriptPath = path.resolve(__dirname, "../scripts/postinstall.js");

describe("postinstall script", () => {
  it("script file exists", () => {
    expect(fs.existsSync(scriptPath)).toBe(true);
  });

  it("prints hint suggesting rafter agent init", () => {
    const output = execFileSync("node", [scriptPath], { encoding: "utf-8" });
    expect(output).toContain("rafter");
    expect(output).toContain("agent init --all");
  });

  it("exits with code 0", () => {
    // execFileSync throws on non-zero exit, so if this doesn't throw, exit code is 0
    expect(() =>
      execFileSync("node", [scriptPath], { encoding: "utf-8" })
    ).not.toThrow();
  });

  it("is referenced in package.json postinstall script", () => {
    const pkgPath = path.resolve(__dirname, "../package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
    expect(pkg.scripts.postinstall).toContain("postinstall.js");
  });

  it("scripts directory is included in package.json files", () => {
    const pkgPath = path.resolve(__dirname, "../package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
    expect(pkg.files).toContain("scripts");
  });
});
