import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import yaml from "js-yaml";
import { writeSuppression } from "../src/core/suppression-writer.js";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-suppress-"));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function readPolicy(): any {
  return yaml.load(fs.readFileSync(path.join(tmp, ".rafter.yml"), "utf-8"));
}

describe("writeSuppression", () => {
  it("creates .rafter.yml when none exists", () => {
    const res = writeSuppression({ cwd: tmp, paths: ["test/fixtures/**"], rules: ["AWS Access Key"], reason: "fixtures" });
    expect(res.action).toBe("created");
    expect(res.suppressionCount).toBe(1);
    expect(fs.existsSync(path.join(tmp, ".rafter.yml"))).toBe(true);
    const policy = readPolicy();
    expect(policy.ignore).toEqual([
      { paths: ["test/fixtures/**"], rules: ["AWS Access Key"], reason: "fixtures" },
    ]);
  });

  it("appends a new rule to an existing policy without clobbering other keys", () => {
    fs.writeFileSync(
      path.join(tmp, ".rafter.yml"),
      yaml.dump({ risk_level: "moderate", ignore: [{ paths: ["a/**"], reason: "first" }] }),
    );
    const res = writeSuppression({ cwd: tmp, paths: ["b/**"], reason: "second" });
    expect(res.action).toBe("appended");
    expect(res.suppressionCount).toBe(2);
    const policy = readPolicy();
    expect(policy.risk_level).toBe("moderate");
    expect(policy.ignore).toHaveLength(2);
    expect(policy.ignore[1]).toEqual({ paths: ["b/**"], reason: "second" });
  });

  it("updates reason in place for the same path+rules scope (no duplicate)", () => {
    writeSuppression({ cwd: tmp, paths: ["a/**"], rules: ["X"], reason: "old" });
    const res = writeSuppression({ cwd: tmp, paths: ["a/**"], rules: ["X"], reason: "new reason" });
    expect(res.action).toBe("updated");
    expect(res.suppressionCount).toBe(1);
    const policy = readPolicy();
    expect(policy.ignore).toHaveLength(1);
    expect(policy.ignore[0].reason).toBe("new reason");
  });

  it("treats path/rule order as identical scope (dedup is order-insensitive)", () => {
    writeSuppression({ cwd: tmp, paths: ["a/**", "b/**"], rules: ["X", "Y"], reason: "first" });
    const res = writeSuppression({ cwd: tmp, paths: ["b/**", "a/**"], rules: ["Y", "X"], reason: "second" });
    expect(res.action).toBe("updated");
    expect(res.suppressionCount).toBe(1);
  });

  it("omits rules key when no rule names given (suppress-all-for-path)", () => {
    writeSuppression({ cwd: tmp, paths: ["docs/**"], reason: "docs" });
    const policy = readPolicy();
    expect(policy.ignore[0]).toEqual({ paths: ["docs/**"], reason: "docs" });
    expect(policy.ignore[0]).not.toHaveProperty("rules");
  });

  it("throws on empty paths", () => {
    expect(() => writeSuppression({ cwd: tmp, paths: [] })).toThrow();
  });
});
