import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { parseRemote } from "../src/utils/git.js";

/**
 * Tests for git utility functions.
 *
 * parseRemote is the only pure function we can unit-test without mocking
 * execSync.  detectRepo and safeBranch depend on actual git state so they
 * belong in integration tests.
 */

describe("parseRemote", () => {
  it("parses HTTPS GitHub URL", () => {
    expect(parseRemote("https://github.com/owner/repo.git")).toBe("owner/repo");
  });

  it("parses SSH GitHub URL", () => {
    expect(parseRemote("git@github.com:owner/repo.git")).toBe("owner/repo");
  });

  it("parses URL without .git suffix", () => {
    expect(parseRemote("https://github.com/owner/repo")).toBe("owner/repo");
  });

  it("parses GitLab URL", () => {
    expect(parseRemote("git@gitlab.com:group/project.git")).toBe("group/project");
  });

  it("handles nested paths (takes last two segments)", () => {
    expect(parseRemote("https://gitlab.com/group/subgroup/project.git")).toBe("subgroup/project");
  });

  it("parses HTTP URL (no S)", () => {
    expect(parseRemote("http://github.com/owner/repo.git")).toBe("owner/repo");
  });
});
