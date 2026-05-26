import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { RegexScanner } from "../src/scanners/regex-scanner.js";

describe("RegexScanner", () => {
  let tmpDir: string;
  let scanner: RegexScanner;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-test-"));
    scanner = new RegexScanner();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe("symlink handling", () => {
    it("should not follow symlinked directories", () => {
      // Create an "outside" directory with a secret
      const outsideDir = path.join(tmpDir, "outside");
      fs.mkdirSync(outsideDir);
      fs.writeFileSync(
        path.join(outsideDir, "secret.txt"),
        "AKIAIOSFODNN7EXAMPLE\n"
      );

      // Create the scan target with a symlink pointing outside
      const scanDir = path.join(tmpDir, "project");
      fs.mkdirSync(scanDir);
      fs.writeFileSync(path.join(scanDir, "clean.txt"), "no secrets here\n");
      fs.symlinkSync(outsideDir, path.join(scanDir, "link_to_outside"));

      const results = scanner.scanDirectory(scanDir);
      // The symlinked directory should not be followed
      expect(results).toHaveLength(0);
    });

    it("should not follow symlinked files", () => {
      // Create an "outside" file with a secret
      const outsideDir = path.join(tmpDir, "outside");
      fs.mkdirSync(outsideDir);
      const secretFile = path.join(outsideDir, "secret.txt");
      fs.writeFileSync(secretFile, "AKIAIOSFODNN7EXAMPLE\n");

      // Create the scan target with a symlink to the secret file
      const scanDir = path.join(tmpDir, "project");
      fs.mkdirSync(scanDir);
      fs.symlinkSync(secretFile, path.join(scanDir, "link_to_secret.txt"));

      const results = scanner.scanDirectory(scanDir);
      expect(results).toHaveLength(0);
    });
  });

  // sable-gitignore-fix: respect .gitignore by default; --no-gitignore opt-out.
  describe(".gitignore handling", () => {
    // Assemble the fixture key from characters at runtime so the literal
    // substring is not present in source — avoids self-tripping the
    // pre-commit scanner that this test is exercising.
    const FAKE_AWS = ["A","K","I","A","I","O","S","F","O","D","N","N","7","E","X","A","M","P","L","E"].join("");
    const SECRET_BODY = "AWS_KEY=" + FAKE_AWS + "\n";

    function setUpRepo(): { scanDir: string; visible: string; hidden: string } {
      const scanDir = path.join(tmpDir, "repo");
      fs.mkdirSync(scanDir);
      const { spawnSync } = require("child_process");
      spawnSync("git", ["init", "-q"], { cwd: scanDir });
      spawnSync("git", ["config", "user.email", "ci@test.local"], { cwd: scanDir });
      spawnSync("git", ["config", "user.name", "CI"], { cwd: scanDir });
      fs.mkdirSync(path.join(scanDir, "src"));
      fs.mkdirSync(path.join(scanDir, "ignored"));
      const visible = path.join(scanDir, "src", "visible.env");
      const hidden = path.join(scanDir, "ignored", "hidden.env");
      fs.writeFileSync(visible, SECRET_BODY);
      fs.writeFileSync(hidden, SECRET_BODY);
      fs.writeFileSync(path.join(scanDir, ".gitignore"), "ignored/\n");
      return { scanDir, visible, hidden };
    }

    it("default: skips files matching .gitignore", () => {
      const { scanDir, visible } = setUpRepo();
      const results = scanner.scanDirectory(scanDir);
      const files = results.map((r) => r.file).sort();
      expect(files).toEqual([visible]);
    });

    it("respectGitignore=false: includes ignored files", () => {
      const { scanDir, visible, hidden } = setUpRepo();
      const results = scanner.scanDirectory(scanDir, { respectGitignore: false });
      const files = results.map((r) => r.file).sort();
      expect(files).toEqual([hidden, visible].sort());
    });

    it("non-git directory: scans everything (no filter applied)", () => {
      const scanDir = path.join(tmpDir, "plain");
      fs.mkdirSync(scanDir);
      fs.mkdirSync(path.join(scanDir, "ignored"));
      const a = path.join(scanDir, "a.env");
      const b = path.join(scanDir, "ignored", "b.env");
      fs.writeFileSync(a, SECRET_BODY);
      fs.writeFileSync(b, SECRET_BODY);
      // A .gitignore-shaped file in a non-repo should be a no-op.
      fs.writeFileSync(path.join(scanDir, ".gitignore"), "ignored/\n");

      const results = scanner.scanDirectory(scanDir);
      const files = results.map((r) => r.file).sort();
      expect(files).toEqual([a, b].sort());
    });
  });
});
