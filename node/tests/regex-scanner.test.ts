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

  // The Node and Python CLIs must skip the same directories by default: Python
  // once scanned vendor/ and reported 19,920 findings where Node reported 271.
  it("skips the same default directories as the Python CLI", () => {
    const skipped = ["node_modules", ".git", "dist", "build", ".next", "coverage", ".vscode", ".idea", "vendor", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "results", ".terraform", "bower_components", ".trigger"];
    for (const dir of skipped) {
      fs.mkdirSync(path.join(tmpDir, dir), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, dir, "creds.env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCDEFG\n");
    }
    fs.writeFileSync(path.join(tmpDir, "creds.env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCDEFG\n");
    const results = scanner.scanDirectory(tmpDir, { respectGitignore: false });
    expect(results.map((r) => path.relative(tmpDir, r.file))).toEqual(["creds.env"]);
  });

  // sable-ilbx — a file that cannot be read is not a clean scan. The scanner
  // swallowed the read error and returned nothing, so a permission-denied file
  // looked identical to one with no secrets.
  describe("unreadable files", () => {
    it("scanFile surfaces a read error instead of an empty result", () => {
      const f = path.join(tmpDir, "secret.env");
      fs.writeFileSync(f, "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdef1234567890ABCDEFGHIJKL\n");
      fs.chmodSync(f, 0o000);
      try {
        const res = scanner.scanFile(f);
        expect(res.readError).toBeTruthy();
        expect(res.matches).toHaveLength(0);
      } finally {
        fs.chmodSync(f, 0o644);
      }
    });

    it("scanDirectory reports an unreadable file rather than dropping it", () => {
      const f = path.join(tmpDir, "secret.env");
      fs.writeFileSync(f, "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdef1234567890ABCDEFGHIJKL\n");
      fs.chmodSync(f, 0o000);
      try {
        const results = scanner.scanDirectory(tmpDir, { respectGitignore: false });
        const unreadable = results.filter((r) => r.readError);
        expect(unreadable).toHaveLength(1);
        expect(unreadable[0].file).toBe(f);
      } finally {
        fs.chmodSync(f, 0o644);
      }
    });
  });

  describe("symlink handling", () => {
    it("should not follow symlinked directories", () => {
      // Create an "outside" directory with a secret
      const outsideDir = path.join(tmpDir, "outside");
      fs.mkdirSync(outsideDir);
      fs.writeFileSync(
        path.join(outsideDir, "secret.txt"),
        "AKIAIOSFODNN7ABCDEFG\n"
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
      fs.writeFileSync(secretFile, "AKIAIOSFODNN7ABCDEFG\n");

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
    const FAKE_AWS = ["A","K","I","A","I","O","S","F","O","D","N","N","7","A","B","C","D","E","F","G"].join("");
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
