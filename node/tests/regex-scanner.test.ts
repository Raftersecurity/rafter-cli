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
});
