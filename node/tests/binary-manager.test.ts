import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";
import * as tar from "tar";

describe("BinaryManager extractTarball", () => {
  let tmpDir: string;
  let binDir: string;
  let tarballPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-bin-test-"));
    binDir = path.join(tmpDir, "bin");
    fs.mkdirSync(binDir, { recursive: true });

    // Create a tarball mimicking gitleaks release: binary + LICENSE + README.md
    const stageDir = path.join(tmpDir, "stage");
    fs.mkdirSync(stageDir);
    fs.writeFileSync(path.join(stageDir, "gitleaks"), "#!/bin/sh\necho fake", { mode: 0o755 });
    fs.writeFileSync(path.join(stageDir, "LICENSE"), "MIT License");
    fs.writeFileSync(path.join(stageDir, "README.md"), "# Gitleaks");

    tarballPath = path.join(tmpDir, "gitleaks.tar.gz");
    tar.create(
      { gzip: true, file: tarballPath, cwd: stageDir, sync: true },
      ["gitleaks", "LICENSE", "README.md"]
    );
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should extract only the gitleaks binary, not LICENSE or README", async () => {
    const binaryName = process.platform === "win32" ? "gitleaks.exe" : "gitleaks";

    await tar.extract({
      file: tarballPath,
      cwd: binDir,
      strip: 0,
      filter: (entryPath: string) => path.basename(entryPath) === binaryName
    });

    const files = fs.readdirSync(binDir);
    expect(files).toContain("gitleaks");
    expect(files).not.toContain("LICENSE");
    expect(files).not.toContain("README.md");
    expect(files).toHaveLength(1);
  });

  it("old behavior (no filter) would extract all files", async () => {
    await tar.extract({
      file: tarballPath,
      cwd: binDir,
      strip: 0
    });

    const files = fs.readdirSync(binDir);
    expect(files).toContain("gitleaks");
    expect(files).toContain("LICENSE");
    expect(files).toContain("README.md");
    expect(files).toHaveLength(3);
  });
});
