import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";
import * as tar from "tar";
import { BinaryManager, GITLEAKS_VERSION } from "../src/utils/binary-manager.js";

// ── Tarball extraction (existing tests) ─────────────────────────────

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

// ── Platform detection ──────────────────────────────────────────────

describe("BinaryManager platform detection", () => {
  let bm: BinaryManager;

  beforeEach(() => {
    bm = new BinaryManager();
  });

  it("reports current platform as supported (CI runs on supported platforms)", () => {
    expect(bm.isPlatformSupported()).toBe(true);
  });

  it("getPlatformInfo returns correct structure", () => {
    const info = bm.getPlatformInfo();
    expect(info).toHaveProperty("platform");
    expect(info).toHaveProperty("arch");
    expect(info).toHaveProperty("supported");
    expect(typeof info.platform).toBe("string");
    expect(typeof info.arch).toBe("string");
    expect(typeof info.supported).toBe("boolean");
  });

  it("getPlatformInfo.platform matches process.platform", () => {
    const info = bm.getPlatformInfo();
    expect(info.platform).toBe(process.platform);
  });

  it("getPlatformInfo.arch matches process.arch", () => {
    const info = bm.getPlatformInfo();
    expect(info.arch).toBe(process.arch);
  });
});

// ── Gitleaks path ───────────────────────────────────────────────────

describe("BinaryManager getGitleaksPath", () => {
  let bm: BinaryManager;

  beforeEach(() => {
    bm = new BinaryManager();
  });

  it("returns a path ending in 'gitleaks' (or 'gitleaks.exe' on Windows)", () => {
    const p = bm.getGitleaksPath();
    const basename = path.basename(p);
    if (process.platform === "win32") {
      expect(basename).toBe("gitleaks.exe");
    } else {
      expect(basename).toBe("gitleaks");
    }
  });

  it("path is inside ~/.rafter/bin", () => {
    const p = bm.getGitleaksPath();
    expect(p).toContain(path.join(".rafter", "bin"));
  });
});

// ── isGitleaksInstalled ─────────────────────────────────────────────

describe("BinaryManager isGitleaksInstalled", () => {
  it("returns a boolean", () => {
    const bm = new BinaryManager();
    expect(typeof bm.isGitleaksInstalled()).toBe("boolean");
  });
});

// ── findGitleaksOnPath ──────────────────────────────────────────────

describe("BinaryManager findGitleaksOnPath", () => {
  it("returns string or null", () => {
    const bm = new BinaryManager();
    const result = bm.findGitleaksOnPath();
    expect(result === null || typeof result === "string").toBe(true);
  });
});

// ── Version detection ───────────────────────────────────────────────

describe("BinaryManager version detection", () => {
  it("GITLEAKS_VERSION is a semver string", () => {
    expect(GITLEAKS_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("getGitleaksVersion returns a string", async () => {
    const bm = new BinaryManager();
    const version = await bm.getGitleaksVersion();
    expect(typeof version).toBe("string");
    // Either a version string or "not installed" / "unknown"
    expect(version.length).toBeGreaterThan(0);
  });
});

// ── verifyGitleaksVerbose ───────────────────────────────────────────

describe("BinaryManager verifyGitleaksVerbose", () => {
  it("returns {ok, stdout, stderr} structure", async () => {
    const bm = new BinaryManager();
    const result = await bm.verifyGitleaksVerbose();
    expect(result).toHaveProperty("ok");
    expect(result).toHaveProperty("stdout");
    expect(result).toHaveProperty("stderr");
    expect(typeof result.ok).toBe("boolean");
    expect(typeof result.stdout).toBe("string");
    expect(typeof result.stderr).toBe("string");
  });

  it("returns ok=false for a non-existent binary", async () => {
    const bm = new BinaryManager();
    const result = await bm.verifyGitleaksVerbose("/tmp/nonexistent-gitleaks-binary-xyz");
    expect(result.ok).toBe(false);
  });
});

// ── collectBinaryDiagnostics ────────────────────────────────────────

describe("BinaryManager collectBinaryDiagnostics", () => {
  it("returns a multi-line diagnostic string", async () => {
    const bm = new BinaryManager();
    const diag = await bm.collectBinaryDiagnostics();
    expect(typeof diag).toBe("string");
    expect(diag).toContain("node arch:");
    expect(diag).toContain(process.arch);
  });

  it("includes libc detection on linux", async () => {
    const bm = new BinaryManager();
    const diag = await bm.collectBinaryDiagnostics();
    if (process.platform === "linux") {
      expect(diag).toMatch(/libc:/);
    }
  });
});

// ── Download URL construction ───────────────────────────────────────

describe("BinaryManager download URL construction", () => {
  let bm: BinaryManager;

  beforeEach(() => {
    bm = new BinaryManager();
  });

  // Access private method for testing URL generation
  const getDownloadUrl = (bm: BinaryManager, platform: string, arch: string, version?: string) => {
    return (bm as any).getDownloadUrl(platform, arch, version);
  };

  it("generates correct linux x64 URL", () => {
    const url = getDownloadUrl(bm, "linux", "x64");
    expect(url).toBe(
      `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz`
    );
  });

  it("generates correct darwin arm64 URL", () => {
    const url = getDownloadUrl(bm, "darwin", "arm64");
    expect(url).toBe(
      `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz`
    );
  });

  it("generates correct windows x64 URL (zip)", () => {
    const url = getDownloadUrl(bm, "windows", "x64");
    expect(url).toBe(
      `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_windows_x64.zip`
    );
  });

  it("uses custom version when provided", () => {
    const url = getDownloadUrl(bm, "linux", "x64", "8.20.0");
    expect(url).toContain("v8.20.0");
    expect(url).toContain("gitleaks_8.20.0_linux_x64.tar.gz");
  });
});

// ── getPlatformString / getArchString ───────────────────────────────

describe("BinaryManager platform/arch string mapping", () => {
  let bm: BinaryManager;

  beforeEach(() => {
    bm = new BinaryManager();
  });

  it("getPlatformString returns a valid platform string", () => {
    const platformStr = (bm as any).getPlatformString();
    expect(["darwin", "linux", "windows"]).toContain(platformStr);
  });

  it("getArchString returns a valid arch string", () => {
    const archStr = (bm as any).getArchString();
    expect(["x64", "arm64"]).toContain(archStr);
  });
});

// ── Checksum parsing ────────────────────────────────────────────────

describe("BinaryManager checksum parsing", () => {
  let bm: BinaryManager;

  beforeEach(() => {
    bm = new BinaryManager();
  });

  const parseChecksumFile = (bm: BinaryManager, content: string, filename: string) => {
    return (bm as any).parseChecksumFile(content, filename);
  };

  const sampleChecksums = [
    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890  gitleaks_8.18.2_linux_x64.tar.gz",
    "1111111111111111111111111111111111111111111111111111111111111111  gitleaks_8.18.2_darwin_arm64.tar.gz",
    "2222222222222222222222222222222222222222222222222222222222222222  gitleaks_8.18.2_windows_x64.zip",
  ].join("\n");

  it("finds the correct hash for a known filename", () => {
    const hash = parseChecksumFile(bm, sampleChecksums, "gitleaks_8.18.2_linux_x64.tar.gz");
    expect(hash).toBe("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
  });

  it("finds the correct hash for windows zip", () => {
    const hash = parseChecksumFile(bm, sampleChecksums, "gitleaks_8.18.2_windows_x64.zip");
    expect(hash).toBe("2222222222222222222222222222222222222222222222222222222222222222");
  });

  it("returns null for unknown filename", () => {
    const hash = parseChecksumFile(bm, sampleChecksums, "gitleaks_8.18.2_freebsd_x64.tar.gz");
    expect(hash).toBeNull();
  });

  it("handles empty content", () => {
    const hash = parseChecksumFile(bm, "", "gitleaks_8.18.2_linux_x64.tar.gz");
    expect(hash).toBeNull();
  });

  it("handles content with blank lines", () => {
    const content = "\n\n" + sampleChecksums + "\n\n";
    const hash = parseChecksumFile(bm, content, "gitleaks_8.18.2_darwin_arm64.tar.gz");
    expect(hash).toBe("1111111111111111111111111111111111111111111111111111111111111111");
  });

  it("lowercases hash values", () => {
    const content = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890  gitleaks_8.18.2_linux_x64.tar.gz";
    const hash = parseChecksumFile(bm, content, "gitleaks_8.18.2_linux_x64.tar.gz");
    expect(hash).toBe("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
  });
});

// ── downloadGitleaks error handling ─────────────────────────────────

describe("BinaryManager downloadGitleaks error handling", () => {
  it("rejects on unsupported platform", async () => {
    const bm = new BinaryManager();
    // Mock isPlatformSupported to return false
    vi.spyOn(bm, "isPlatformSupported").mockReturnValue(false);

    await expect(bm.downloadGitleaks()).rejects.toThrow(/not available for/);

    vi.restoreAllMocks();
  });

  it("accepts an onProgress callback", async () => {
    const bm = new BinaryManager();
    vi.spyOn(bm, "isPlatformSupported").mockReturnValue(false);

    const messages: string[] = [];
    await expect(
      bm.downloadGitleaks((msg) => messages.push(msg))
    ).rejects.toThrow();

    vi.restoreAllMocks();
  });

  it("accepts a custom version parameter", async () => {
    const bm = new BinaryManager();
    vi.spyOn(bm, "isPlatformSupported").mockReturnValue(false);

    await expect(
      bm.downloadGitleaks(undefined, "9.99.99")
    ).rejects.toThrow();

    vi.restoreAllMocks();
  });
});

// ── SHA256 computation ──────────────────────────────────────────────

describe("BinaryManager SHA256 computation", () => {
  let tmpFile: string;

  beforeEach(() => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-sha-test-"));
    tmpFile = path.join(tmpDir, "test.bin");
    fs.writeFileSync(tmpFile, "hello world\n");
  });

  afterEach(() => {
    if (fs.existsSync(tmpFile)) {
      const dir = path.dirname(tmpFile);
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("computes correct SHA256 for known content", async () => {
    const bm = new BinaryManager();
    const hash = await (bm as any).computeSHA256(tmpFile);
    // SHA256 of "hello world\n"
    expect(hash).toBe("a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447");
  });

  it("returns a 64-character hex string", async () => {
    const bm = new BinaryManager();
    const hash = await (bm as any).computeSHA256(tmpFile);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });
});
