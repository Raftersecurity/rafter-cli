import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";
import * as tar from "tar";
import { BinaryManager, BETTERLEAKS_VERSION } from "../src/utils/binary-manager.js";

// ── Tarball extraction ──────────────────────────────────────────────

describe("BinaryManager extractTarball", () => {
  let tmpDir: string;
  let binDir: string;
  let tarballPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-bin-test-"));
    binDir = path.join(tmpDir, "bin");
    fs.mkdirSync(binDir, { recursive: true });

    // Create a tarball mimicking betterleaks release: binary + LICENSE + README.md
    const stageDir = path.join(tmpDir, "stage");
    fs.mkdirSync(stageDir);
    fs.writeFileSync(path.join(stageDir, "betterleaks"), "#!/bin/sh\necho fake", { mode: 0o755 });
    fs.writeFileSync(path.join(stageDir, "LICENSE"), "MIT License");
    fs.writeFileSync(path.join(stageDir, "README.md"), "# Betterleaks");

    tarballPath = path.join(tmpDir, "betterleaks.tar.gz");
    tar.create(
      { gzip: true, file: tarballPath, cwd: stageDir, sync: true },
      ["betterleaks", "LICENSE", "README.md"]
    );
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should extract only the betterleaks binary, not LICENSE or README", async () => {
    const binaryName = process.platform === "win32" ? "betterleaks.exe" : "betterleaks";

    await tar.extract({
      file: tarballPath,
      cwd: binDir,
      strip: 0,
      filter: (entryPath: string) => path.basename(entryPath) === binaryName
    });

    const files = fs.readdirSync(binDir);
    expect(files).toContain("betterleaks");
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
    expect(files).toContain("betterleaks");
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

// ── Betterleaks path ────────────────────────────────────────────────

describe("BinaryManager getBetterleaksPath", () => {
  let bm: BinaryManager;

  beforeEach(() => {
    bm = new BinaryManager();
  });

  it("returns a path ending in 'betterleaks' (or 'betterleaks.exe' on Windows)", () => {
    const p = bm.getBetterleaksPath();
    const basename = path.basename(p);
    if (process.platform === "win32") {
      expect(basename).toBe("betterleaks.exe");
    } else {
      expect(basename).toBe("betterleaks");
    }
  });

  it("path is inside ~/.rafter/bin", () => {
    const p = bm.getBetterleaksPath();
    expect(p).toContain(path.join(".rafter", "bin"));
  });
});

// ── isBetterleaksInstalled ──────────────────────────────────────────

describe("BinaryManager isBetterleaksInstalled", () => {
  it("returns a boolean", () => {
    const bm = new BinaryManager();
    expect(typeof bm.isBetterleaksInstalled()).toBe("boolean");
  });
});

// ── findBetterleaksOnPath ───────────────────────────────────────────

describe("BinaryManager findBetterleaksOnPath", () => {
  it("returns string or null", () => {
    const bm = new BinaryManager();
    const result = bm.findBetterleaksOnPath();
    expect(result === null || typeof result === "string").toBe(true);
  });
});

// ── Version detection ───────────────────────────────────────────────

describe("BinaryManager version detection", () => {
  it("BETTERLEAKS_VERSION is a semver string", () => {
    expect(BETTERLEAKS_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("getBetterleaksVersion returns a string", async () => {
    const bm = new BinaryManager();
    const version = await bm.getBetterleaksVersion();
    expect(typeof version).toBe("string");
    expect(version.length).toBeGreaterThan(0);
  });
});

// ── isManagedBetterleaksStale (sable-o4k) ───────────────────────────

describe("BinaryManager isManagedBetterleaksStale", () => {
  it("returns false when no managed binary is installed", async () => {
    const bm = new BinaryManager();
    vi.spyOn(bm, "isBetterleaksInstalled").mockReturnValue(false);
    expect(await bm.isManagedBetterleaksStale()).toBe(false);
  });

  it("returns false when the installed version matches the pinned version", async () => {
    const bm = new BinaryManager();
    vi.spyOn(bm, "isBetterleaksInstalled").mockReturnValue(true);
    vi.spyOn(bm, "getBetterleaksVersion").mockResolvedValue(BETTERLEAKS_VERSION);
    expect(await bm.isManagedBetterleaksStale()).toBe(false);
  });

  it("tolerates extra text around the pinned version (e.g. 'betterleaks 1.1.2')", async () => {
    const bm = new BinaryManager();
    vi.spyOn(bm, "isBetterleaksInstalled").mockReturnValue(true);
    vi.spyOn(bm, "getBetterleaksVersion").mockResolvedValue(`betterleaks version ${BETTERLEAKS_VERSION}`);
    expect(await bm.isManagedBetterleaksStale()).toBe(false);
  });

  it("returns true for a leftover older betterleaks", async () => {
    const bm = new BinaryManager();
    vi.spyOn(bm, "isBetterleaksInstalled").mockReturnValue(true);
    vi.spyOn(bm, "getBetterleaksVersion").mockResolvedValue("1.0.0");
    expect(await bm.isManagedBetterleaksStale()).toBe(true);
  });

  it("returns true for a leftover gitleaks-era binary (8.x)", async () => {
    const bm = new BinaryManager();
    vi.spyOn(bm, "isBetterleaksInstalled").mockReturnValue(true);
    vi.spyOn(bm, "getBetterleaksVersion").mockResolvedValue("8.18.0");
    expect(await bm.isManagedBetterleaksStale()).toBe(true);
  });

  it("returns false when the version can't be determined (don't churn)", async () => {
    const bm = new BinaryManager();
    vi.spyOn(bm, "isBetterleaksInstalled").mockReturnValue(true);
    vi.spyOn(bm, "getBetterleaksVersion").mockResolvedValue("unknown");
    expect(await bm.isManagedBetterleaksStale()).toBe(false);
  });
});

// ── verifyBetterleaksVerbose ────────────────────────────────────────

describe("BinaryManager verifyBetterleaksVerbose", () => {
  it("returns {ok, stdout, stderr} structure", async () => {
    const bm = new BinaryManager();
    const result = await bm.verifyBetterleaksVerbose();
    expect(result).toHaveProperty("ok");
    expect(result).toHaveProperty("stdout");
    expect(result).toHaveProperty("stderr");
    expect(typeof result.ok).toBe("boolean");
    expect(typeof result.stdout).toBe("string");
    expect(typeof result.stderr).toBe("string");
  });

  it("returns ok=false for a non-existent binary", async () => {
    const bm = new BinaryManager();
    const result = await bm.verifyBetterleaksVerbose("/tmp/nonexistent-betterleaks-binary-xyz");
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

  const getDownloadUrl = (bm: BinaryManager, platform: string, arch: string, version?: string) => {
    return (bm as any).getDownloadUrl(platform, arch, version);
  };

  it("generates correct linux x64 URL", () => {
    const url = getDownloadUrl(bm, "linux", "x64");
    expect(url).toBe(
      `https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/betterleaks_${BETTERLEAKS_VERSION}_linux_x64.tar.gz`
    );
  });

  it("generates correct darwin arm64 URL", () => {
    const url = getDownloadUrl(bm, "darwin", "arm64");
    expect(url).toBe(
      `https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/betterleaks_${BETTERLEAKS_VERSION}_darwin_arm64.tar.gz`
    );
  });

  it("generates correct windows x64 URL (zip)", () => {
    const url = getDownloadUrl(bm, "windows", "x64");
    expect(url).toBe(
      `https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/betterleaks_${BETTERLEAKS_VERSION}_windows_x64.zip`
    );
  });

  it("uses custom version when provided", () => {
    const url = getDownloadUrl(bm, "linux", "x64", "1.2.0");
    expect(url).toContain("v1.2.0");
    expect(url).toContain("betterleaks_1.2.0_linux_x64.tar.gz");
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
    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890  betterleaks_1.1.2_linux_x64.tar.gz",
    "1111111111111111111111111111111111111111111111111111111111111111  betterleaks_1.1.2_darwin_arm64.tar.gz",
    "2222222222222222222222222222222222222222222222222222222222222222  betterleaks_1.1.2_windows_x64.zip",
  ].join("\n");

  it("finds the correct hash for a known filename", () => {
    const hash = parseChecksumFile(bm, sampleChecksums, "betterleaks_1.1.2_linux_x64.tar.gz");
    expect(hash).toBe("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
  });

  it("finds the correct hash for windows zip", () => {
    const hash = parseChecksumFile(bm, sampleChecksums, "betterleaks_1.1.2_windows_x64.zip");
    expect(hash).toBe("2222222222222222222222222222222222222222222222222222222222222222");
  });

  it("returns null for unknown filename", () => {
    const hash = parseChecksumFile(bm, sampleChecksums, "betterleaks_1.1.2_freebsd_x64.tar.gz");
    expect(hash).toBeNull();
  });

  it("handles empty content", () => {
    const hash = parseChecksumFile(bm, "", "betterleaks_1.1.2_linux_x64.tar.gz");
    expect(hash).toBeNull();
  });

  it("handles content with blank lines", () => {
    const content = "\n\n" + sampleChecksums + "\n\n";
    const hash = parseChecksumFile(bm, content, "betterleaks_1.1.2_darwin_arm64.tar.gz");
    expect(hash).toBe("1111111111111111111111111111111111111111111111111111111111111111");
  });

  it("lowercases hash values", () => {
    const content = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890  betterleaks_1.1.2_linux_x64.tar.gz";
    const hash = parseChecksumFile(bm, content, "betterleaks_1.1.2_linux_x64.tar.gz");
    expect(hash).toBe("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
  });
});

// ── downloadBetterleaks error handling ──────────────────────────────

describe("BinaryManager downloadBetterleaks error handling", () => {
  it("rejects on unsupported platform", async () => {
    const bm = new BinaryManager();
    vi.spyOn(bm, "isPlatformSupported").mockReturnValue(false);

    await expect(bm.downloadBetterleaks()).rejects.toThrow(/not available for/);

    vi.restoreAllMocks();
  });

  it("accepts an onProgress callback", async () => {
    const bm = new BinaryManager();
    vi.spyOn(bm, "isPlatformSupported").mockReturnValue(false);

    const messages: string[] = [];
    await expect(
      bm.downloadBetterleaks((msg) => messages.push(msg))
    ).rejects.toThrow();

    vi.restoreAllMocks();
  });

  it("accepts a custom version parameter", async () => {
    const bm = new BinaryManager();
    vi.spyOn(bm, "isPlatformSupported").mockReturnValue(false);

    await expect(
      bm.downloadBetterleaks(undefined, "9.99.99")
    ).rejects.toThrow();

    vi.restoreAllMocks();
  });

  it("rejects malformed --version (URL injection guard)", async () => {
    const bm = new BinaryManager();
    // Should reject before any platform check / network call.
    await expect(
      bm.downloadBetterleaks(undefined, "1.1.2/../evil")
    ).rejects.toThrow(/Invalid betterleaks version/);
    await expect(
      bm.downloadBetterleaks(undefined, "../etc/passwd")
    ).rejects.toThrow(/Invalid betterleaks version/);
    await expect(
      bm.downloadBetterleaks(undefined, "1.1.2 && rm -rf /")
    ).rejects.toThrow(/Invalid betterleaks version/);
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
