import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";
import https from "https";
import { exec, execSync } from "child_process";
import { promisify } from "util";
import { getBinDir } from "../core/config-defaults.js";
import * as tar from "tar";

const execAsync = promisify(exec);

export const BETTERLEAKS_VERSION = "1.1.2";

/**
 * Pinned SHA256 hashes for the bundled BETTERLEAKS_VERSION release artifacts.
 * Pulled from the upstream `checksums.txt` at the time of vendoring; checked into
 * source so we don't trust the release-page `checksums.txt` to authenticate
 * itself when installing the version we ship by default.
 *
 * Whenever you bump BETTERLEAKS_VERSION, refresh these by downloading the new
 * release's `checksums.txt`.
 */
const BETTERLEAKS_PINNED_HASHES: Record<string, string> = {
  "betterleaks_1.1.2_darwin_arm64.tar.gz": "19cc2298463d7abf0aee9a03208a49834ab2e6f8411781c4cf1360827b3ded36",
  "betterleaks_1.1.2_darwin_x64.tar.gz":   "d51904879ed77fabad157ec67cb8dd3f5548e975fc32082e6abc30a026e1bec1",
  "betterleaks_1.1.2_linux_arm64.tar.gz":  "4d73dcbfe38c38878ee69e82b5aaa539398be8331f62b5640eb214ac04d890b0",
  "betterleaks_1.1.2_linux_x64.tar.gz":    "648c20617178065072ff1791d383192a62c911d9b4427f0426a8c504a6d9ddad",
  "betterleaks_1.1.2_windows_arm64.zip":   "8cc28068e8c7846027bc9b14f1c200cce64ff4198f90be5730510631c59f23ce",
  "betterleaks_1.1.2_windows_x64.zip":     "e149c86d00fb99cce8d87def2cd1ff046c6889a0e912007d44668df5980cea3a",
};

/** Allowed shape for the optional `--version` flag (prevents URL injection). */
const VERSION_PATTERN = /^[A-Za-z0-9._-]+$/;

export class BinaryManager {
  private binDir: string;

  constructor() {
    this.binDir = getBinDir();
  }

  /**
   * Check if current platform is supported
   */
  isPlatformSupported(): boolean {
    const platform = process.platform;
    const arch = process.arch;

    const supported = [
      "darwin-x64",
      "darwin-arm64",
      "linux-x64",
      "linux-arm64",
      "win32-x64",
      "win32-arm64",
    ];

    return supported.includes(`${platform}-${arch}`);
  }

  /**
   * Get platform info for display
   */
  getPlatformInfo(): { platform: string; arch: string; supported: boolean } {
    return {
      platform: process.platform,
      arch: process.arch,
      supported: this.isPlatformSupported()
    };
  }

  /**
   * Get Betterleaks binary path
   */
  getBetterleaksPath(): string {
    const platform = process.platform;
    const ext = platform === "win32" ? ".exe" : "";
    return path.join(this.binDir, `betterleaks${ext}`);
  }

  /**
   * Check if Betterleaks is installed
   */
  isBetterleaksInstalled(): boolean {
    return fs.existsSync(this.getBetterleaksPath());
  }

  /**
   * Find betterleaks on system PATH
   */
  findBetterleaksOnPath(): string | null {
    const cmd = process.platform === "win32" ? "where betterleaks" : "which betterleaks";
    try {
      const result = execSync(cmd, { timeout: 5000, encoding: "utf-8" });
      const found = result.trim().split("\n")[0].trim();
      return found || null;
    } catch {
      return null;
    }
  }

  /**
   * Verify Betterleaks binary works
   */
  async verifyBetterleaks(): Promise<boolean> {
    if (!this.isBetterleaksInstalled()) {
      return false;
    }

    try {
      await execAsync(`"${this.getBetterleaksPath()}" version`, { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Run betterleaks version and return {ok, stdout, stderr}
   */
  async verifyBetterleaksVerbose(binaryPath?: string): Promise<{ ok: boolean; stdout: string; stderr: string }> {
    const blPath = binaryPath ?? this.getBetterleaksPath();
    try {
      const { stdout, stderr } = await execAsync(`"${blPath}" version`, { timeout: 5000 });
      return { ok: true, stdout: stdout.trim(), stderr: stderr.trim() };
    } catch (e: unknown) {
      const err = e as { stdout?: string; stderr?: string };
      return {
        ok: false,
        stdout: (err.stdout ?? "").trim(),
        stderr: (err.stderr ?? String(e)).trim(),
      };
    }
  }

  /**
   * Collect diagnostic context for a failed binary (file type, uname, glibc/musl)
   */
  async collectBinaryDiagnostics(binaryPath?: string): Promise<string> {
    const blPath = binaryPath ?? this.getBetterleaksPath();
    const lines: string[] = [];

    try {
      const { stdout: fileOut } = await execAsync(`file "${blPath}"`, { timeout: 5000 });
      lines.push(`  file: ${fileOut.trim()}`);
    } catch {
      lines.push(`  file: (unavailable)`);
    }

    try {
      const { stdout: uname } = await execAsync("uname -a", { timeout: 5000 });
      lines.push(`  uname: ${uname.trim()}`);
    } catch {
      lines.push(`  uname: (unavailable)`);
    }

    lines.push(`  node arch: ${process.arch}, platform: ${process.platform}`);

    if (process.platform === "linux") {
      try {
        const { stdout: ldd } = await execAsync("ldd --version 2>&1 || true", { timeout: 5000 });
        if (ldd.includes("musl")) {
          lines.push("  libc: musl (betterleaks linux builds target glibc; musl systems need a musl build or static binary)");
        } else if (ldd.includes("GLIBC") || ldd.includes("GNU")) {
          const match = ldd.match(/(\d+\.\d+)/);
          lines.push(`  libc: glibc ${match ? match[1] : "(version unknown)"}`);
        } else {
          lines.push("  libc: unknown");
        }
      } catch {
        lines.push("  libc: (detection failed)");
      }
    }

    return lines.join("\n");
  }

  /**
   * Download and install Betterleaks.
   */
  async downloadBetterleaks(onProgress?: (message: string) => void, version: string = BETTERLEAKS_VERSION): Promise<void> {
    const log = onProgress || (() => {});

    if (!VERSION_PATTERN.test(version)) {
      throw new Error(`Invalid betterleaks version: ${version} (expected /^[A-Za-z0-9._-]+$/)`);
    }

    if (!this.isPlatformSupported()) {
      throw new Error(`Betterleaks not available for ${process.platform}/${process.arch}`);
    }

    if (!fs.existsSync(this.binDir)) {
      fs.mkdirSync(this.binDir, { recursive: true });
    }

    const platform = this.getPlatformString();
    const arch = this.getArchString();
    const url = this.getDownloadUrl(platform, arch, version);

    log(`Downloading Betterleaks v${version} for ${platform}/${arch}...`);
    log(`  URL: ${url}`);

    const archivePath = path.join(this.binDir, platform === "windows" ? "betterleaks.zip" : "betterleaks.tar.gz");

    try {
      await this.downloadFile(url, archivePath, log);

      const stats = fs.statSync(archivePath);
      log(`  Downloaded: ${(stats.size / 1024).toFixed(1)} KB`);

      log("Verifying checksum...");
      await this.verifyChecksum(archivePath, platform, arch, version, log);
      log("  ✓ Checksum verified");

      log("Extracting binary...");
      if (platform === "windows") {
        await this.extractZip(archivePath);
      } else {
        await this.extractTarball(archivePath);
      }

      if (process.platform !== "win32") {
        await execAsync(`chmod +x "${this.getBetterleaksPath()}"`);
        log("  chmod +x applied");
      }

      const { ok, stdout: verOut, stderr: verErr } = await this.verifyBetterleaksVerbose();
      if (!ok) {
        const diag = await this.collectBinaryDiagnostics();
        const binaryPath = this.getBetterleaksPath();
        throw new Error(
          `Betterleaks binary failed to execute.\n` +
          `  Binary: ${binaryPath}\n` +
          `  URL: ${url}\n` +
          (verOut ? `  betterleaks version stdout: ${verOut}\n` : "") +
          (verErr ? `  betterleaks version stderr: ${verErr}\n` : "") +
          `Diagnostics:\n${diag}\n` +
          `Fix: ensure the binary matches your OS/arch, or install betterleaks manually and ensure it is on PATH.`
        );
      }

      log(`  Verified: ${verOut}`);

      if (fs.existsSync(archivePath)) {
        fs.unlinkSync(archivePath);
      }

      log("✓ Betterleaks installed successfully");
    } catch (e) {
      if (fs.existsSync(archivePath)) {
        fs.unlinkSync(archivePath);
      }
      const blPath = this.getBetterleaksPath();
      if (fs.existsSync(blPath)) {
        fs.unlinkSync(blPath);
      }
      throw e;
    }
  }

  /**
   * Get Betterleaks version
   */
  async getBetterleaksVersion(): Promise<string> {
    if (!this.isBetterleaksInstalled()) {
      return "not installed";
    }

    try {
      const { stdout } = await execAsync(`"${this.getBetterleaksPath()}" version`);
      return stdout.trim();
    } catch {
      return "unknown";
    }
  }

  /**
   * Get platform string for download URL
   */
  private getPlatformString(): string {
    const platform = process.platform;
    if (platform === "darwin") return "darwin";
    if (platform === "win32") return "windows";
    if (platform === "linux") return "linux";
    throw new Error(`Unsupported platform: ${platform}`);
  }

  /**
   * Get architecture string for download URL
   */
  private getArchString(): string {
    const arch = process.arch;
    if (arch === "x64") return "x64";
    if (arch === "arm64") return "arm64";
    throw new Error(`Unsupported architecture: ${arch}`);
  }

  /**
   * Get download URL for platform/arch/version
   */
  private getDownloadUrl(platform: string, arch: string, version: string = BETTERLEAKS_VERSION): string {
    const baseUrl = `https://github.com/betterleaks/betterleaks/releases/download/v${version}`;

    if (platform === "windows") {
      return `${baseUrl}/betterleaks_${version}_windows_${arch}.zip`;
    } else {
      return `${baseUrl}/betterleaks_${version}_${platform}_${arch}.tar.gz`;
    }
  }

  /**
   * Download file from URL
   */
  private downloadFile(url: string, dest: string, onProgress: (msg: string) => void): Promise<void> {
    return new Promise((resolve, reject) => {
      const file = fs.createWriteStream(dest);

      https.get(url, (response) => {
        // Follow redirects (HTTPS only — never follow into http://, mailto:, etc.)
        if (response.statusCode === 302 || response.statusCode === 301) {
          const redirectUrl = response.headers.location;
          if (!redirectUrl) {
            reject(new Error("Redirect without location"));
            return;
          }
          let resolved: URL;
          try {
            resolved = new URL(redirectUrl, url);
          } catch {
            reject(new Error(`Invalid redirect URL: ${redirectUrl}`));
            return;
          }
          if (resolved.protocol !== "https:") {
            reject(new Error(`Refusing redirect to non-https URL: ${resolved.toString()}`));
            return;
          }
          file.close();
          fs.unlinkSync(dest);
          this.downloadFile(resolved.toString(), dest, onProgress).then(resolve).catch(reject);
          return;
        }

        if (response.statusCode !== 200) {
          reject(new Error(`Download failed: ${response.statusCode}`));
          return;
        }

        const totalBytes = parseInt(response.headers["content-length"] || "0", 10);
        let downloadedBytes = 0;
        let lastPercent = 0;

        response.on("data", (chunk) => {
          downloadedBytes += chunk.length;
          if (totalBytes > 0) {
            const percent = Math.round((downloadedBytes / totalBytes) * 100);
            if (percent > lastPercent && percent % 10 === 0) {
              onProgress(`Downloading... ${percent}%`);
              lastPercent = percent;
            }
          }
        });

        response.pipe(file);

        file.on("finish", () => {
          file.close();
          resolve();
        });

        file.on("error", (err) => {
          fs.unlinkSync(dest);
          reject(err);
        });
      }).on("error", (err) => {
        if (fs.existsSync(dest)) {
          fs.unlinkSync(dest);
        }
        reject(err);
      });
    });
  }

  /**
   * Verify downloaded archive checksum.
   *
   * For BETTERLEAKS_VERSION (the version we vendor), use the SHA256 pinned in
   * source — this prevents a release-page compromise from re-signing both the
   * tarball and `checksums.txt`. For an explicit `--version <other>`, fall back
   * to the upstream `checksums.txt` (TOFU at that moment).
   */
  private async verifyChecksum(
    archivePath: string,
    platform: string,
    arch: string,
    version: string,
    _onProgress: (msg: string) => void
  ): Promise<void> {
    const archiveFilename = platform === "windows"
      ? `betterleaks_${version}_windows_${arch}.zip`
      : `betterleaks_${version}_${platform}_${arch}.tar.gz`;

    let expectedHash: string | null = null;
    let source = "";

    if (version === BETTERLEAKS_VERSION && BETTERLEAKS_PINNED_HASHES[archiveFilename]) {
      expectedHash = BETTERLEAKS_PINNED_HASHES[archiveFilename];
      source = "pinned in source";
    } else {
      // Fetch the release's `checksums.txt`. This is TOFU — use the pinned table
      // for the bundled default to avoid trusting the release page on every install.
      const checksumsUrl = `https://github.com/betterleaks/betterleaks/releases/download/v${version}/checksums.txt`;
      const checksumsPath = path.join(this.binDir, "checksums.txt");
      try {
        await this.downloadFile(checksumsUrl, checksumsPath, () => {});
        const checksumsContent = fs.readFileSync(checksumsPath, "utf-8");
        expectedHash = this.parseChecksumFile(checksumsContent, archiveFilename);
      } finally {
        if (fs.existsSync(checksumsPath)) {
          fs.unlinkSync(checksumsPath);
        }
      }
      source = "release checksums.txt";
    }

    if (!expectedHash) {
      throw new Error(`Checksum not found for ${archiveFilename} (${source})`);
    }

    const actualHash = await this.computeSHA256(archivePath);
    if (actualHash !== expectedHash) {
      throw new Error(
        `Checksum mismatch for ${archiveFilename} (${source}):\n` +
        `  Expected: ${expectedHash}\n` +
        `  Actual:   ${actualHash}\n` +
        `The downloaded file may be corrupted or tampered with.`
      );
    }
  }

  /**
   * Parse a checksums.txt file and return the SHA256 hash for the given filename.
   */
  private parseChecksumFile(content: string, filename: string): string | null {
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2 && parts[1] === filename) {
        return parts[0].toLowerCase();
      }
    }
    return null;
  }

  /**
   * Compute SHA256 hash of a file.
   */
  private computeSHA256(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash("sha256");
      const stream = fs.createReadStream(filePath);
      stream.on("data", (data) => hash.update(data));
      stream.on("end", () => resolve(hash.digest("hex")));
      stream.on("error", reject);
    });
  }

  /**
   * Extract zip (Windows) — uses PowerShell's Expand-Archive, then copies
   * only the betterleaks.exe binary to binDir. Cleans up the temp extract dir.
   */
  private async extractZip(zipPath: string): Promise<void> {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-betterleaks-"));
    try {
      const safeZipPath = zipPath.replace(/'/g, "''");
      const safeTempDir = tempDir.replace(/'/g, "''");
      await execAsync(
        `powershell -NoProfile -Command "Expand-Archive -Force -LiteralPath '${safeZipPath}' -DestinationPath '${safeTempDir}'"`,
        { timeout: 30000 }
      );

      const findBinary = (dir: string): string | null => {
        for (const entry of fs.readdirSync(dir)) {
          const full = path.join(dir, entry);
          if (entry === "betterleaks.exe") return full;
          if (fs.statSync(full).isDirectory()) {
            const found = findBinary(full);
            if (found) return found;
          }
        }
        return null;
      };

      const found = findBinary(tempDir);
      if (!found) throw new Error("betterleaks.exe not found in archive");
      fs.copyFileSync(found, path.join(this.binDir, "betterleaks.exe"));
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }

  /**
   * Extract tarball — binary only, strip packaging extras (LICENSE, README.md).
   *
   * Rejects symlinks, hardlinks, and absolute / `..` paths defensively. node-tar
   * blocks `..`/absolute by default, but symlinks/hardlinks would otherwise pass
   * the basename filter and let a malicious release point `betterleaks` at e.g.
   * `~/.ssh/authorized_keys`, which the subsequent `chmod +x` would then mode-flip.
   */
  private async extractTarball(tarballPath: string): Promise<void> {
    await tar.extract({
      file: tarballPath,
      cwd: this.binDir,
      filter: (p: string, entry: any) => {
        const base = path.basename(p);
        if (base !== "betterleaks" && base !== "betterleaks.exe") return false;
        if (entry?.type && entry.type !== "File") return false;
        return true;
      },
    });

    // Post-extract belt-and-suspenders: ensure what landed is a regular file.
    const installedPath = this.getBetterleaksPath();
    if (fs.existsSync(installedPath)) {
      const st = fs.lstatSync(installedPath);
      if (!st.isFile() || st.isSymbolicLink()) {
        fs.unlinkSync(installedPath);
        throw new Error("Extracted betterleaks is not a regular file (symlink or special); aborting.");
      }
    }
  }
}
