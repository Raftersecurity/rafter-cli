import fs from "fs";
import path from "path";
import https from "https";
import { exec, execSync } from "child_process";
import { promisify } from "util";
import { getBinDir } from "../core/config-defaults.js";
import * as tar from "tar";

const execAsync = promisify(exec);

const GITLEAKS_VERSION = "8.18.2";

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

    // Supported platforms
    const supported = [
      "darwin-x64",
      "darwin-arm64",
      "linux-x64",
      "linux-arm64",
      "win32-x64"
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
   * Get Gitleaks binary path
   */
  getGitleaksPath(): string {
    const platform = process.platform;
    const ext = platform === "win32" ? ".exe" : "";
    return path.join(this.binDir, `gitleaks${ext}`);
  }

  /**
   * Check if Gitleaks is installed
   */
  isGitleaksInstalled(): boolean {
    const gitleaksPath = this.getGitleaksPath();
    return fs.existsSync(gitleaksPath);
  }

  /**
   * Find gitleaks on system PATH (like Python's shutil.which)
   */
  findGitleaksOnPath(): string | null {
    const cmd = process.platform === "win32" ? "where gitleaks" : "which gitleaks";
    try {
      const result = execSync(cmd, { timeout: 5000, encoding: "utf-8" });
      const found = result.trim().split("\n")[0].trim();
      return found || null;
    } catch {
      return null;
    }
  }

  /**
   * Verify Gitleaks binary works
   */
  async verifyGitleaks(): Promise<boolean> {
    if (!this.isGitleaksInstalled()) {
      return false;
    }

    try {
      const { stdout } = await execAsync(`"${this.getGitleaksPath()}" version`, {
        timeout: 5000
      });
      return stdout.includes("gitleaks version");
    } catch {
      return false;
    }
  }

  /**
   * Run gitleaks version and return {ok, stdout, stderr}
   */
  async verifyGitleaksVerbose(binaryPath?: string): Promise<{ ok: boolean; stdout: string; stderr: string }> {
    const gitleaksPath = binaryPath ?? this.getGitleaksPath();
    try {
      const { stdout, stderr } = await execAsync(`"${gitleaksPath}" version`, { timeout: 5000 });
      const ok = stdout.includes("gitleaks version");
      return { ok, stdout: stdout.trim(), stderr: stderr.trim() };
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
    const gitleaksPath = binaryPath ?? this.getGitleaksPath();
    const lines: string[] = [];

    try {
      const { stdout: fileOut } = await execAsync(`file "${gitleaksPath}"`, { timeout: 5000 });
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

    // Detect glibc vs musl on Linux
    if (process.platform === "linux") {
      try {
        const { stdout: ldd } = await execAsync("ldd --version 2>&1 || true", { timeout: 5000 });
        if (ldd.includes("musl")) {
          lines.push("  libc: musl (gitleaks linux builds target glibc; musl systems need a musl build or static binary)");
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
   * Download and install Gitleaks
   */
  async downloadGitleaks(onProgress?: (message: string) => void): Promise<void> {
    const log = onProgress || (() => {});

    // Check platform support
    if (!this.isPlatformSupported()) {
      throw new Error(`Gitleaks not available for ${process.platform}/${process.arch}`);
    }

    // Ensure bin directory exists
    if (!fs.existsSync(this.binDir)) {
      fs.mkdirSync(this.binDir, { recursive: true });
    }

    const platform = this.getPlatformString();
    const arch = this.getArchString();
    const url = this.getDownloadUrl(platform, arch);

    log(`Downloading Gitleaks v${GITLEAKS_VERSION} for ${platform}/${arch}...`);
    log(`  URL: ${url}`);

    const archivePath = path.join(this.binDir, platform === "windows" ? "gitleaks.zip" : "gitleaks.tar.gz");

    try {
      // Download archive
      await this.downloadFile(url, archivePath, log);

      // Log downloaded file size as basic integrity signal
      const stats = fs.statSync(archivePath);
      log(`  Downloaded: ${(stats.size / 1024).toFixed(1)} KB`);

      // Extract binary
      log("Extracting binary...");
      if (platform === "windows") {
        // For Windows, we'd need unzip - for now just error
        throw new Error("Windows support coming soon");
      } else {
        await this.extractTarball(archivePath);
      }

      // Make executable (Unix systems)
      if (process.platform !== "win32") {
        await execAsync(`chmod +x "${this.getGitleaksPath()}"`);
        log("  chmod +x applied");
      }

      // Verify it works — capture output for diagnostics
      const { ok, stdout: verOut, stderr: verErr } = await this.verifyGitleaksVerbose();
      if (!ok) {
        const diag = await this.collectBinaryDiagnostics();
        const binaryPath = this.getGitleaksPath();
        throw new Error(
          `Gitleaks binary failed to execute.\n` +
          `  Binary: ${binaryPath}\n` +
          `  URL: ${url}\n` +
          (verOut ? `  gitleaks version stdout: ${verOut}\n` : "") +
          (verErr ? `  gitleaks version stderr: ${verErr}\n` : "") +
          `Diagnostics:\n${diag}\n` +
          `Fix: ensure the binary matches your OS/arch, or install gitleaks manually and ensure it is on PATH.`
        );
      }

      log(`  Verified: ${verOut}`);

      // Clean up archive
      if (fs.existsSync(archivePath)) {
        fs.unlinkSync(archivePath);
      }

      log("✓ Gitleaks installed successfully");
    } catch (e) {
      // Clean up on failure
      if (fs.existsSync(archivePath)) {
        fs.unlinkSync(archivePath);
      }
      const gitleaksPath = this.getGitleaksPath();
      if (fs.existsSync(gitleaksPath)) {
        fs.unlinkSync(gitleaksPath);
      }
      throw e;
    }
  }

  /**
   * Get Gitleaks version
   */
  async getGitleaksVersion(): Promise<string> {
    if (!this.isGitleaksInstalled()) {
      return "not installed";
    }

    try {
      const { stdout } = await execAsync(`"${this.getGitleaksPath()}" version`);
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
   * Get download URL for platform/arch
   */
  private getDownloadUrl(platform: string, arch: string): string {
    const baseUrl = `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}`;

    if (platform === "windows") {
      return `${baseUrl}/gitleaks_${GITLEAKS_VERSION}_windows_${arch}.zip`;
    } else {
      return `${baseUrl}/gitleaks_${GITLEAKS_VERSION}_${platform}_${arch}.tar.gz`;
    }
  }

  /**
   * Download file from URL
   */
  private downloadFile(url: string, dest: string, onProgress: (msg: string) => void): Promise<void> {
    return new Promise((resolve, reject) => {
      const file = fs.createWriteStream(dest);

      https.get(url, (response) => {
        // Follow redirects
        if (response.statusCode === 302 || response.statusCode === 301) {
          const redirectUrl = response.headers.location;
          if (!redirectUrl) {
            reject(new Error("Redirect without location"));
            return;
          }
          file.close();
          fs.unlinkSync(dest);
          this.downloadFile(redirectUrl, dest, onProgress).then(resolve).catch(reject);
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
   * Extract tarball
   */
  private async extractTarball(tarballPath: string): Promise<void> {
    await tar.extract({
      file: tarballPath,
      cwd: this.binDir,
      strip: 0
    });
  }
}

