import fs from "fs";
import path from "path";
import https from "https";
import { exec } from "child_process";
import { promisify } from "util";
import { getBinDir } from "../core/config-defaults.js";
import tar from "tar";

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

    const archivePath = path.join(this.binDir, platform === "windows" ? "gitleaks.zip" : "gitleaks.tar.gz");

    try {
      // Download archive
      await this.downloadFile(url, archivePath, log);

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
      }

      // Verify it works
      const works = await this.verifyGitleaks();
      if (!works) {
        throw new Error("Downloaded binary doesn't execute correctly");
      }

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

