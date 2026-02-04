import fs from "fs";
import path from "path";
import os from "os";
import { createHash } from "crypto";
import { ConfigManager } from "../core/config-manager.js";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface SkillMetadata {
  name: string;
  version: string;
  rafter_cli_version: string;
  last_updated: string;
}

export class SkillManager {
  private configManager: ConfigManager;

  constructor() {
    this.configManager = new ConfigManager();
  }

  /**
   * Get path to OpenClaw skills directory
   */
  getOpenClawSkillsDir(): string {
    return path.join(os.homedir(), ".openclaw", "skills");
  }

  /**
   * Get path to skill-auditor in OpenClaw
   */
  getSkillAuditorPath(): string {
    return path.join(this.getOpenClawSkillsDir(), "rafter-skill-auditor.md");
  }

  /**
   * Get path to skill-auditor source in CLI resources
   */
  getSkillAuditorSourcePath(): string {
    // Go up from src/utils/ to node/ then into resources/
    return path.join(__dirname, "..", "..", "resources", "rafter-skill-auditor.md");
  }

  /**
   * Get path to backups directory
   */
  getBackupsDir(): string {
    return path.join(this.getOpenClawSkillsDir(), ".backups");
  }

  /**
   * Check if OpenClaw is installed (skills directory exists)
   */
  isOpenClawInstalled(): boolean {
    return fs.existsSync(this.getOpenClawSkillsDir());
  }

  /**
   * Check if skill-auditor is installed
   */
  isSkillAuditorInstalled(): boolean {
    return fs.existsSync(this.getSkillAuditorPath());
  }

  /**
   * Parse frontmatter metadata from skill file
   */
  parseSkillMetadata(content: string): SkillMetadata | null {
    const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---/);
    if (!frontmatterMatch) {
      return null;
    }

    const frontmatter = frontmatterMatch[1];
    const metadata: any = {};

    frontmatter.split('\n').forEach(line => {
      const [key, ...valueParts] = line.split(':');
      if (key && valueParts.length > 0) {
        metadata[key.trim()] = valueParts.join(':').trim();
      }
    });

    if (!metadata.name || !metadata.version) {
      return null;
    }

    return metadata as SkillMetadata;
  }

  /**
   * Get version of installed skill-auditor
   */
  getInstalledVersion(): string | null {
    if (!this.isSkillAuditorInstalled()) {
      return null;
    }

    try {
      const content = fs.readFileSync(this.getSkillAuditorPath(), "utf-8");
      const metadata = this.parseSkillMetadata(content);
      return metadata?.version || null;
    } catch (e) {
      return null;
    }
  }

  /**
   * Get version of skill-auditor in CLI resources
   */
  getSourceVersion(): string | null {
    try {
      const content = fs.readFileSync(this.getSkillAuditorSourcePath(), "utf-8");
      const metadata = this.parseSkillMetadata(content);
      return metadata?.version || null;
    } catch (e) {
      return null;
    }
  }

  /**
   * Calculate hash of file content (excluding frontmatter for version)
   */
  calculateContentHash(content: string): string {
    // Remove frontmatter for hash calculation
    const withoutFrontmatter = content.replace(/^---\n[\s\S]*?\n---\n/, '');
    return createHash('sha256').update(withoutFrontmatter).digest('hex').substring(0, 8);
  }

  /**
   * Check if installed skill has been modified by user
   */
  isSkillModified(): boolean {
    if (!this.isSkillAuditorInstalled()) {
      return false;
    }

    try {
      const installedContent = fs.readFileSync(this.getSkillAuditorPath(), "utf-8");
      const sourceContent = fs.readFileSync(this.getSkillAuditorSourcePath(), "utf-8");

      const installedHash = this.calculateContentHash(installedContent);
      const sourceHash = this.calculateContentHash(sourceContent);

      return installedHash !== sourceHash;
    } catch (e) {
      return false;
    }
  }

  /**
   * Install skill-auditor to OpenClaw
   */
  async installSkillAuditor(force: boolean = false): Promise<boolean> {
    if (!this.isOpenClawInstalled()) {
      return false;
    }

    const skillPath = this.getSkillAuditorPath();
    const sourcePath = this.getSkillAuditorSourcePath();

    // Check if already installed and not forcing
    if (!force && this.isSkillAuditorInstalled()) {
      return true;
    }

    try {
      // Ensure skills directory exists
      const skillsDir = this.getOpenClawSkillsDir();
      if (!fs.existsSync(skillsDir)) {
        fs.mkdirSync(skillsDir, { recursive: true });
      }

      // Copy skill file
      const sourceContent = fs.readFileSync(sourcePath, "utf-8");
      fs.writeFileSync(skillPath, sourceContent, "utf-8");

      // Update config
      const version = this.getSourceVersion();
      if (version) {
        this.configManager.set("agent.skills.installedVersion", version);
        this.configManager.set("agent.skills.lastChecked", new Date().toISOString());
      }

      return true;
    } catch (e) {
      console.error(`Failed to install skill-auditor: ${e}`);
      return false;
    }
  }

  /**
   * Backup current skill before updating
   */
  backupSkill(): boolean {
    if (!this.isSkillAuditorInstalled()) {
      return false;
    }

    try {
      const backupsDir = this.getBackupsDir();
      if (!fs.existsSync(backupsDir)) {
        fs.mkdirSync(backupsDir, { recursive: true });
      }

      const version = this.getInstalledVersion() || "unknown";
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backupPath = path.join(backupsDir, `rafter-skill-auditor.md.v${version}.${timestamp}`);

      const content = fs.readFileSync(this.getSkillAuditorPath(), "utf-8");
      fs.writeFileSync(backupPath, content, "utf-8");

      // Keep only last 3 backups
      this.cleanupOldBackups(3);

      return true;
    } catch (e) {
      console.error(`Failed to backup skill: ${e}`);
      return false;
    }
  }

  /**
   * Remove old backups, keeping only the most recent N
   */
  private cleanupOldBackups(keep: number): void {
    const backupsDir = this.getBackupsDir();
    if (!fs.existsSync(backupsDir)) {
      return;
    }

    try {
      const files = fs.readdirSync(backupsDir)
        .filter(f => f.startsWith("rafter-skill-auditor.md.v"))
        .map(f => ({
          name: f,
          path: path.join(backupsDir, f),
          mtime: fs.statSync(path.join(backupsDir, f)).mtime
        }))
        .sort((a, b) => b.mtime.getTime() - a.mtime.getTime());

      // Remove old backups
      files.slice(keep).forEach(file => {
        fs.unlinkSync(file.path);
      });
    } catch (e) {
      // Ignore cleanup errors
    }
  }

  /**
   * Update skill-auditor to latest version
   */
  async updateSkillAuditor(options: {
    force?: boolean;
    backup?: boolean;
  } = {}): Promise<{ updated: boolean; message: string }> {
    if (!this.isOpenClawInstalled()) {
      return { updated: false, message: "OpenClaw not installed" };
    }

    if (!this.isSkillAuditorInstalled()) {
      // Install if not present
      const installed = await this.installSkillAuditor();
      return {
        updated: installed,
        message: installed ? "Skill auditor installed" : "Failed to install skill auditor"
      };
    }

    const installedVersion = this.getInstalledVersion();
    const sourceVersion = this.getSourceVersion();

    if (!sourceVersion) {
      return { updated: false, message: "Could not determine source version" };
    }

    // Check if update needed
    if (!options.force && installedVersion === sourceVersion) {
      return { updated: false, message: "Skill auditor is up to date" };
    }

    // Check if modified
    if (!options.force && this.isSkillModified()) {
      return {
        updated: false,
        message: "Skill has been modified. Use --force to overwrite."
      };
    }

    // Backup if requested
    const config = this.configManager.load();
    if (options.backup !== false && config.agent?.skills.backupBeforeUpdate) {
      this.backupSkill();
    }

    // Install new version
    const installed = await this.installSkillAuditor(true);
    if (installed) {
      return {
        updated: true,
        message: `Updated skill auditor: ${installedVersion || 'unknown'} → ${sourceVersion}`
      };
    } else {
      return {
        updated: false,
        message: "Failed to update skill auditor"
      };
    }
  }

  /**
   * Remove skill-auditor
   */
  removeSkillAuditor(): boolean {
    if (!this.isSkillAuditorInstalled()) {
      return false;
    }

    try {
      fs.unlinkSync(this.getSkillAuditorPath());

      // Clear config
      this.configManager.set("agent.skills.installedVersion", undefined);

      return true;
    } catch (e) {
      console.error(`Failed to remove skill-auditor: ${e}`);
      return false;
    }
  }

  /**
   * Check if skill update is available
   */
  isUpdateAvailable(): boolean {
    if (!this.isSkillAuditorInstalled()) {
      return false;
    }

    const installedVersion = this.getInstalledVersion();
    const sourceVersion = this.getSourceVersion();

    if (!installedVersion || !sourceVersion) {
      return false;
    }

    return installedVersion !== sourceVersion;
  }

  /**
   * Check for updates and auto-update if configured
   */
  async checkAndUpdate(silent: boolean = true): Promise<void> {
    const config = this.configManager.load();

    // Skip if auto-update disabled
    if (!config.agent?.skills.autoUpdate) {
      return;
    }

    // Check if update available
    if (!this.isUpdateAvailable()) {
      return;
    }

    // Update silently
    const result = await this.updateSkillAuditor({ backup: true });

    if (!silent && result.updated) {
      console.log(`✓ ${result.message}`);
    }

    // Update last checked timestamp
    this.configManager.set("agent.skills.lastChecked", new Date().toISOString());
  }
}
