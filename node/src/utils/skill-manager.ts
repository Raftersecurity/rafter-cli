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
   * Get path to Rafter Security skill in OpenClaw
   */
  getRafterSkillPath(): string {
    return path.join(this.getOpenClawSkillsDir(), "rafter-security.md");
  }

  /**
   * Get path to old skill-auditor (for migration)
   */
  getOldSkillAuditorPath(): string {
    return path.join(this.getOpenClawSkillsDir(), "rafter-skill-auditor.md");
  }

  /**
   * Get path to Rafter Security skill source in CLI resources
   */
  getRafterSkillSourcePath(): string {
    // Go up from src/utils/ to node/ then into resources/
    return path.join(__dirname, "..", "..", "resources", "rafter-security-skill.md");
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
   * Check if Rafter Security skill is installed
   */
  isRafterSkillInstalled(): boolean {
    return fs.existsSync(this.getRafterSkillPath());
  }

  /**
   * Check if old skill-auditor is installed (for migration)
   */
  hasOldSkillAuditor(): boolean {
    return fs.existsSync(this.getOldSkillAuditorPath());
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
   * Get version of installed Rafter Security skill
   */
  getInstalledVersion(): string | null {
    if (!this.isRafterSkillInstalled()) {
      return null;
    }

    try {
      const content = fs.readFileSync(this.getRafterSkillPath(), "utf-8");
      const metadata = this.parseSkillMetadata(content);
      return metadata?.version || null;
    } catch (e) {
      return null;
    }
  }

  /**
   * Get version of Rafter Security skill in CLI resources
   */
  getSourceVersion(): string | null {
    try {
      const content = fs.readFileSync(this.getRafterSkillSourcePath(), "utf-8");
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
    if (!this.isRafterSkillInstalled()) {
      return false;
    }

    try {
      const installedContent = fs.readFileSync(this.getRafterSkillPath(), "utf-8");
      const sourceContent = fs.readFileSync(this.getRafterSkillSourcePath(), "utf-8");

      const installedHash = this.calculateContentHash(installedContent);
      const sourceHash = this.calculateContentHash(sourceContent);

      return installedHash !== sourceHash;
    } catch (e) {
      return false;
    }
  }

  /**
   * Migrate from old separate skill-auditor to combined Rafter Security skill
   */
  async migrateOldSkill(): Promise<void> {
    if (this.hasOldSkillAuditor()) {
      try {
        // Remove old skill-auditor file
        fs.unlinkSync(this.getOldSkillAuditorPath());
        console.log("✓ Migrated from separate skill-auditor to combined Rafter Security skill");
      } catch (e) {
        // Ignore migration errors
      }
    }
  }

  /**
   * Install Rafter Security skill to OpenClaw
   */
  async installRafterSkill(force: boolean = false): Promise<boolean> {
    if (!this.isOpenClawInstalled()) {
      return false;
    }

    const skillPath = this.getRafterSkillPath();
    const sourcePath = this.getRafterSkillSourcePath();

    // Check if already installed and not forcing
    if (!force && this.isRafterSkillInstalled()) {
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

      // Migrate old skill-auditor if present
      await this.migrateOldSkill();

      return true;
    } catch (e) {
      console.error(`Failed to install Rafter Security skill: ${e}`);
      return false;
    }
  }

  /**
   * Backup current skill before updating
   */
  backupSkill(): boolean {
    if (!this.isRafterSkillInstalled()) {
      return false;
    }

    try {
      const backupsDir = this.getBackupsDir();
      if (!fs.existsSync(backupsDir)) {
        fs.mkdirSync(backupsDir, { recursive: true });
      }

      const version = this.getInstalledVersion() || "unknown";
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backupPath = path.join(backupsDir, `rafter-security.md.v${version}.${timestamp}`);

      const content = fs.readFileSync(this.getRafterSkillPath(), "utf-8");
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
        .filter(f => f.startsWith("rafter-security.md.v") || f.startsWith("rafter-skill-auditor.md.v"))
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
   * Update Rafter Security skill to latest version
   */
  async updateRafterSkill(options: {
    force?: boolean;
    backup?: boolean;
  } = {}): Promise<{ updated: boolean; message: string }> {
    if (!this.isOpenClawInstalled()) {
      return { updated: false, message: "OpenClaw not installed" };
    }

    if (!this.isRafterSkillInstalled()) {
      // Install if not present
      const installed = await this.installRafterSkill();
      return {
        updated: installed,
        message: installed ? "Rafter Security skill installed" : "Failed to install Rafter Security skill"
      };
    }

    const installedVersion = this.getInstalledVersion();
    const sourceVersion = this.getSourceVersion();

    if (!sourceVersion) {
      return { updated: false, message: "Could not determine source version" };
    }

    // Check if update needed
    if (!options.force && installedVersion === sourceVersion) {
      return { updated: false, message: "Rafter Security skill is up to date" };
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
    const installed = await this.installRafterSkill(true);
    if (installed) {
      return {
        updated: true,
        message: `Updated Rafter Security skill: ${installedVersion || 'unknown'} → ${sourceVersion}`
      };
    } else {
      return {
        updated: false,
        message: "Failed to update Rafter Security skill"
      };
    }
  }

  /**
   * Remove Rafter Security skill
   */
  removeRafterSkill(): boolean {
    if (!this.isRafterSkillInstalled()) {
      return false;
    }

    try {
      fs.unlinkSync(this.getRafterSkillPath());

      // Clear config
      this.configManager.set("agent.skills.installedVersion", undefined);

      return true;
    } catch (e) {
      console.error(`Failed to remove Rafter Security skill: ${e}`);
      return false;
    }
  }

  /**
   * Check if skill update is available
   */
  isUpdateAvailable(): boolean {
    if (!this.isRafterSkillInstalled()) {
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
    const result = await this.updateRafterSkill({ backup: true });

    if (!silent && result.updated) {
      console.log(`✓ ${result.message}`);
    }

    // Update last checked timestamp
    this.configManager.set("agent.skills.lastChecked", new Date().toISOString());
  }
}
