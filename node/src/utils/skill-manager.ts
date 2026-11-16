import fs from "fs";
import path from "path";
import os from "os";
import { openclawLegacySkillPath, openclawSkillPath } from "../commands/agent/install-files.js";

export interface SkillMetadata {
  name: string;
  version: string;
  rafter_cli_version: string;
  last_updated: string;
}

/**
 * Read-only view of the OpenClaw skill install, for `agent verify`, `agent
 * status` and `agent audit-skill`. Installing and updating go through
 * install-files.ts like every other platform.
 */
export class SkillManager {
  /**
   * Path to the OpenClaw root directory.
   *
   * The platform's presence is the platform root, not the skills dir — a
   * fresh OpenClaw install has no skills written yet.
   */
  getOpenClawRoot(): string {
    return path.join(os.homedir(), ".openclaw");
  }

  /**
   * Path to the OpenClaw default-workspace skills directory.
   *
   * Per docs.openclaw.ai/tools/skills, OpenClaw auto-discovers skills from
   * `<workspace>/skills/<skill>/SKILL.md`. The default workspace lives at
   * `~/.openclaw/workspace/`. ClawHub-style skills are directories
   * containing a `SKILL.md`, not loose markdown files.
   *
   * Earlier rafter versions wrote to `~/.openclaw/skills/<name>.md` — that
   * path was never read by OpenClaw at runtime. Migrated in rf-zgwj.
   */
  getOpenClawSkillsDir(): string {
    return path.join(this.getOpenClawRoot(), "workspace", "skills");
  }

  /**
   * Path to the Rafter Security skill directory (containing SKILL.md).
   */
  getRafterSkillDir(): string {
    return path.join(this.getOpenClawSkillsDir(), "rafter-security");
  }

  /**
   * Path to the Rafter Security SKILL.md file.
   */
  getRafterSkillPath(): string {
    return openclawSkillPath(os.homedir());
  }

  /**
   * Legacy install path used by rafter ≤ 0.7.7. Removed on reinstall.
   */
  getLegacyRafterSkillPath(): string {
    return openclawLegacySkillPath(os.homedir());
  }

  /**
   * Check if OpenClaw is installed.
   *
   * Detects the platform root (~/.openclaw) — a fresh OpenClaw install
   * doesn't have the workspace skills dir yet, so checking the skills dir
   * gave a false-negative until at least one skill was written.
   */
  isOpenClawInstalled(): boolean {
    return fs.existsSync(this.getOpenClawRoot());
  }

  /**
   * Check if the legacy skill file from rafter ≤ 0.7.7 is present.
   * Used to print a migration note on reinstall (rf-zgwj).
   */
  hasLegacyRafterSkill(): boolean {
    return fs.existsSync(this.getLegacyRafterSkillPath());
  }

  /**
   * Check if Rafter Security skill is installed
   */
  isRafterSkillInstalled(): boolean {
    return fs.existsSync(this.getRafterSkillPath());
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
}
