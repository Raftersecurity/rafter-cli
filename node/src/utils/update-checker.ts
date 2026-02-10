import fs from "fs";
import path from "path";
import os from "os";
import axios from "axios";

const UPDATE_CHECK_FILE = path.join(os.homedir(), ".rafter", "update-check.json");
const NPM_REGISTRY_URL = "https://registry.npmjs.org/@rafter-security/cli/latest";
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

interface UpdateCheckCache {
  lastChecked: string;
  latestVersion: string;
  currentVersion: string;
  notifiedVersion?: string; // Don't nag — only notify once per new version
}

function readCache(): UpdateCheckCache | null {
  try {
    if (!fs.existsSync(UPDATE_CHECK_FILE)) return null;
    return JSON.parse(fs.readFileSync(UPDATE_CHECK_FILE, "utf-8"));
  } catch {
    return null;
  }
}

function writeCache(cache: UpdateCheckCache): void {
  try {
    const dir = path.dirname(UPDATE_CHECK_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(UPDATE_CHECK_FILE, JSON.stringify(cache), "utf-8");
  } catch {
    // Silent fail — update check is best-effort
  }
}

function shouldCheck(cache: UpdateCheckCache | null): boolean {
  if (process.env.CI || process.env.CONTINUOUS_INTEGRATION) return false;
  if (!cache) return true;
  const elapsed = Date.now() - new Date(cache.lastChecked).getTime();
  return elapsed > CHECK_INTERVAL_MS;
}

function isNewer(current: string, latest: string): boolean {
  const c = current.split(".").map(Number);
  const l = latest.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((l[i] || 0) > (c[i] || 0)) return true;
    if ((l[i] || 0) < (c[i] || 0)) return false;
  }
  return false;
}

/**
 * Check npm registry for latest version. Non-blocking, cached, silent on failure.
 *
 * Behavior:
 * - Hits the registry at most once per 24h
 * - Shows the update notice exactly once per new version discovered
 * - After the user sees the notice, stays silent until a newer version appears
 * - Skips entirely in CI environments
 */
export async function checkForUpdate(currentVersion: string): Promise<string | null> {
  const cache = readCache();

  if (!shouldCheck(cache)) {
    // Within 24h window — no registry hit, no notice
    return null;
  }

  try {
    const res = await axios.get(NPM_REGISTRY_URL, { timeout: 3000 });
    const latestVersion: string = res.data.version;

    const updateAvailable = isNewer(currentVersion, latestVersion);
    const alreadyNotified = cache?.notifiedVersion === latestVersion;

    if (updateAvailable && !alreadyNotified) {
      // New version we haven't told the user about yet
      writeCache({
        lastChecked: new Date().toISOString(),
        latestVersion,
        currentVersion,
        notifiedVersion: latestVersion,
      });
      return formatNotice(currentVersion, latestVersion);
    }

    // Either up-to-date or already notified for this version
    writeCache({
      lastChecked: new Date().toISOString(),
      latestVersion,
      currentVersion,
      notifiedVersion: cache?.notifiedVersion,
    });
  } catch {
    // Silent fail — network issues, registry down, etc.
  }

  return null;
}

function formatNotice(current: string, latest: string): string {
  return `\n  Update available: ${current} → ${latest}\n  Run: npm install -g @rafter-security/cli@latest\n   Or: pip install --upgrade rafter-cli\n`;
}
