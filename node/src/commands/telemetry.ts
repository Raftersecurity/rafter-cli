import { Command } from "commander";
import { createRequire } from "module";
import fs from "fs";
import {
  USAGE_FAMILIES,
  USAGE_NOTICE,
  USAGE_STORE_DISPLAY,
  USAGE_ALLOWLIST,
  clearStore,
  discardPending,
  readCounters,
  usageStatus,
} from "../core/usage-counters.js";
import { getConfigPath } from "../core/config-defaults.js";
import { listBundledSkills, readSkillFrontmatter, skillDestPath, SKILL_PLATFORMS } from "./skill/registry.js";

const require = createRequire(import.meta.url);
const { version: VERSION } = require("../../package.json");

const FAMILY_TITLES: Record<string, string> = {
  unknown_command: "Unknown commands",
  unknown_option: "Unknown options",
  command: "Command results",
  hook: "Hook decisions",
  scan_engine: "Scan engines",
  scan_fallback: "Scan fall-backs",
  scan_duration: "Scan durations",
  error_class: "Errors",
};

const VERSION_RE = /^[0-9A-Za-z.+-]{1,32}$/;
const cleanVersion = (v: unknown): string | null =>
  typeof v === "string" && VERSION_RE.test(v) ? v : v == null ? null : "other";

interface SkillStaleness {
  name: string;
  platform: string;
  installed_version: string | null;
  current_version: string;
  stale: boolean;
}

/** Installed rafter skills vs the versions this CLI ships. Names and platforms are enumerated, never read from disk. */
function skillStaleness(): SkillStaleness[] {
  const rows: SkillStaleness[] = [];
  for (const skill of listBundledSkills()) {
    for (const platform of SKILL_PLATFORMS) {
      const dest = skillDestPath(platform, skill.name);
      if (!fs.existsSync(dest)) continue;
      const fm = readSkillFrontmatter(dest);
      const installed = cleanVersion(fm.version ?? null);
      const pinned = cleanVersion(fm.rafter_cli_version ?? null);
      rows.push({
        name: skill.name,
        platform,
        installed_version: installed,
        current_version: skill.version,
        stale: installed !== skill.version || (pinned !== null && pinned !== VERSION),
      });
    }
  }
  let openclaw: unknown;
  try {
    const cfg = JSON.parse(fs.readFileSync(getConfigPath(), "utf-8"));
    openclaw = cfg?.agent?.skills?.installedVersion ?? cfg?.agent?.skills?.installed_version;
  } catch {
    openclaw = undefined;
  }
  if (typeof openclaw === "string" && openclaw) {
    const installed = cleanVersion(openclaw);
    rows.push({
      name: "rafter-security",
      platform: "openclaw",
      installed_version: installed,
      current_version: VERSION,
      stale: installed !== VERSION,
    });
  }
  return rows.sort((a, b) => (a.name + "\0" + a.platform < b.name + "\0" + b.platform ? -1 : 1));
}

export function buildTelemetryReport(days: number): Record<string, unknown> {
  const status = usageStatus();
  const { since, counters } = readCounters(days);
  return {
    schema: USAGE_ALLOWLIST.schema,
    notice: USAGE_NOTICE,
    cli_version: VERSION,
    runtime: "node",
    runtime_major: Number(process.versions.node.split(".")[0]),
    os: process.platform,
    enabled: status.enabled,
    enabled_source: status.source,
    store: USAGE_STORE_DISPLAY,
    days,
    since,
    counters,
    skills: skillStaleness(),
  };
}

function printText(r: any): void {
  const out: string[] = [];
  out.push(`Rafter usage counters, last ${r.days} day(s) (since ${r.since} UTC)`);
  out.push(r.notice);
  out.push("");
  out.push(`CLI version:  ${r.cli_version}`);
  out.push(`Runtime:      ${r.runtime} ${r.runtime_major}`);
  out.push(`OS:           ${r.os}`);
  out.push(`Counting:     ${r.enabled ? "enabled" : "disabled"} (${r.enabled_source})`);
  out.push(`Store:        ${r.store}`);
  let any = false;
  for (const fam of USAGE_FAMILIES) {
    const entries = Object.entries(r.counters[fam] as Record<string, number>);
    if (entries.length === 0) continue;
    any = true;
    out.push("");
    out.push(FAMILY_TITLES[fam] ?? fam);
    for (const [k, n] of entries) out.push(`  ${k.padEnd(48)} ${n}`);
  }
  if (!any) {
    out.push("");
    out.push("No counts recorded.");
  }
  out.push("");
  out.push("Skills");
  if (r.skills.length === 0) out.push("  (no rafter skills installed)");
  for (const s of r.skills as SkillStaleness[]) {
    const label = `${s.name} (${s.platform})`.padEnd(36);
    out.push(`  ${label} installed ${s.installed_version ?? "unknown"}, current ${s.current_version}: ${s.stale ? "stale" : "up to date"}`);
  }
  process.stdout.write(out.join("\n") + "\n");
}

export function createTelemetryCommand(): Command {
  const telemetry = new Command("telemetry")
    .description(`Show or clear local usage counters. ${USAGE_NOTICE}`);

  telemetry
    .command("show")
    .description(`Print the local usage counters for the last N days. ${USAGE_NOTICE}`)
    .option("--json", "Output machine-readable JSON")
    .option("--days <n>", "Days to include, 1 to 7", "7")
    .action((opts) => {
      const days = Number(opts.days);
      if (!/^\d+$/.test(String(opts.days)) || days < 1 || days > USAGE_ALLOWLIST.retention_days) {
        console.error(`Error: --days must be an integer from 1 to ${USAGE_ALLOWLIST.retention_days}`);
        process.exit(2);
      }
      const report = buildTelemetryReport(days);
      if (opts.json) process.stdout.write(JSON.stringify(report, null, 2) + "\n");
      else printText(report);
    });

  telemetry
    .command("clear")
    .description(`Delete the local usage counters (${USAGE_STORE_DISPLAY})`)
    .action(() => {
      discardPending();
      const existed = clearStore();
      process.stdout.write(
        existed
          ? `Deleted local usage counters (${USAGE_STORE_DISPLAY}).\n`
          : `No local usage counters to delete (${USAGE_STORE_DISPLAY}).\n`,
      );
    });

  return telemetry;
}
