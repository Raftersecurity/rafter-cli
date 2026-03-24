import { Command } from "commander";
import axios from "axios";
import {
  API,
  resolveKey,
  handle403,
  EXIT_SUCCESS,
  EXIT_GENERAL_ERROR,
  EXIT_SCAN_NOT_FOUND,
} from "../utils/api.js";

interface BadgeOptions {
  apiKey?: string;
  label?: string;
  style?: string;
  markdown?: boolean;
}

interface ScanData {
  status?: string;
  vulnerabilities?: Array<{ level?: string; severity?: string }>;
}

function classifyScore(data: ScanData): { message: string; color: string } {
  const status = data.status;

  if (!status || status === "failed") {
    return { message: "error", color: "critical" };
  }

  if (["queued", "pending", "processing"].includes(status)) {
    return { message: "pending", color: "yellow" };
  }

  if (status === "completed") {
    const vulns = data.vulnerabilities ?? [];
    const errors = vulns.filter(
      (v) => v.level === "error" || v.severity === "error",
    ).length;
    const warnings = vulns.filter(
      (v) => v.level === "warning" || v.severity === "warning",
    ).length;

    if (errors > 0) {
      return { message: `${errors} critical`, color: "critical" };
    }
    if (warnings > 0) {
      return { message: `${warnings} warnings`, color: "yellow" };
    }
    return { message: "passing", color: "brightgreen" };
  }

  return { message: status, color: "lightgrey" };
}

function buildShieldsUrl(
  label: string,
  message: string,
  color: string,
  style: string,
): string {
  const l = encodeURIComponent(label);
  const m = encodeURIComponent(message);
  return `https://img.shields.io/badge/${l}-${m}-${color}?style=${style}`;
}

export function createBadgeCommand(): Command {
  return new Command("badge")
    .description(
      "Generate a shields.io badge URL from the last scan status",
    )
    .argument("<scan_id>", "Scan ID to generate badge for")
    .option("-k, --api-key <key>", "API key or RAFTER_API_KEY env var")
    .option("-l, --label <label>", "Badge label", "rafter")
    .option(
      "-s, --style <style>",
      "Shield style (flat, flat-square, plastic, for-the-badge, social)",
      "flat",
    )
    .option("--markdown", "Output as markdown image tag")
    .action(async (scan_id: string, opts: BadgeOptions) => {
      const key = resolveKey(opts.apiKey);
      const headers = { "x-api-key": key };

      let data: ScanData;
      try {
        const res = await axios.get(`${API}/static/scan`, {
          params: { scan_id, format: "json" },
          headers,
        });
        data = res.data;
      } catch (e: any) {
        const code403 = handle403(e);
        if (code403 >= 0) {
          process.exit(code403);
        }
        if (e.response?.status === 404) {
          console.error(`Scan '${scan_id}' not found`);
          process.exit(EXIT_SCAN_NOT_FOUND);
        }
        console.error(`Error: ${e.response?.data || e.message}`);
        process.exit(EXIT_GENERAL_ERROR);
      }

      const { message, color } = classifyScore(data);
      const label = opts.label ?? "rafter";
      const style = opts.style ?? "flat";
      const url = buildShieldsUrl(label, message, color, style);

      if (opts.markdown) {
        process.stdout.write(
          `[![${label}](${url})](https://rafter.so)\n`,
        );
      } else {
        process.stdout.write(url + "\n");
      }

      process.exit(EXIT_SUCCESS);
    });
}
