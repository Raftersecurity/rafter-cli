import { Command } from "commander";
import { API, resolveKey, EXIT_GENERAL_ERROR, EXIT_SCAN_NOT_FOUND, apiClient, apiUrl} from "../utils/api.js";
import { validateWebhookUrl } from "../core/audit-logger.js";
import { ConfigManager } from "../core/config-manager.js";
import { fmt, isAgentMode } from "../utils/formatter.js";

interface Vulnerability {
  severity?: string;
  level?: string;
  title?: string;
  rule_id?: string;
  ruleId?: string;
  message?: string;
  location?: string;
  // Real API shape (GET /api/static/scan).
  file_path?: string | null;
  line_start?: number | null;
  // Pre-rename names — fallback for old cached payloads.
  file?: string;
  line?: number;
}

interface ScanData {
  status?: string;
  repository_name?: string;
  scan_id?: string;
  branch_name?: string;
  // Real scan API shape. `findings` is a legacy fallback for old cached payloads.
  vulnerabilities?: Vulnerability[];
  findings?: Vulnerability[];
  summary?: Record<string, unknown>;
  [key: string]: unknown;
}

interface NormalizedFinding {
  severity: string;
  title: string;
  location: string;
}

interface NormalizedScan {
  findings: NormalizedFinding[];
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

// Map a raw severity/level to a display tier, using the same rules as the
// GitHub Action (github-action/action.yml) and `rafter get`, so notify agrees
// with both. A value outside the known set is kept verbatim so a finding is
// never silently dropped.
function severityTier(raw?: string): string {
  switch ((raw ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "error":
    case "high":
      return "high";
    case "warning":
    case "medium":
      return "medium";
    case "note":
    case "low":
      return "low";
    default:
      return (raw ?? "unknown").toLowerCase();
  }
}

// Read findings from the real scan shape (`vulnerabilities[]`), falling back to
// the legacy `findings[]` for old cached payloads. Counts are derived from each
// finding's own severity — never from `summary` — so a finding cannot be lost
// to a summary field this code does not read. "Clean" is therefore reported
// only when there are genuinely zero findings.
function normalizeScan(scan: ScanData): NormalizedScan {
  const raw: Vulnerability[] = Array.isArray(scan.vulnerabilities)
    ? scan.vulnerabilities
    : Array.isArray(scan.findings)
      ? scan.findings
      : [];

  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;

  const findings: NormalizedFinding[] = raw.map((v) => {
    const tier = severityTier(v.severity ?? v.level);
    if (tier === "critical") critical++;
    else if (tier === "high") high++;
    else if (tier === "medium") medium++;
    else if (tier === "low") low++;

    const title = v.title ?? v.rule_id ?? v.ruleId ?? v.message ?? "Unknown";
    const file = v.file_path ?? v.file;
    const line = v.line_start ?? v.line;
    let location = v.location ?? file ?? "";
    if (!v.location && file && line != null) location = `${file}:${line}`;

    return { severity: tier, title, location };
  });

  return { findings, critical, high, medium, low, total: findings.length };
}

function resolveWebhook(cliOpt?: string): string {
  if (cliOpt) return cliOpt;
  if (process.env.RAFTER_NOTIFY_WEBHOOK) return process.env.RAFTER_NOTIFY_WEBHOOK;
  // Try config file
  try {
    const configManager = new ConfigManager();
    const config = configManager.load();
    if (config.agent?.notifications?.webhook) {
      return config.agent.notifications.webhook;
    }
  } catch {
    // ignore
  }
  console.error("No webhook URL provided. Use --webhook or set RAFTER_NOTIFY_WEBHOOK");
  process.exit(EXIT_GENERAL_ERROR);
}

function detectPlatform(url: string): string {
  if (url.includes("hooks.slack.com") || url.includes("slack.com/api")) return "slack";
  if (url.includes("discord.com/api/webhooks") || url.includes("discordapp.com/api/webhooks")) return "discord";
  return "generic";
}

export function formatSlackPayload(scan: ScanData): Record<string, unknown> {
  const status = scan.status ?? "unknown";
  const repo = scan.repository_name ?? "unknown";
  const scanId = scan.scan_id ?? "";
  const { findings, critical, high, medium, low, total } = normalizeScan(scan);

  let statusIcon: string;
  let statusText: string;
  if (status === "completed" && total === 0) {
    statusIcon = ":white_check_mark:";
    statusText = "Clean — no issues found";
  } else if (status === "completed" && (critical > 0 || high > 0)) {
    statusIcon = ":rotating_light:";
    statusText = `${total} issue${total !== 1 ? "s" : ""} found`;
  } else if (status === "completed") {
    statusIcon = ":warning:";
    statusText = `${total} issue${total !== 1 ? "s" : ""} found`;
  } else if (status === "failed") {
    statusIcon = ":x:";
    statusText = "Scan failed";
  } else {
    statusIcon = ":hourglass_flowing_sand:";
    statusText = `Scan ${status}`;
  }

  const sectionFields: Array<{ type: string; text: string }> = [
    { type: "mrkdwn", text: `*Repository:*\n${repo}` },
    { type: "mrkdwn", text: `*Status:*\n${statusText}` },
  ];
  if (scanId) sectionFields.push({ type: "mrkdwn", text: `*Scan ID:*\n\`${scanId}\`` });
  if (scan.branch_name) sectionFields.push({ type: "mrkdwn", text: `*Branch:*\n\`${scan.branch_name}\`` });

  const blocks: Array<Record<string, unknown>> = [
    { type: "header", text: { type: "plain_text", text: `${statusIcon} Rafter Security Scan` } },
    { type: "section", fields: sectionFields },
  ];

  if (total > 0) {
    const parts: string[] = [];
    if (critical) parts.push(`:red_circle: Critical: *${critical}*`);
    if (high) parts.push(`:orange_circle: High: *${high}*`);
    if (medium) parts.push(`:large_yellow_circle: Medium: *${medium}*`);
    if (low) parts.push(`:white_circle: Low: *${low}*`);
    blocks.push({ type: "section", text: { type: "mrkdwn", text: parts.join("\n") } });
  }

  if (findings.length > 0) {
    const lines = findings.slice(0, 5).map((f) => {
      let line = `• \`[${f.severity.toUpperCase()}]\` ${f.title}`;
      if (f.location) line += ` — ${f.location}`;
      return line;
    });
    if (findings.length > 5) lines.push(`_... and ${findings.length - 5} more_`);

    blocks.push({ type: "divider" });
    blocks.push({ type: "section", text: { type: "mrkdwn", text: `*Top Findings:*\n${lines.join("\n")}` } });
  }

  blocks.push({
    type: "context",
    elements: [{ type: "mrkdwn", text: "Posted by *rafter-bot* | <https://rafter.so|rafter.so>" }],
  });

  return { text: `[rafter] ${repo}: ${statusText}`, blocks };
}

export function formatDiscordPayload(scan: ScanData): Record<string, unknown> {
  const status = scan.status ?? "unknown";
  const repo = scan.repository_name ?? "unknown";
  const scanId = scan.scan_id ?? "";
  const { findings, critical, high, medium, low, total } = normalizeScan(scan);

  let color: number;
  let statusText: string;
  if (status === "completed" && total === 0) {
    color = 0x2ecc71;
    statusText = "Clean — no issues found";
  } else if (status === "completed" && (critical > 0 || high > 0)) {
    color = 0xe74c3c;
    statusText = `${total} issue${total !== 1 ? "s" : ""} found`;
  } else if (status === "completed") {
    color = 0xf39c12;
    statusText = `${total} issue${total !== 1 ? "s" : ""} found`;
  } else if (status === "failed") {
    color = 0x95a5a6;
    statusText = "Scan failed";
  } else {
    color = 0x3498db;
    statusText = `Scan ${status}`;
  }

  const fields: Array<{ name: string; value: string; inline: boolean }> = [
    { name: "Repository", value: repo, inline: true },
    { name: "Status", value: statusText, inline: true },
  ];
  if (scanId) fields.push({ name: "Scan ID", value: `\`${scanId}\``, inline: true });
  if (scan.branch_name) fields.push({ name: "Branch", value: `\`${scan.branch_name}\``, inline: true });

  if (total > 0) {
    const parts: string[] = [];
    if (critical) parts.push(`\u{1f534} Critical: **${critical}**`);
    if (high) parts.push(`\u{1f7e0} High: **${high}**`);
    if (medium) parts.push(`\u{1f7e1} Medium: **${medium}**`);
    if (low) parts.push(`\u26aa Low: **${low}**`);
    fields.push({ name: "Severity Breakdown", value: parts.join("\n"), inline: false });
  }

  if (findings.length > 0) {
    const lines = findings.slice(0, 5).map((f) => {
      let line = `• \`[${f.severity.toUpperCase()}]\` ${f.title}`;
      if (f.location) line += ` — ${f.location}`;
      return line;
    });
    if (findings.length > 5) lines.push(`*... and ${findings.length - 5} more*`);
    fields.push({ name: "Top Findings", value: lines.join("\n"), inline: false });
  }

  return {
    content: `[rafter] ${repo}: ${statusText}`,
    embeds: [{ title: "\u{1f6e1}\ufe0f Rafter Security Scan", color, fields, footer: { text: "rafter-bot | rafter.so" } }],
  };
}

export function formatGenericPayload(scan: ScanData): Record<string, unknown> {
  const status = scan.status ?? "unknown";
  const repo = scan.repository_name ?? "unknown";
  const { total } = normalizeScan(scan);

  let statusText: string;
  if (status === "completed" && total === 0) statusText = "Clean — no issues found";
  else if (status === "completed") statusText = `${total} issue${total !== 1 ? "s" : ""} found`;
  else statusText = `Scan ${status}`;

  const msg = `[rafter] ${repo}: ${statusText}`;
  return { text: msg, content: msg, ...scan };
}

export function createNotifyCommand(): Command {
  return new Command("notify")
    .description("Post scan results to Slack or Discord channels via webhooks")
    .argument("[scan_id]", "Scan ID to fetch and post results for")
    .option("-w, --webhook <url>", "Webhook URL (Slack or Discord)")
    .option("-k, --api-key <key>", "API key for fetching scan results")
    .option("-p, --platform <platform>", "Force platform: slack, discord, or generic")
    .option("--quiet", "Suppress status messages")
    .option("--dry-run", "Print payload without posting")
    .action(async (scanId?: string, opts?: Record<string, unknown>) => {
      const webhookUrl = resolveWebhook(opts?.webhook as string | undefined);
      let scanData: ScanData;

      if (scanId) {
        const key = resolveKey(opts?.apiKey as string | undefined);
        try {
          const { data } = await apiClient.get(apiUrl("static/scan"), {
            params: { scan_id: scanId, format: "json" },
            headers: { "x-api-key": key },
          });
          scanData = data;
        } catch (e: any) {
          if (e.response?.status === 404) {
            console.error(`Scan '${scanId}' not found`);
            process.exit(EXIT_SCAN_NOT_FOUND);
          }
          console.error(`Error: ${e.response?.data ?? e.message}`);
          process.exit(EXIT_GENERAL_ERROR);
        }
      } else if (!process.stdin.isTTY) {
        // Read from stdin
        const chunks: Buffer[] = [];
        for await (const chunk of process.stdin) {
          chunks.push(chunk);
        }
        const raw = Buffer.concat(chunks).toString("utf-8");
        try {
          scanData = JSON.parse(raw);
        } catch {
          console.error("Error: stdin is not valid JSON");
          process.exit(EXIT_GENERAL_ERROR);
        }
      } else {
        console.error("Error: provide a scan ID or pipe JSON scan data via stdin");
        process.exit(EXIT_GENERAL_ERROR);
      }

      const detected = (opts?.platform as string) || detectPlatform(webhookUrl);

      let payload: Record<string, unknown>;
      if (detected === "slack") payload = formatSlackPayload(scanData!);
      else if (detected === "discord") payload = formatDiscordPayload(scanData!);
      else payload = formatGenericPayload(scanData!);

      if (opts?.dryRun) {
        console.log(JSON.stringify(payload, null, 2));
        return;
      }

      if (!opts?.quiet) {
        process.stderr.write(fmt.info(`Posting to ${detected} webhook...`) + "\n");
      }

      try {
        await validateWebhookUrl(webhookUrl);
        await fetch(webhookUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
      } catch (e: any) {
        console.error(`Error posting to webhook: ${e.message}`);
        process.exit(EXIT_GENERAL_ERROR);
      }

      if (!opts?.quiet) {
        process.stderr.write(fmt.success(`Scan results posted to ${detected} channel`) + "\n");
      }
    });
}
