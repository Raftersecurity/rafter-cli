import { Command } from "commander";
import fs from "fs";
import path from "path";
import { createRequire } from "module";

const _require = createRequire(import.meta.url);
const { version: CLI_VERSION } = _require("../../package.json");

interface ReportMatch {
  pattern: { name: string; severity: string; description?: string };
  line?: number | null;
  column?: number | null;
  redacted?: string;
}

interface ReportResult {
  file: string;
  matches: ReportMatch[];
}

export function createReportCommand(): Command {
  return new Command("report")
    .description("Generate a standalone HTML security report from scan results")
    .argument("[input]", "Path to JSON scan results (default: read from stdin)")
    .option("-o, --output <path>", "Output file path (default: stdout)")
    .option("--title <title>", "Report title", "Rafter Security Report")
    .action(async (input: string | undefined, opts: { output?: string; title?: string }) => {
      let jsonData: string;

      if (input) {
        const resolved = path.resolve(input);
        if (!fs.existsSync(resolved)) {
          console.error(`Error: File not found: ${resolved}`);
          process.exit(2);
        }
        jsonData = fs.readFileSync(resolved, "utf-8");
      } else if (!process.stdin.isTTY) {
        jsonData = await readStdin();
      } else {
        console.error(
          "Error: No input provided. Pipe scan results or provide a file path.\n" +
          "  Example: rafter scan local --json . | rafter report -o report.html\n" +
          "  Example: rafter report scan-results.json -o report.html"
        );
        process.exit(2);
        return;
      }

      let results: ReportResult[];
      try {
        results = JSON.parse(jsonData);
        if (!Array.isArray(results)) {
          throw new Error("Expected a JSON array of scan results");
        }
      } catch (e: any) {
        console.error(`Error: Invalid JSON input — ${e.message}`);
        process.exit(2);
        return;
      }

      const html = generateHtmlReport(results, opts.title || "Rafter Security Report");

      if (opts.output) {
        const outPath = path.resolve(opts.output);
        fs.writeFileSync(outPath, html, "utf-8");
        console.error(`Report written to ${outPath}`);
      } else {
        process.stdout.write(html);
      }
    });
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (chunk) => chunks.push(chunk));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    process.stdin.on("error", reject);
  });
}

function generateHtmlReport(results: ReportResult[], title: string): string {
  const now = new Date().toISOString();
  const totalFindings = results.reduce((sum, r) => sum + r.matches.length, 0);
  const filesAffected = results.length;

  const severityCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const patternCounts: Record<string, number> = {};

  for (const r of results) {
    for (const m of r.matches) {
      const sev = m.pattern.severity.toLowerCase();
      if (sev in severityCounts) severityCounts[sev]++;
      const name = m.pattern.name;
      patternCounts[name] = (patternCounts[name] || 0) + 1;
    }
  }

  const riskLevel = severityCounts.critical > 0
    ? "Critical"
    : severityCounts.high > 0
      ? "High"
      : severityCounts.medium > 0
        ? "Medium"
        : totalFindings > 0
          ? "Low"
          : "None";

  const riskColor = {
    Critical: "hsl(0 40% 55%)",
    High: "hsl(25 35% 55%)",
    Medium: "hsl(0 0% 64%)",
    Low: "hsl(0 0% 50%)",
    None: "hsl(0 0% 50%)",
  }[riskLevel];

  const topPatterns = Object.entries(patternCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  const findingsRows = results
    .flatMap((r) =>
      r.matches.map((m) => ({
        file: escapeHtml(r.file),
        line: m.line ?? "—",
        severity: m.pattern.severity,
        pattern: escapeHtml(m.pattern.name),
        description: escapeHtml(m.pattern.description || ""),
        redacted: escapeHtml(m.redacted || ""),
      })),
    )
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; line-height: 1.6; color: hsl(0 0% 98%); background: hsl(0 0% 3.9%); }
  .container { max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }
  header { background: hsl(0 0% 7%); color: hsl(0 0% 98%); padding: 2rem 0; margin-bottom: 2rem; border-bottom: 1px solid hsl(0 0% 14.9%); }
  header .container { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }
  header h1 { font-size: 1.5rem; font-weight: 700; }
  header .meta { font-size: 0.85rem; opacity: 0.6; text-align: right; }
  .card { background: hsl(0 0% 7%); border-radius: 8px; border: 1px solid hsl(0 0% 14.9%); padding: 1.5rem; margin-bottom: 1.5rem; }
  .card h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; color: hsl(0 0% 98%); }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; }
  .stat { text-align: center; padding: 1rem; border-radius: 6px; background: hsl(0 0% 10%); border: 1px solid hsl(0 0% 14.9%); }
  .stat .value { font-size: 2rem; font-weight: 700; color: hsl(0 0% 98%); }
  .stat .label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: hsl(0 0% 50%); margin-top: 0.25rem; }
  .risk-badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px; font-weight: 600; font-size: 0.85rem; }
  .sev-critical { background: hsl(0 30% 20%); color: hsl(0 40% 75%); border: 1px solid hsl(0 30% 30%); }
  .sev-high { background: hsl(25 25% 18%); color: hsl(25 35% 70%); border: 1px solid hsl(25 25% 28%); }
  .sev-medium { background: hsl(0 0% 18%); color: hsl(0 0% 70%); border: 1px solid hsl(0 0% 25%); }
  .sev-low { background: hsl(0 0% 14%); color: hsl(0 0% 55%); border: 1px solid hsl(0 0% 22%); }
  .bar-chart { margin-top: 0.5rem; }
  .bar-row { display: flex; align-items: center; margin-bottom: 0.4rem; }
  .bar-label { width: 180px; font-size: 0.85rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: hsl(0 0% 70%); }
  .bar-track { flex: 1; height: 20px; background: hsl(0 0% 14.9%); border-radius: 3px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 3px; min-width: 2px; background: hsl(0 0% 98%); opacity: 0.6; }
  .bar-count { width: 40px; text-align: right; font-size: 0.85rem; font-weight: 600; color: hsl(0 0% 64%); margin-left: 0.5rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th { text-align: left; padding: 0.6rem 0.75rem; background: hsl(0 0% 10%); border-bottom: 2px solid hsl(0 0% 14.9%); font-weight: 600; color: hsl(0 0% 64%); white-space: nowrap; text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.75rem; }
  td { padding: 0.6rem 0.75rem; border-bottom: 1px solid hsl(0 0% 14.9%); vertical-align: top; }
  tr:hover td { background: hsl(0 0% 10%); }
  .sev-pill { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; }
  .file-path { font-size: 0.8rem; word-break: break-all; }
  .redacted { font-size: 0.8rem; color: hsl(0 0% 40%); }
  .description { color: hsl(0 0% 50%); }
  footer { text-align: center; padding: 2rem 0; font-size: 0.8rem; color: hsl(0 0% 35%); border-top: 1px solid hsl(0 0% 14.9%); }
  .no-findings { text-align: center; padding: 3rem; color: hsl(0 0% 64%); }
  .no-findings .icon { font-size: 3rem; margin-bottom: 0.5rem; }
  @media (max-width: 768px) {
    .summary-grid { grid-template-columns: repeat(2, 1fr); }
    .bar-label { width: 120px; }
    table { display: block; overflow-x: auto; }
  }
  @media print {
    body { background: hsl(0 0% 3.9%); color: hsl(0 0% 98%); }
    .card { break-inside: avoid; }
    header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  }
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>${escapeHtml(title)}</h1>
    <div class="meta">
      Generated: ${escapeHtml(formatDate(now))}<br>
      Rafter CLI v${escapeHtml(CLI_VERSION)}
    </div>
  </div>
</header>
<main class="container">
  <div class="card">
    <h2>Executive Summary</h2>
    <div class="summary-grid">
      <div class="stat">
        <div class="value">${totalFindings}</div>
        <div class="label">Total Findings</div>
      </div>
      <div class="stat">
        <div class="value">${filesAffected}</div>
        <div class="label">Files Affected</div>
      </div>
      <div class="stat">
        <div class="value"><span class="risk-badge" style="background:${riskColor};color:hsl(0 0% 98%)">${riskLevel}</span></div>
        <div class="label">Overall Risk</div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Severity Breakdown</h2>
    <div class="summary-grid">
      <div class="stat"><div class="value" style="color:hsl(0 40% 70%)">${severityCounts.critical}</div><div class="label">Critical</div></div>
      <div class="stat"><div class="value" style="color:hsl(25 30% 65%)">${severityCounts.high}</div><div class="label">High</div></div>
      <div class="stat"><div class="value">${severityCounts.medium}</div><div class="label">Medium</div></div>
      <div class="stat"><div class="value" style="color:hsl(0 0% 50%)">${severityCounts.low}</div><div class="label">Low</div></div>
    </div>
  </div>

${topPatterns.length > 0 ? `  <div class="card">
    <h2>Top Finding Types</h2>
    <div class="bar-chart">
${topPatterns.map(([name, count]) => {
  const pct = Math.round((count / totalFindings) * 100);
  return `      <div class="bar-row">
        <div class="bar-label" title="${escapeHtml(name)}">${escapeHtml(name)}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
        <div class="bar-count">${count}</div>
      </div>`;
}).join("\n")}
    </div>
  </div>
` : ""}
${totalFindings > 0 ? `  <div class="card">
    <h2>Detailed Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Pattern</th>
          <th>File</th>
          <th>Line</th>
          <th>Redacted</th>
        </tr>
      </thead>
      <tbody>
${findingsRows.map((f) => `        <tr>
          <td><span class="sev-pill sev-${f.severity}">${f.severity}</span></td>
          <td>${f.pattern}${f.description ? `<br><small class="description">${f.description}</small>` : ""}</td>
          <td class="file-path">${f.file}</td>
          <td>${f.line}</td>
          <td class="redacted">${f.redacted}</td>
        </tr>`).join("\n")}
      </tbody>
    </table>
  </div>
` : `  <div class="card no-findings">
    <div class="icon">&#x2705;</div>
    <h2>No Security Findings</h2>
    <p>No secrets or vulnerabilities were detected in the scanned files.</p>
  </div>
`}
</main>
<footer>
  Generated by Rafter CLI v${escapeHtml(CLI_VERSION)} &mdash; ${escapeHtml(formatDate(now))}
</footer>
</body>
</html>
`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function severityRank(severity: string): number {
  const ranks: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return ranks[severity.toLowerCase()] ?? 4;
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  });
}
