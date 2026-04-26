"""rafter report — generate a standalone HTML security report from scan results."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer

from .. import __version__

report_app = typer.Typer(
    name="report",
    help="Generate a standalone HTML security report from scan results.",
    invoke_without_command=True,
    no_args_is_help=False,
)


@report_app.callback(invoke_without_command=True)
def report_main(
    input_file: str = typer.Argument(None, help="Path to JSON scan results (default: read from stdin)"),
    output: str = typer.Option(None, "-o", "--output", help="Output file path (default: stdout)"),
    title: str = typer.Option("Rafter Security Report", "--title", help="Report title"),
) -> None:
    """Generate a standalone HTML security report from scan results."""
    if input_file is not None:
        resolved = Path(input_file).resolve()
        if not resolved.exists():
            typer.echo(f"Error: File not found: {resolved}", err=True)
            raise typer.Exit(code=2)
        json_data = resolved.read_text(encoding="utf-8")
    elif not sys.stdin.isatty():
        json_data = sys.stdin.read()
    else:
        typer.echo(
            "Error: No input provided. Pipe scan results or provide a file path.\n"
            "  Example: rafter secrets --json . | rafter report -o report.html\n"
            "  Example: rafter report scan-results.json -o report.html",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        results = json.loads(json_data)
        if not isinstance(results, list):
            raise ValueError("Expected a JSON array of scan results")
    except (json.JSONDecodeError, ValueError) as exc:
        typer.echo(f"Error: Invalid JSON input — {exc}", err=True)
        raise typer.Exit(code=2)

    html = generate_html_report(results, title)

    if output:
        out_path = Path(output).resolve()
        out_path.write_text(html, encoding="utf-8")
        typer.echo(f"Report written to {out_path}", err=True)
    else:
        sys.stdout.write(html)


def generate_html_report(results: list[dict[str, Any]], title: str) -> str:
    now = datetime.now(timezone.utc).isoformat()
    total_findings = sum(len(r.get("matches", [])) for r in results)
    files_affected = len(results)

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    pattern_counts: dict[str, int] = {}

    for r in results:
        for m in r.get("matches", []):
            sev = m.get("pattern", {}).get("severity", "").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            name = m.get("pattern", {}).get("name", "Unknown")
            pattern_counts[name] = pattern_counts.get(name, 0) + 1

    if severity_counts["critical"] > 0:
        risk_level = "Critical"
    elif severity_counts["high"] > 0:
        risk_level = "High"
    elif severity_counts["medium"] > 0:
        risk_level = "Medium"
    elif total_findings > 0:
        risk_level = "Low"
    else:
        risk_level = "None"

    risk_colors = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#2563eb",
        "Low": "#16a34a",
        "None": "#16a34a",
    }
    risk_color = risk_colors[risk_level]

    top_patterns = sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    findings_rows = []
    for r in results:
        for m in r.get("matches", []):
            findings_rows.append({
                "file": _escape_html(r.get("file", "")),
                "line": m.get("line") if m.get("line") is not None else "\u2014",
                "severity": m.get("pattern", {}).get("severity", "unknown"),
                "pattern": _escape_html(m.get("pattern", {}).get("name", "")),
                "description": _escape_html(m.get("pattern", {}).get("description", "")),
                "redacted": _escape_html(m.get("redacted", "")),
            })
    findings_rows.sort(key=lambda f: _severity_rank(f["severity"]))

    # Build top patterns bar chart
    top_patterns_html = ""
    if top_patterns:
        bars = []
        for name, count in top_patterns:
            pct = round((count / total_findings) * 100) if total_findings else 0
            bars.append(
                f'      <div class="bar-row">\n'
                f'        <div class="bar-label" title="{_escape_html(name)}">{_escape_html(name)}</div>\n'
                f'        <div class="bar-track"><div class="bar-fill sev-medium" style="width:{pct}%"></div></div>\n'
                f'        <div class="bar-count">{count}</div>\n'
                f'      </div>'
            )
        top_patterns_html = (
            '  <div class="card">\n'
            '    <h2>Top Finding Types</h2>\n'
            '    <div class="bar-chart">\n'
            + "\n".join(bars) + "\n"
            '    </div>\n'
            '  </div>\n'
        )

    # Build findings table or no-findings message
    if total_findings > 0:
        rows_html = []
        for f in findings_rows:
            desc_html = f'<br><small style="color:#94a3b8">{f["description"]}</small>' if f["description"] else ""
            rows_html.append(
                f'        <tr>\n'
                f'          <td><span class="sev-pill sev-{f["severity"]}">{f["severity"]}</span></td>\n'
                f'          <td>{f["pattern"]}{desc_html}</td>\n'
                f'          <td class="file-path">{f["file"]}</td>\n'
                f'          <td>{f["line"]}</td>\n'
                f'          <td class="redacted">{f["redacted"]}</td>\n'
                f'        </tr>'
            )
        findings_html = (
            '  <div class="card">\n'
            '    <h2>Detailed Findings</h2>\n'
            '    <table>\n'
            '      <thead>\n'
            '        <tr>\n'
            '          <th>Severity</th>\n'
            '          <th>Pattern</th>\n'
            '          <th>File</th>\n'
            '          <th>Line</th>\n'
            '          <th>Redacted</th>\n'
            '        </tr>\n'
            '      </thead>\n'
            '      <tbody>\n'
            + "\n".join(rows_html) + "\n"
            '      </tbody>\n'
            '    </table>\n'
            '  </div>\n'
        )
    else:
        findings_html = (
            '  <div class="card no-findings">\n'
            '    <div class="icon">&#x2705;</div>\n'
            '    <h2>No Security Findings</h2>\n'
            '    <p>No secrets or vulnerabilities were detected in the scanned files.</p>\n'
            '  </div>\n'
        )

    formatted_date = _format_date(now)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_escape_html(title)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background: #f8fafc; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }}
  header {{ background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: white; padding: 2rem 0; margin-bottom: 2rem; }}
  header .container {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }}
  header h1 {{ font-size: 1.5rem; font-weight: 700; }}
  header .meta {{ font-size: 0.85rem; opacity: 0.8; text-align: right; }}
  .card {{ background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); padding: 1.5rem; margin-bottom: 1.5rem; }}
  .card h2 {{ font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; color: #334155; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; }}
  .stat {{ text-align: center; padding: 1rem; border-radius: 6px; background: #f1f5f9; }}
  .stat .value {{ font-size: 2rem; font-weight: 700; }}
  .stat .label {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-top: 0.25rem; }}
  .risk-badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px; color: white; font-weight: 600; font-size: 0.85rem; }}
  .sev-critical {{ background: #dc2626; }}
  .sev-high {{ background: #ea580c; }}
  .sev-medium {{ background: #2563eb; }}
  .sev-low {{ background: #16a34a; }}
  .bar-chart {{ margin-top: 0.5rem; }}
  .bar-row {{ display: flex; align-items: center; margin-bottom: 0.4rem; }}
  .bar-label {{ width: 180px; font-size: 0.85rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .bar-track {{ flex: 1; height: 20px; background: #e2e8f0; border-radius: 3px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 3px; min-width: 2px; }}
  .bar-count {{ width: 40px; text-align: right; font-size: 0.85rem; font-weight: 600; color: #475569; margin-left: 0.5rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ text-align: left; padding: 0.6rem 0.75rem; background: #f1f5f9; border-bottom: 2px solid #e2e8f0; font-weight: 600; color: #475569; white-space: nowrap; }}
  td {{ padding: 0.6rem 0.75rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  tr:hover td {{ background: #f8fafc; }}
  .sev-pill {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; color: white; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; }}
  .file-path {{ font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; font-size: 0.8rem; word-break: break-all; }}
  .redacted {{ font-family: monospace; font-size: 0.8rem; color: #94a3b8; }}
  footer {{ text-align: center; padding: 2rem 0; font-size: 0.8rem; color: #94a3b8; }}
  .no-findings {{ text-align: center; padding: 3rem; color: #16a34a; }}
  .no-findings .icon {{ font-size: 3rem; margin-bottom: 0.5rem; }}
  @media (max-width: 768px) {{
    .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .bar-label {{ width: 120px; }}
    table {{ display: block; overflow-x: auto; }}
  }}
  @media print {{
    body {{ background: white; }}
    .card {{ box-shadow: none; border: 1px solid #e2e8f0; break-inside: avoid; }}
    header {{ background: #0f172a !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  }}
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>{_escape_html(title)}</h1>
    <div class="meta">
      Generated: {_escape_html(formatted_date)}<br>
      Rafter CLI v{_escape_html(__version__)}
    </div>
  </div>
</header>
<main class="container">
  <div class="card">
    <h2>Executive Summary</h2>
    <div class="summary-grid">
      <div class="stat">
        <div class="value" style="color:{risk_color}">{total_findings}</div>
        <div class="label">Total Findings</div>
      </div>
      <div class="stat">
        <div class="value">{files_affected}</div>
        <div class="label">Files Affected</div>
      </div>
      <div class="stat">
        <div class="value"><span class="risk-badge" style="background:{risk_color}">{risk_level}</span></div>
        <div class="label">Overall Risk</div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Severity Breakdown</h2>
    <div class="summary-grid">
      <div class="stat"><div class="value" style="color:#dc2626">{severity_counts["critical"]}</div><div class="label">Critical</div></div>
      <div class="stat"><div class="value" style="color:#ea580c">{severity_counts["high"]}</div><div class="label">High</div></div>
      <div class="stat"><div class="value" style="color:#2563eb">{severity_counts["medium"]}</div><div class="label">Medium</div></div>
      <div class="stat"><div class="value" style="color:#16a34a">{severity_counts["low"]}</div><div class="label">Low</div></div>
    </div>
  </div>

{top_patterns_html}\
{findings_html}\
</main>
<footer>
  Generated by Rafter CLI v{_escape_html(__version__)} &mdash; {_escape_html(formatted_date)}
</footer>
</body>
</html>
"""


def _escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _severity_rank(severity: str) -> int:
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return ranks.get(severity.lower(), 4)


def _format_date(iso: str) -> str:
    dt = datetime.fromisoformat(iso)
    return dt.strftime("%B %d, %Y, %I:%M %p UTC")
