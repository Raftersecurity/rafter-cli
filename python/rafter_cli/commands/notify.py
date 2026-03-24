"""rafter notify — post scan results to Slack/Discord channels."""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from typing import Optional

import typer

from ..utils.api import (
    API_BASE,
    API_TIMEOUT_SHORT,
    EXIT_GENERAL_ERROR,
    EXIT_SCAN_NOT_FOUND,
    EXIT_SUCCESS,
    resolve_key,
)
from ..utils.formatter import fmt, print_stderr

notify_app = typer.Typer(
    name="notify",
    help="Post scan results to Slack or Discord channels via webhooks.",
    invoke_without_command=True,
    no_args_is_help=False,
)


def _resolve_webhook(cli_opt: str | None) -> str:
    """Resolve webhook URL from CLI option, env var, or config."""
    if cli_opt:
        return cli_opt
    env_url = os.getenv("RAFTER_NOTIFY_WEBHOOK")
    if env_url:
        return env_url
    # Try config file
    try:
        from ..core.config_manager import ConfigManager
        config = ConfigManager.load()
        if config.agent.notifications.webhook:
            return config.agent.notifications.webhook
    except Exception:
        pass
    print("No webhook URL provided. Use --webhook or set RAFTER_NOTIFY_WEBHOOK", file=sys.stderr)
    raise typer.Exit(code=EXIT_GENERAL_ERROR)


def _detect_platform(url: str) -> str:
    """Detect webhook platform from URL pattern."""
    if "hooks.slack.com" in url or "slack.com/api" in url:
        return "slack"
    if "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url:
        return "discord"
    return "generic"


def _format_slack_payload(scan_data: dict) -> dict:
    """Format scan results as a Slack message with Block Kit."""
    status = scan_data.get("status", "unknown")
    repo = scan_data.get("repository_name", "unknown")
    scan_id = scan_data.get("scan_id", "")
    findings = scan_data.get("findings", [])
    summary = scan_data.get("summary", {})

    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    total = critical + high + medium + low

    # Status emoji
    if status == "completed" and total == 0:
        status_icon = ":white_check_mark:"
        status_text = "Clean — no issues found"
    elif status == "completed" and (critical > 0 or high > 0):
        status_icon = ":rotating_light:"
        status_text = f"{total} issue{'s' if total != 1 else ''} found"
    elif status == "completed":
        status_icon = ":warning:"
        status_text = f"{total} issue{'s' if total != 1 else ''} found"
    elif status == "failed":
        status_icon = ":x:"
        status_text = "Scan failed"
    else:
        status_icon = ":hourglass_flowing_sand:"
        status_text = f"Scan {status}"

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{status_icon} Rafter Security Scan",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Repository:*\n{repo}"},
                {"type": "mrkdwn", "text": f"*Status:*\n{status_text}"},
            ],
        },
    ]

    if scan_id:
        blocks[1]["fields"].append(
            {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id}`"}
        )

    branch = scan_data.get("branch_name")
    if branch:
        blocks[1]["fields"].append(
            {"type": "mrkdwn", "text": f"*Branch:*\n`{branch}`"}
        )

    # Severity breakdown
    if total > 0:
        severity_parts = []
        if critical:
            severity_parts.append(f":red_circle: Critical: *{critical}*")
        if high:
            severity_parts.append(f":orange_circle: High: *{high}*")
        if medium:
            severity_parts.append(f":large_yellow_circle: Medium: *{medium}*")
        if low:
            severity_parts.append(f":white_circle: Low: *{low}*")

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "\n".join(severity_parts),
            },
        })

    # Top findings (max 5)
    if findings:
        finding_lines = []
        for f in findings[:5]:
            sev = f.get("severity", "unknown").upper()
            title = f.get("title", f.get("rule_id", "Unknown"))
            location = f.get("location", f.get("file", ""))
            line = f"• `[{sev}]` {title}"
            if location:
                line += f" — {location}"
            finding_lines.append(line)

        if len(findings) > 5:
            finding_lines.append(f"_... and {len(findings) - 5} more_")

        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Top Findings:*\n" + "\n".join(finding_lines),
            },
        })

    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": "Posted by *rafter-bot* | <https://rafter.so|rafter.so>"},
        ],
    })

    # Slack needs both text (for notifications) and blocks (for rendering)
    return {
        "text": f"[rafter] {repo}: {status_text}",
        "blocks": blocks,
    }


def _format_discord_payload(scan_data: dict) -> dict:
    """Format scan results as a Discord webhook embed."""
    status = scan_data.get("status", "unknown")
    repo = scan_data.get("repository_name", "unknown")
    scan_id = scan_data.get("scan_id", "")
    findings = scan_data.get("findings", [])
    summary = scan_data.get("summary", {})

    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    total = critical + high + medium + low

    # Embed color
    if status == "completed" and total == 0:
        color = 0x2ECC71  # green
        status_text = "Clean — no issues found"
    elif status == "completed" and (critical > 0 or high > 0):
        color = 0xE74C3C  # red
        status_text = f"{total} issue{'s' if total != 1 else ''} found"
    elif status == "completed":
        color = 0xF39C12  # orange
        status_text = f"{total} issue{'s' if total != 1 else ''} found"
    elif status == "failed":
        color = 0x95A5A6  # gray
        status_text = "Scan failed"
    else:
        color = 0x3498DB  # blue
        status_text = f"Scan {status}"

    fields: list[dict] = [
        {"name": "Repository", "value": repo, "inline": True},
        {"name": "Status", "value": status_text, "inline": True},
    ]

    if scan_id:
        fields.append({"name": "Scan ID", "value": f"`{scan_id}`", "inline": True})

    branch = scan_data.get("branch_name")
    if branch:
        fields.append({"name": "Branch", "value": f"`{branch}`", "inline": True})

    if total > 0:
        severity_parts = []
        if critical:
            severity_parts.append(f"\U0001f534 Critical: **{critical}**")
        if high:
            severity_parts.append(f"\U0001f7e0 High: **{high}**")
        if medium:
            severity_parts.append(f"\U0001f7e1 Medium: **{medium}**")
        if low:
            severity_parts.append(f"\u26aa Low: **{low}**")
        fields.append({
            "name": "Severity Breakdown",
            "value": "\n".join(severity_parts),
            "inline": False,
        })

    # Top findings
    if findings:
        finding_lines = []
        for f in findings[:5]:
            sev = f.get("severity", "unknown").upper()
            title = f.get("title", f.get("rule_id", "Unknown"))
            location = f.get("location", f.get("file", ""))
            line = f"• `[{sev}]` {title}"
            if location:
                line += f" — {location}"
            finding_lines.append(line)

        if len(findings) > 5:
            finding_lines.append(f"*... and {len(findings) - 5} more*")

        fields.append({
            "name": "Top Findings",
            "value": "\n".join(finding_lines),
            "inline": False,
        })

    embed = {
        "title": "\U0001f6e1\ufe0f Rafter Security Scan",
        "color": color,
        "fields": fields,
        "footer": {"text": "rafter-bot | rafter.so"},
    }

    return {
        "content": f"[rafter] {repo}: {status_text}",
        "embeds": [embed],
    }


def _format_generic_payload(scan_data: dict) -> dict:
    """Format scan results as a plain JSON payload with text field."""
    status = scan_data.get("status", "unknown")
    repo = scan_data.get("repository_name", "unknown")
    summary = scan_data.get("summary", {})
    total = sum(summary.get(k, 0) for k in ("critical", "high", "medium", "low"))

    if status == "completed" and total == 0:
        status_text = "Clean — no issues found"
    elif status == "completed":
        status_text = f"{total} issue{'s' if total != 1 else ''} found"
    else:
        status_text = f"Scan {status}"

    msg = f"[rafter] {repo}: {status_text}"
    return {
        "text": msg,
        "content": msg,
        **scan_data,
    }


def _post_webhook(url: str, payload: dict) -> None:
    """POST JSON payload to a webhook URL."""
    from ..core.audit_logger import validate_webhook_url
    validate_webhook_url(url)

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"Webhook returned HTTP {resp.status}")


def _fetch_scan(scan_id: str, api_key: str) -> dict:
    """Fetch scan results from the backend API."""
    import requests

    headers = {"x-api-key": api_key}
    resp = requests.get(
        f"{API_BASE}/static/scan",
        headers=headers,
        params={"scan_id": scan_id, "format": "json"},
        timeout=API_TIMEOUT_SHORT,
    )
    if resp.status_code == 404:
        print(f"Scan '{scan_id}' not found", file=sys.stderr)
        raise typer.Exit(code=EXIT_SCAN_NOT_FOUND)
    elif resp.status_code != 200:
        print(f"Error: {resp.text}", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)
    return resp.json()


@notify_app.callback()
def notify(
    ctx: typer.Context,
    scan_id: Optional[str] = typer.Argument(None, help="Scan ID to post results for"),
    webhook: Optional[str] = typer.Option(None, "--webhook", "-w", envvar="RAFTER_NOTIFY_WEBHOOK", help="Webhook URL (Slack or Discord)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="API key for fetching scan results"),
    platform: Optional[str] = typer.Option(None, "--platform", "-p", help="Force platform: slack, discord, or generic"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress status messages"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print payload without posting"),
):
    """Post scan results to Slack or Discord channels.

    Provide a scan ID to fetch and post results, or pipe JSON scan data via stdin.

    \b
    Examples:
      rafter notify abc123 --webhook https://hooks.slack.com/services/...
      rafter get abc123 -f json | rafter notify --webhook https://discord.com/api/webhooks/...
      RAFTER_NOTIFY_WEBHOOK=https://hooks.slack.com/... rafter notify abc123
    """
    if ctx.invoked_subcommand is not None:
        return

    webhook_url = _resolve_webhook(webhook)

    # Determine scan data source
    if scan_id:
        key = resolve_key(api_key)
        scan_data = _fetch_scan(scan_id, key)
    elif not sys.stdin.isatty():
        # Read from stdin
        raw = sys.stdin.read()
        try:
            scan_data = json.loads(raw)
        except json.JSONDecodeError:
            print("Error: stdin is not valid JSON", file=sys.stderr)
            raise typer.Exit(code=EXIT_GENERAL_ERROR)
    else:
        print("Error: provide a scan ID or pipe JSON scan data via stdin", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    # Detect platform from URL
    detected = platform or _detect_platform(webhook_url)

    # Format payload
    if detected == "slack":
        payload = _format_slack_payload(scan_data)
    elif detected == "discord":
        payload = _format_discord_payload(scan_data)
    else:
        payload = _format_generic_payload(scan_data)

    if dry_run:
        print(json.dumps(payload, indent=2))
        return

    # Post
    if not quiet:
        print_stderr(fmt.info(f"Posting to {detected} webhook..."))

    try:
        _post_webhook(webhook_url, payload)
    except Exception as e:
        print(f"Error posting to webhook: {e}", file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    if not quiet:
        print_stderr(fmt.success(f"Scan results posted to {detected} channel"))
