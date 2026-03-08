"""rafter issues — GitHub Issues integration.

Subcommands:
  rafter issues create from-scan   Create issues from scan results
  rafter issues create from-text   Create issue from natural language text
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import requests
import typer

from ...utils.api import API_BASE, EXIT_GENERAL_ERROR, EXIT_SUCCESS, resolve_key
from ...utils.formatter import fmt
from ...utils.git import detect_repo
from .dedup import find_duplicates
from .github_client import create_issue, list_open_issues
from .issue_builder import (
    BackendVulnerability,
    IssueDraft,
    LocalMatch,
    build_from_backend_vulnerability,
    build_from_local_match,
)

issues_app = typer.Typer(
    name="issues",
    help="GitHub Issues integration — create issues from scan results or text.",
    no_args_is_help=True,
)

create_app = typer.Typer(
    name="create",
    help="Create GitHub issues from scan findings or natural text.",
    no_args_is_help=True,
)
issues_app.add_typer(create_app)


@create_app.command("from-scan")
def from_scan(
    scan_id: str = typer.Option(None, "--scan-id", help="Backend scan ID"),
    from_local: str = typer.Option(
        None, "--from-local", help="Path to local scan JSON"
    ),
    repo: str = typer.Option(None, "--repo", "-r", help="Target GitHub repo (org/repo)"),
    api_key: str = typer.Option(
        None, "--api-key", "-k", envvar="RAFTER_API_KEY", help="Rafter API key"
    ),
    no_dedup: bool = typer.Option(False, "--no-dedup", help="Skip deduplication check"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show without creating"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress status messages"),
):
    """Create GitHub issues from scan results."""
    if not scan_id and not from_local:
        print(fmt.error("Provide --scan-id or --from-local"), file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    # Resolve target repo
    target_repo = repo
    if not target_repo:
        try:
            target_repo, _ = detect_repo(repo)
        except RuntimeError as e:
            print(fmt.error(str(e)), file=sys.stderr)
            raise typer.Exit(code=EXIT_GENERAL_ERROR)

    if not quiet:
        print(fmt.info(f"Target repo: {target_repo}"), file=sys.stderr)

    # Build drafts
    if scan_id:
        drafts = _drafts_from_backend(scan_id, api_key)
    else:
        drafts = _drafts_from_local(from_local)  # type: ignore[arg-type]

    if not drafts:
        if not quiet:
            print(fmt.success("No findings to create issues for"), file=sys.stderr)
        return

    if not quiet:
        print(fmt.info(f"Found {len(drafts)} findings"), file=sys.stderr)

    # Dedup
    if not no_dedup:
        existing = list_open_issues(target_repo)
        dupes = find_duplicates(existing, [d.fingerprint for d in drafts])
        before = len(drafts)
        drafts = [d for d in drafts if d.fingerprint not in dupes]
        if before != len(drafts) and not quiet:
            print(
                fmt.info(f"Skipped {before - len(drafts)} duplicate(s)"),
                file=sys.stderr,
            )

    if not drafts:
        if not quiet:
            print(
                fmt.success("All findings already have open issues"),
                file=sys.stderr,
            )
        return

    # Dry run
    if dry_run:
        print(fmt.info(f"Would create {len(drafts)} issue(s):"), file=sys.stderr)
        for d in drafts:
            print(f"  - {d.title}", file=sys.stderr)
        sys.stdout.write(
            json.dumps(
                [{"title": d.title, "body": d.body, "labels": d.labels} for d in drafts],
                indent=2,
            )
        )
        return

    # Create issues
    created: list[str] = []
    for d in drafts:
        try:
            issue = create_issue(
                repo=target_repo,
                title=d.title,
                body=d.body,
                labels=d.labels,
            )
            created.append(issue.html_url)
            if not quiet:
                print(fmt.success(f"Created: {issue.html_url}"), file=sys.stderr)
        except Exception as e:
            print(fmt.error(f"Failed to create issue: {e}"), file=sys.stderr)

    if created:
        sys.stdout.write("\n".join(created) + "\n")

    if not quiet:
        print(
            fmt.success(f"Created {len(created)}/{len(drafts)} issue(s)"),
            file=sys.stderr,
        )


@create_app.command("from-text")
def from_text(
    repo: str = typer.Option(None, "--repo", "-r", help="Target GitHub repo (org/repo)"),
    text: str = typer.Option(None, "--text", "-t", help="Inline text"),
    file: str = typer.Option(None, "--file", "-f", help="Read text from file"),
    title: str = typer.Option(None, "--title", help="Override extracted title"),
    labels: str = typer.Option(None, "--labels", help="Comma-separated labels"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show without creating"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress status messages"),
):
    """Create a GitHub issue from natural language text."""
    # Read input
    input_text = _read_input(text, file)
    if not input_text.strip():
        print(
            fmt.error("No input text provided. Use --text, --file, or pipe via stdin"),
            file=sys.stderr,
        )
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    # Resolve repo
    target_repo = repo
    if not target_repo:
        try:
            target_repo, _ = detect_repo(repo)
        except RuntimeError as e:
            print(fmt.error(str(e)), file=sys.stderr)
            raise typer.Exit(code=EXIT_GENERAL_ERROR)

    # Parse text
    parsed = _parse_natural_text(input_text)

    if title:
        parsed["title"] = title
    if labels:
        extra = [l.strip() for l in labels.split(",") if l.strip()]
        parsed["labels"].extend(extra)
        parsed["labels"] = list(set(parsed["labels"]))

    if not quiet:
        print(fmt.info(f"Target repo: {target_repo}"), file=sys.stderr)
        print(fmt.info(f"Title: {parsed['title']}"), file=sys.stderr)
        if parsed["labels"]:
            print(
                fmt.info(f"Labels: {', '.join(parsed['labels'])}"),
                file=sys.stderr,
            )

    if dry_run:
        sys.stdout.write(json.dumps(parsed, indent=2))
        return

    try:
        issue = create_issue(
            repo=target_repo,
            title=parsed["title"],
            body=parsed["body"],
            labels=parsed["labels"],
        )
    except Exception as e:
        print(fmt.error(f"Failed to create issue: {e}"), file=sys.stderr)
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    if not quiet:
        print(fmt.success(f"Created: {issue.html_url}"), file=sys.stderr)
    sys.stdout.write(issue.html_url + "\n")


# ── Internal helpers ──────────────────────────────────────────────────


def _drafts_from_backend(scan_id: str, api_key: str | None) -> list[IssueDraft]:
    key = resolve_key(api_key)
    resp = requests.get(
        f"{API_BASE}/static/scan",
        headers={"x-api-key": key},
        params={"scan_id": scan_id, "format": "json"},
        timeout=(10, 60),
    )
    resp.raise_for_status()
    data = resp.json()

    vulns = data.get("vulnerabilities", [])
    return [
        build_from_backend_vulnerability(
            BackendVulnerability(
                rule_id=v["ruleId"],
                level=v.get("level", "warning"),
                message=v.get("message", ""),
                file=v.get("file", ""),
                line=v.get("line"),
            )
        )
        for v in vulns
    ]


def _drafts_from_local(file_path: str) -> list[IssueDraft]:
    raw = Path(file_path).read_text()
    results = json.loads(raw)
    drafts: list[IssueDraft] = []

    for result in results:
        for match in result.get("matches", []):
            pattern = match.get("pattern", {})
            drafts.append(
                build_from_local_match(
                    result["file"],
                    LocalMatch(
                        pattern_name=pattern.get("name", "unknown"),
                        severity=pattern.get("severity", "medium"),
                        description=pattern.get("description", ""),
                        line=match.get("line"),
                        column=match.get("column"),
                        redacted=match.get("redacted", ""),
                    ),
                )
            )

    return drafts


def _read_input(text: str | None, file: str | None) -> str:
    if text:
        return text
    if file:
        return Path(file).read_text()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def _parse_natural_text(text: str) -> dict:
    lines = text.strip().split("\n")
    issue_labels: list[str] = []

    # Extract title from first non-empty line
    title = ""
    body_start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped:
            title = re.sub(r"^#+\s*", "", stripped).strip()
            body_start = i + 1
            break

    if not title:
        title = "Security issue reported via Rafter CLI"

    if len(title) > 120:
        title = title[:117] + "..."

    # Body from remaining text
    body_lines = lines[body_start:]
    body = "\n".join(body_lines).strip() or text.strip()

    # Severity detection
    text_lower = text.lower()
    if "critical" in text_lower or "p0" in text_lower:
        issue_labels.append("severity:critical")
    elif "high severity" in text_lower or "high risk" in text_lower or "p1" in text_lower:
        issue_labels.append("severity:high")
    elif "medium" in text_lower or "p2" in text_lower:
        issue_labels.append("severity:medium")
    elif "low" in text_lower or "p3" in text_lower:
        issue_labels.append("severity:low")

    # Security keyword detection
    security_keywords = [
        "security", "vulnerability", "cve", "cwe", "owasp",
        "secret", "credential", "token", "password", "injection",
        "xss", "csrf", "ssrf", "exploit",
    ]
    if any(kw in text_lower for kw in security_keywords):
        issue_labels.append("security")

    # File path references
    file_refs = re.findall(
        r"(?:^|\s)([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,10})(?::(\d+))?", text
    )
    if file_refs:
        files = [f[0].strip() for f in file_refs if "/" in f[0] or "." in f[0]]
        if files:
            body += "\n\n### Referenced Files\n\n"
            for f in files[:10]:
                body += f"- `{f}`\n"

    body += "\n\n---\n*Created by [Rafter CLI](https://rafter.so) — security for AI builders*\n"

    return {
        "title": title,
        "body": body,
        "labels": list(set(issue_labels)),
    }
